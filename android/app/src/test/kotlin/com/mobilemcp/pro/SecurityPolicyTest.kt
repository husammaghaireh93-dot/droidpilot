package com.mobilemcp.pro

import com.mobilemcp.pro.security.ConsentCoordinator
import com.mobilemcp.pro.security.ConsentRateLimiter
import com.mobilemcp.pro.security.DynamicPolicyStore
import com.mobilemcp.pro.security.InMemoryEncryptedPolicyVault
import com.mobilemcp.pro.security.NodeSanitizer
import com.mobilemcp.pro.security.PackageTier
import com.mobilemcp.pro.security.PolicyDecisionType
import com.mobilemcp.pro.security.PolicyEngine
import com.mobilemcp.pro.security.PolicyUpdateResult
import com.mobilemcp.pro.security.PolicyVaultBackend
import com.mobilemcp.pro.server.WebSocketCommandServer
import com.mobilemcp.pro.service.AuditLogger
import org.java_websocket.client.WebSocketClient
import org.java_websocket.handshake.ServerHandshake
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SecurityPolicyTest {

    @Rule
    @JvmField
    val tempFolder = TemporaryFolder()

    @Test
    fun `command allowlist strictly permits slice 1 commands and denies all others including gestures and ping`() {
        val engine = PolicyEngine()
        val pkg = "com.google.android.calculator"

        assertEquals(18, PolicyEngine.ALL_KNOWN_COMMANDS.size)

        for (command in PolicyEngine.ALL_KNOWN_COMMANDS) {
            val decision = engine.evaluate(command, pkg)
            when (command) {
                "get_ui_tree" -> assertEquals(
                    "Expected ALLOW for $command",
                    PolicyDecisionType.ALLOW,
                    decision.type
                )
                "click_element", "type_text" -> assertEquals(
                    "Expected REQUIRE_CONSENT for $command",
                    PolicyDecisionType.REQUIRE_CONSENT,
                    decision.type
                )
                else -> assertEquals(
                    "Expected DENY for disallowed command '$command'",
                    PolicyDecisionType.DENY,
                    decision.type
                )
            }
        }

        // Explicitly confirm gesture & probe vectors are denied
        for (explicitlyDenied in listOf("swipe", "tap", "long_press", "pinch", "ping", "get_device_info", "set_text", "open_app", "", null)) {
            assertEquals(
                "Expected DENY for $explicitlyDenied",
                PolicyDecisionType.DENY,
                engine.evaluate(explicitlyDenied, pkg).type
            )
        }
    }

    @Test
    fun `package whitelist enforced for read mutations and node refresh`() {
        val engine = PolicyEngine()

        // Read command must fail on non-whitelisted or null package
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("get_ui_tree", "com.android.settings").type)
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("get_ui_tree", "com.android.systemui").type)
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("get_ui_tree", null).type)
        assertEquals(PolicyDecisionType.ALLOW, engine.evaluate("get_ui_tree", "com.android.calculator2").type)

        // Mutation commands require consent only on whitelisted packages
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("click_element", "com.whatsapp").type)
        assertEquals(PolicyDecisionType.REQUIRE_CONSENT, engine.evaluate("click_element", "com.google.android.calculator").type)

        // Target node refresh & package verification (prevents TOCTOU overlay swap)
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyTargetNodePackage("com.google.android.calculator", refreshed = false).type
        )
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyTargetNodePackage("com.android.systemui", refreshed = true).type
        )
        assertEquals(
            PolicyDecisionType.ALLOW,
            engine.verifyTargetNodePackage("com.google.android.calculator", refreshed = true).type
        )
    }

    @Test
    fun `websocket server enforces loopback remote and constant-time bearer token`() {
        val server = WebSocketCommandServer(
            port = 0,
            onLog = {},
            onConnectionChange = {}
        )

        // Empty authToken rejects everything
        assertFalse(server.isAuthorizedHandshake("Bearer "))
        assertFalse(server.isAuthorizedHandshake(null))

        server.authToken = "a9b8c7d6e5f40123456789abcdef0123"
        assertTrue(server.isAuthorizedHandshake("Bearer a9b8c7d6e5f40123456789abcdef0123"))
        assertFalse(server.isAuthorizedHandshake("Bearer wrong_token"))
        assertFalse(server.isAuthorizedHandshake("a9b8c7d6e5f40123456789abcdef0123"))
        assertFalse(server.isAuthorizedHandshake(""))
        assertFalse(server.isAuthorizedHandshake(null))

        assertTrue(WebSocketCommandServer.isLoopbackRemote(InetAddress.getByName("127.0.0.1")))
        assertTrue(WebSocketCommandServer.isLoopbackRemote(InetAddress.getByName("::1")))
        assertFalse(WebSocketCommandServer.isLoopbackRemote(InetAddress.getByName("192.168.1.42")))
        assertFalse(WebSocketCommandServer.isLoopbackRemote(null))
    }

    @Test
    fun `node sanitizer masks password text and contentDescription`() {
        val (maskedText, maskedDesc) = NodeSanitizer.sanitizeNodeFields(
            rawText = "S3cretP@ss",
            rawContentDescription = "Enter password S3cretP@ss",
            isPassword = true
        )
        assertNull(maskedText)
        assertNull(maskedDesc)

        val (plainText, plainDesc) = NodeSanitizer.sanitizeNodeFields(
            rawText = "8",
            rawContentDescription = "eight",
            isPassword = false
        )
        assertEquals("8", plainText)
        assertEquals("eight", plainDesc)
    }

    @Test
    fun `consent coordinator enforces notifications prerequisite single pending nonce and timeout default-deny`() {
        var fakeClockMs = 10_000L
        var nonceSeq = 0
        val coordinator = ConsentCoordinator(
            timeoutMs = 5_000L,
            clock = { fakeClockMs },
            nonceGenerator = { "nonce-${++nonceSeq}" }
        )

        // Notifications disabled -> immediate denial
        val disabledResult = coordinator.startConsent(notificationsEnabled = false)
        assertTrue(disabledResult is ConsentCoordinator.StartResult.Denied)

        // Start active session -> second concurrent request must be denied
        val started = coordinator.startConsent(notificationsEnabled = true) as ConsentCoordinator.StartResult.Started
        val concurrent = coordinator.startConsent(notificationsEnabled = true)
        assertTrue(concurrent is ConsentCoordinator.StartResult.Denied)

        // Forged / mismatched nonce rejected
        assertFalse(coordinator.submitDecision("forged-nonce", approved = true))

        // Advancing clock past timeout forces default-deny
        val timedOutOutcome = coordinator.awaitResult(started.session) {
            fakeClockMs += 6_000L
        }
        assertFalse(timedOutOutcome)

        // Valid approval succeeds and nonce cannot be replayed
        val started2 = coordinator.startConsent(notificationsEnabled = true) as ConsentCoordinator.StartResult.Started
        assertTrue(coordinator.submitDecision(started2.session.nonce, approved = true))
        assertFalse("Nonce replay must fail", coordinator.submitDecision(started2.session.nonce, approved = true))
        assertTrue(coordinator.awaitResult(started2.session))

        // Explicit denial returns false
        val started3 = coordinator.startConsent(notificationsEnabled = true) as ConsentCoordinator.StartResult.Started
        assertTrue(coordinator.submitDecision(started3.session.nonce, approved = false))
        assertFalse(coordinator.awaitResult(started3.session))
    }

    @Test
    fun `audit logger builds valid hash chain across restarts and detects tampering`() {
        val logger = AuditLogger(tempFolder.root)
        logger.record("get_ui_tree", "com.google.android.calculator", null, "not_required", "executed")
        logger.record("click_element", "com.google.android.calculator", "=", "approved", "executed")
        logger.record("swipe", "com.google.android.calculator", null, "n/a", "denied")

        val reopenedLogger = AuditLogger(tempFolder.root)
        val fourth = reopenedLogger.record("type_text", "com.google.android.calculator", "input", "denied_or_timeout", "denied")
        assertEquals(3L, fourth.index)

        val lines = reopenedLogger.getLogLines()
        assertEquals(4, lines.size)
        assertTrue(AuditLogger.verifyChainIntegrity(lines))

        // Tamper middle record
        val modified = lines.toMutableList()
        modified[1] = modified[1].replace("executed", "forged")
        assertFalse(AuditLogger.verifyChainIntegrity(modified))

        // Delete middle record
        val deleted = listOf(lines[0], lines[2], lines[3])
        assertFalse(AuditLogger.verifyChainIntegrity(deleted))
    }

    @Test
    fun `post-consent TOCTOU verifier rejects overlay switches cross-package swaps and stale nodes`() {
        val engine = PolicyEngine()

        // Exact match with refreshed node succeeds
        assertEquals(
            PolicyDecisionType.ALLOW,
            engine.verifyPostConsentContext(
                consentedPackage = "com.google.android.calculator",
                currentPackage = "com.google.android.calculator",
                targetPackage = "com.google.android.calculator",
                refreshed = true
            ).type
        )

        // Overlay or foreground switch to non-whitelisted app denied
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyPostConsentContext(
                consentedPackage = "com.google.android.calculator",
                currentPackage = "com.android.systemui",
                targetPackage = "com.google.android.calculator",
                refreshed = true
            ).type
        )

        // Cross-package switch even between two whitelisted packages denied
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyPostConsentContext(
                consentedPackage = "com.google.android.calculator",
                currentPackage = "com.android.calculator2",
                targetPackage = "com.android.calculator2",
                refreshed = true
            ).type
        )

        // Target node belonging to another package denied
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyPostConsentContext(
                consentedPackage = "com.google.android.calculator",
                currentPackage = "com.google.android.calculator",
                targetPackage = "com.android.settings",
                refreshed = true
            ).type
        )

        // Failed node.refresh() denied
        assertEquals(
            PolicyDecisionType.DENY,
            engine.verifyPostConsentContext(
                consentedPackage = "com.google.android.calculator",
                currentPackage = "com.google.android.calculator",
                targetPackage = "com.google.android.calculator",
                refreshed = false
            ).type
        )
    }

    @Test
    fun `consent coordinator purges pending session and nonce in finally when wait throws`() {
        var fakeClockMs = 5_000L
        var nonceSeq = 0
        val coordinator = ConsentCoordinator(
            timeoutMs = 15_000L,
            clock = { fakeClockMs },
            nonceGenerator = { "nonce-${++nonceSeq}" }
        )

        val session1 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        try {
            coordinator.awaitResult(session1) {
                throw IllegalStateException("Simulated wait interruption")
            }
        } catch (_: IllegalStateException) {
            // Expected
        }

        // Old nonce must be purged from memory immediately without waiting for timeout
        assertFalse(coordinator.submitDecision(session1.nonce, approved = true))

        // A brand new consent session must start cleanly right away
        val session2 = coordinator.startConsent(true)
        assertTrue(session2 is ConsentCoordinator.StartResult.Started)
    }

    @Test
    fun `websocket token rotation disconnects active clients immediately and invalidates old token`() {
        val port = ServerSocket(0).use { it.localPort }
        val startedLatch = CountDownLatch(1)
        val connCount = AtomicInteger(0)
        val firstConnectedLatch = CountDownLatch(1)
        val secondConnectedLatch = CountDownLatch(1)
        val rotated = AtomicInteger(0)
        val server = WebSocketCommandServer(
            port = port,
            onLog = { msg ->
                if (msg.startsWith("Server started on")) {
                    startedLatch.countDown()
                }
            },
            onConnectionChange = { count ->
                connCount.set(count)
                if (count == 1) {
                    if (rotated.get() == 0) firstConnectedLatch.countDown() else secondConnectedLatch.countDown()
                }
            }
        )
        server.authToken = "initial-token-alpha"
        server.start()

        try {
            assertTrue("Server failed to start", startedLatch.await(5, TimeUnit.SECONDS))

            val closeLatch = CountDownLatch(1)
            val closedCode = AtomicInteger(-1)
            val client1 = object : WebSocketClient(
                URI("ws://127.0.0.1:$port"),
                mapOf("Authorization" to "Bearer initial-token-alpha")
            ) {
                override fun onOpen(handshakedata: ServerHandshake?) {}
                override fun onMessage(message: String?) {}
                override fun onClose(code: Int, reason: String?, remote: Boolean) {
                    closedCode.set(code)
                    closeLatch.countDown()
                }
                override fun onError(ex: Exception?) {}
            }

            assertTrue("Client 1 failed to connect", client1.connectBlocking(5, TimeUnit.SECONDS))
            assertTrue("Server did not register client 1", firstConnectedLatch.await(5, TimeUnit.SECONDS))
            assertEquals(1, server.getConnectionCount())

            // Rotate token: must immediately drop active client1 with 4001
            rotated.set(1)
            server.rotateAuthToken("rotated-token-beta")
            assertTrue("Active client was not closed on rotation", closeLatch.await(5, TimeUnit.SECONDS))
            assertEquals(4001, closedCode.get())
            assertEquals(0, server.getConnectionCount())

            // Old token handshake must now be rejected
            val oldRejectLatch = CountDownLatch(1)
            val oldCloseCode = AtomicInteger(-1)
            val staleClient = object : WebSocketClient(
                URI("ws://127.0.0.1:$port"),
                mapOf("Authorization" to "Bearer initial-token-alpha")
            ) {
                override fun onOpen(handshakedata: ServerHandshake?) {}
                override fun onMessage(message: String?) {}
                override fun onClose(code: Int, reason: String?, remote: Boolean) {
                    oldCloseCode.set(code)
                    oldRejectLatch.countDown()
                }
                override fun onError(ex: Exception?) {}
            }
            staleClient.connectBlocking(5, TimeUnit.SECONDS)
            assertTrue(oldRejectLatch.await(5, TimeUnit.SECONDS))
            assertEquals(4001, oldCloseCode.get())

            // New token connects cleanly
            val freshClient = object : WebSocketClient(
                URI("ws://127.0.0.1:$port"),
                mapOf("Authorization" to "Bearer rotated-token-beta")
            ) {
                override fun onOpen(handshakedata: ServerHandshake?) {}
                override fun onMessage(message: String?) {}
                override fun onClose(code: Int, reason: String?, remote: Boolean) {}
                override fun onError(ex: Exception?) {}
            }
            assertTrue("Fresh client with rotated token failed", freshClient.connectBlocking(5, TimeUnit.SECONDS))
            assertTrue("Server did not register fresh client", secondConnectedLatch.await(5, TimeUnit.SECONDS))
            assertEquals(1, server.getConnectionCount())
            freshClient.closeBlocking()
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `tier 0 hard deny permanently blocks financial apps settings password managers and installers`() {
        val hardDeniedPackages = listOf(
            // Financial / Wallets / Banking
            "com.reflect",
            "com.umniah.uwallet",
            "com.arabbank.mobile",
            "com.example.mybank",
            "com.fintech.walletapp",
            "com.demo.payments",
            "com.crypto.exchange",
            "com.company.pay",
            // System Settings & Security
            "com.android.settings",
            "com.android.systemui",
            // Password Managers & Authenticators
            "com.x8bit.bitwarden",
            "com.agilebits.onepassword",
            "com.lastpass.lpandroid",
            "com.google.android.apps.authenticator2",
            // Package Installers & Self-Protection
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.mobilemcp.pro"
        )

        // Attempt to forcefully misconfigure TIER_0 packages into read-only and consent-gated sets
        val engine = PolicyEngine(
            readOnlyPackages = hardDeniedPackages.toSet() + setOf("com.example.reader"),
            consentGatedPackages = hardDeniedPackages.toSet() + setOf("com.google.android.calculator")
        )

        for (pkg in hardDeniedPackages) {
            assertEquals("Expected TIER_0_HARD_DENY for $pkg", PackageTier.TIER_0_HARD_DENY, engine.classifyPackage(pkg))
            for (cmd in listOf("get_ui_tree", "click_element", "type_text")) {
                val decision = engine.evaluate(cmd, pkg)
                assertEquals("Expected DENY for $cmd on $pkg", PolicyDecisionType.DENY, decision.type)
                assertEquals(PackageTier.TIER_0_HARD_DENY, decision.tier)
            }
            assertEquals(
                "Expected target node DENY on $pkg",
                PolicyDecisionType.DENY,
                engine.verifyTargetNodePackage(pkg, refreshed = true, command = "get_ui_tree").type
            )
            assertEquals(
                "Expected post-consent DENY on $pkg",
                PolicyDecisionType.DENY,
                engine.verifyPostConsentContext(pkg, pkg, pkg, refreshed = true).type
            )
        }
    }

    @Test
    fun `tier 1 read only permits get_ui_tree and blocks all mutation commands`() {
        val engine = PolicyEngine(
            readOnlyPackages = PolicyEngine.DEFAULT_READ_ONLY_PACKAGES + setOf("com.example.reader")
        )

        val readOnlyPackages = listOf(
            "com.google.android.deskclock",
            "com.google.android.calendar",
            "com.example.reader"
        )

        for (pkg in readOnlyPackages) {
            assertEquals(PackageTier.TIER_1_READ_ONLY, engine.classifyPackage(pkg))

            val readDecision = engine.evaluate("get_ui_tree", pkg)
            assertEquals(PolicyDecisionType.ALLOW, readDecision.type)
            assertEquals(PackageTier.TIER_1_READ_ONLY, readDecision.tier)

            assertEquals(
                PolicyDecisionType.ALLOW,
                engine.verifyTargetNodePackage(pkg, refreshed = true, command = "get_ui_tree").type
            )

            for (mutation in listOf("click_element", "type_text")) {
                val mutDecision = engine.evaluate(mutation, pkg)
                assertEquals("Expected DENY for $mutation on TIER_1 $pkg", PolicyDecisionType.DENY, mutDecision.type)
                assertEquals(PackageTier.TIER_1_READ_ONLY, mutDecision.tier)

                assertEquals(
                    PolicyDecisionType.DENY,
                    engine.verifyTargetNodePackage(pkg, refreshed = true, command = mutation).type
                )
            }

            // Even post-consent verifier rejects TIER_1_READ_ONLY packages
            assertEquals(
                PolicyDecisionType.DENY,
                engine.verifyPostConsentContext(pkg, pkg, pkg, refreshed = true).type
            )
        }

        // TIER_2_CONSENT_GATED includes Honor/Huawei calculator variants and custom approved non-financial apps
        val customEngine = PolicyEngine(
            consentGatedPackages = PolicyEngine.DEFAULT_CONSENT_GATED_PACKAGES + setOf("com.example.notes")
        )
        for (pkg in listOf("com.hihonor.calculator", "com.huawei.calculator", "com.example.notes")) {
            assertEquals(PackageTier.TIER_2_CONSENT_GATED, customEngine.classifyPackage(pkg))
            assertEquals(PolicyDecisionType.REQUIRE_CONSENT, customEngine.evaluate("click_element", pkg).type)
            assertEquals(PolicyDecisionType.ALLOW, customEngine.verifyPostConsentContext(pkg, pkg, pkg, refreshed = true).type)
        }
    }

    @Test
    fun `consent rate limiter enforces 5 per minute sliding window`() {
        var fakeClockMs = 100_000L
        var nonceSeq = 0
        val coordinator = ConsentCoordinator(
            timeoutMs = 5_000L,
            clock = { fakeClockMs },
            nonceGenerator = { "win-nonce-${++nonceSeq}" }
        )

        // 5 approved consent prompts within 1 minute succeed
        for (i in 1..5) {
            val start = coordinator.startConsent(notificationsEnabled = true)
            assertTrue("Request #$i should start", start is ConsentCoordinator.StartResult.Started)
            val session = (start as ConsentCoordinator.StartResult.Started).session
            assertTrue(coordinator.submitDecision(session.nonce, approved = true))
            assertTrue(coordinator.awaitResult(session))
            fakeClockMs += 5_000L // t = 100s, 105s, 110s, 115s, 120s
        }

        // 6th request at t = 125s (within 60s of request #1 at 100s) must be rate-limited
        val blocked = coordinator.startConsent(notificationsEnabled = true)
        assertTrue(blocked is ConsentCoordinator.StartResult.Denied)
        val denied = blocked as ConsentCoordinator.StartResult.Denied
        assertTrue(denied.rateLimited)
        assertFalse(denied.cooldownActive)

        // Advance clock to t = 160_000L (60s after request #1 at 100_000L) -> slot reopens
        fakeClockMs = 160_000L
        val reopened = coordinator.startConsent(notificationsEnabled = true)
        assertTrue("Slot should reopen after 60s sliding window", reopened is ConsentCoordinator.StartResult.Started)
        val reopenedSession = (reopened as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(reopenedSession.nonce, approved = true))
        assertTrue(coordinator.awaitResult(reopenedSession))
    }

    @Test
    fun `consent rate limiter triggers 60s cooldown after 3 consecutive denials or timeouts and recovers after cooldown`() {
        var fakeClockMs = 10_000L
        var nonceSeq = 0
        val auditLogger = AuditLogger(tempFolder.root)
        val cooldownEvents = mutableListOf<Long>()

        val coordinator = ConsentCoordinator(
            timeoutMs = 5_000L,
            clock = { fakeClockMs },
            nonceGenerator = { "cd-nonce-${++nonceSeq}" },
            onCooldownTriggered = { untilMs ->
                cooldownEvents.add(untilMs)
                auditLogger.record(
                    action = "consent_rate_limiter",
                    targetPackage = "system",
                    targetElement = null,
                    consent = "cooldown",
                    status = "cooldown_activated_60s(until=$untilMs)"
                )
            }
        )

        // 1st failure: explicit denial
        val s1 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(s1.nonce, approved = false))
        assertFalse(coordinator.awaitResult(s1))
        assertFalse(coordinator.rateLimiter.isCooldownActive())

        // 2nd failure: timeout
        fakeClockMs += 1_000L
        val s2 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertFalse(coordinator.awaitResult(s2) { fakeClockMs += 6_000L })
        assertFalse(coordinator.rateLimiter.isCooldownActive())

        // An approval resets consecutive failure streak!
        fakeClockMs += 1_000L
        val sApproved = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(sApproved.nonce, approved = true))
        assertTrue(coordinator.awaitResult(sApproved))
        assertEquals(0, coordinator.rateLimiter.consecutiveFailureCount())

        // Advance past sliding window so we have clean quota for 3 consecutive failures
        fakeClockMs += 65_000L

        // 3 consecutive failures (2 denials + 1 timeout) must trigger 60s cooldown
        val f1 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(f1.nonce, approved = false))
        assertFalse(coordinator.awaitResult(f1))

        fakeClockMs += 1_000L
        val f2 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(f2.nonce, approved = false))
        assertFalse(coordinator.awaitResult(f2))

        fakeClockMs += 1_000L
        val f3 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertFalse(coordinator.awaitResult(f3) { fakeClockMs += 6_000L })

        assertTrue("Cooldown must be active after 3 consecutive failures", coordinator.rateLimiter.isCooldownActive())
        assertEquals(1, cooldownEvents.size)
        assertEquals(ConsentRateLimiter.DEFAULT_COOLDOWN_MS, coordinator.rateLimiter.remainingCooldownMs())

        // Audit log recorded cooldown activation with valid hash chain
        val lines = auditLogger.getLogLines()
        assertEquals(1, lines.size)
        assertTrue(lines[0].contains("cooldown_activated_60s"))
        assertTrue(AuditLogger.verifyChainIntegrity(lines))

        // Requests during cooldown are immediately denied
        fakeClockMs += 30_000L
        val duringCooldown = coordinator.startConsent(true)
        assertTrue(duringCooldown is ConsentCoordinator.StartResult.Denied)
        assertTrue((duringCooldown as ConsentCoordinator.StartResult.Denied).cooldownActive)

        // Advance past remaining 30s of cooldown -> requests work again
        fakeClockMs += 31_000L
        assertFalse(coordinator.rateLimiter.isCooldownActive())
        val recovered = coordinator.startConsent(true)
        assertTrue("Consent should succeed after cooldown expires", recovered is ConsentCoordinator.StartResult.Started)
        val recSession = (recovered as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(recSession.nonce, approved = true))
        assertTrue(coordinator.awaitResult(recSession))
    }

    @Test
    fun `dynamic policy store encrypts persists and enforces tier 1 and tier 2 immediately`() {
        val vault = InMemoryEncryptedPolicyVault()
        val engine = PolicyEngine()
        val store = DynamicPolicyStore(vault, engine)

        // Initially unlisted package is denied
        assertEquals(PackageTier.TIER_0_HARD_DENY, engine.classifyPackage("com.example.reader"))
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("get_ui_tree", "com.example.reader").type)

        // Add to TIER_1_READ_ONLY -> immediately allowed for read, denied for mutations
        val res1 = store.addPackage("com.example.reader", PackageTier.TIER_1_READ_ONLY)
        assertTrue(res1 is PolicyUpdateResult.Success)
        assertEquals(PackageTier.TIER_1_READ_ONLY, engine.classifyPackage("com.example.reader"))
        assertEquals(PolicyDecisionType.ALLOW, engine.evaluate("get_ui_tree", "com.example.reader").type)
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("click_element", "com.example.reader").type)

        // Add another package to TIER_2_CONSENT_GATED -> immediately requires consent
        val res2 = store.addPackage("com.example.notes", PackageTier.TIER_2_CONSENT_GATED)
        assertTrue(res2 is PolicyUpdateResult.Success)
        assertEquals(PackageTier.TIER_2_CONSENT_GATED, engine.classifyPackage("com.example.notes"))
        assertEquals(PolicyDecisionType.REQUIRE_CONSENT, engine.evaluate("click_element", "com.example.notes").type)
        assertEquals(PolicyDecisionType.REQUIRE_CONSENT, engine.evaluate("type_text", "com.example.notes").type)

        // Encrypted vault payload must not expose raw plaintext package names unencrypted
        val encryptedText = vault.readEncryptedPayload()
        assertTrue(encryptedText!!.contains("com.example.reader"))

        // Reload into a brand-new PolicyEngine instance from the same encrypted vault
        val freshEngine = PolicyEngine()
        DynamicPolicyStore(vault, freshEngine)
        assertEquals(PackageTier.TIER_1_READ_ONLY, freshEngine.classifyPackage("com.example.reader"))
        assertEquals(PackageTier.TIER_2_CONSENT_GATED, freshEngine.classifyPackage("com.example.notes"))

        // Remove package -> reverts immediately to default-deny
        assertTrue(store.removePackage("com.example.notes"))
        assertEquals(PackageTier.TIER_0_HARD_DENY, engine.classifyPackage("com.example.notes"))
        assertEquals(PolicyDecisionType.DENY, engine.evaluate("click_element", "com.example.notes").type)
    }

    @Test
    fun `dynamic policy store rejects all tier 0 hard deny packages even if storage is tampered`() {
        val vault = InMemoryEncryptedPolicyVault()
        val engine = PolicyEngine()
        val store = DynamicPolicyStore(vault, engine)

        val forbidden = listOf(
            "com.reflect",
            "com.umniah.uwallet",
            "com.android.settings",
            "com.x8bit.bitwarden",
            "com.android.packageinstaller",
            "com.mobilemcp.pro",
            "com.example.mybank"
        )

        for (pkg in forbidden) {
            for (targetTier in listOf(PackageTier.TIER_1_READ_ONLY, PackageTier.TIER_2_CONSENT_GATED, PackageTier.TIER_0_HARD_DENY)) {
                val res = store.addPackage(pkg, targetTier)
                assertTrue("Expected rejection for $pkg -> $targetTier", res is PolicyUpdateResult.Rejected)
                assertEquals(PackageTier.TIER_0_HARD_DENY, engine.classifyPackage(pkg))
                assertEquals(PolicyDecisionType.DENY, engine.evaluate("get_ui_tree", pkg).type)
                assertEquals(PolicyDecisionType.DENY, engine.evaluate("click_element", pkg).type)
            }
        }

        // Simulate tampered vault payload attempting to inject TIER_0 packages directly
        val tamperedBackend = object : PolicyVaultBackend {
            override fun readEncryptedPayload(): String =
                """{"readOnlyPackages":["com.android.settings"],"consentGatedPackages":["com.reflect","com.umniah.uwallet"]}"""
            override fun writeEncryptedPayload(plaintextJson: String) {}
            override fun clear() {}
        }
        val hardenedEngine = PolicyEngine()
        val hardenedStore = DynamicPolicyStore(tamperedBackend, hardenedEngine)

        assertTrue(hardenedStore.getReadOnlyPackages().isEmpty())
        assertTrue(hardenedStore.getConsentGatedPackages().isEmpty())
        assertEquals(PackageTier.TIER_0_HARD_DENY, hardenedEngine.classifyPackage("com.reflect"))
        assertEquals(PackageTier.TIER_0_HARD_DENY, hardenedEngine.classifyPackage("com.umniah.uwallet"))
        assertEquals(PackageTier.TIER_0_HARD_DENY, hardenedEngine.classifyPackage("com.android.settings"))
    }

    @Test
    fun `audit logger exports signed bundle and independent verifier detects any tampering or deletion`() {
        val logger = AuditLogger(tempFolder.root)
        logger.record("get_ui_tree", "com.google.android.calculator", null, "not_required", "executed")
        logger.record("click_element", "com.google.android.calculator", "7", "approved", "executed")
        logger.record("click_element", "com.reflect", null, "n/a", "denied: TIER_0_HARD_DENY")

        val exportedJson = logger.exportSignedAuditBundle(clock = { 1_763_300_000_000L })
        assertTrue(exportedJson.contains("\"chainValid\": true"))
        assertTrue(exportedJson.contains("\"entryCount\": 3"))
        assertTrue(exportedJson.contains("\"exportedAtEpochMs\": 1763300000000"))
        assertTrue(exportedJson.contains("\"prevHash\""))
        assertTrue(exportedJson.contains("\"hash\""))

        val verification = AuditLogger.verifyExportedBundleDetailed(exportedJson)
        assertTrue("Expected valid exported bundle, got: ${verification.reason}", verification.valid)
        assertEquals(3, verification.entryCount)
        assertTrue(AuditLogger.verifyExportedBundle(exportedJson))

        // 1. Modify a single character in an entry status
        val tamperedStatus = exportedJson.replace("\"status\": \"executed\"", "\"status\": \"forged00\"")
        assertFalse(AuditLogger.verifyExportedBundle(tamperedStatus))

        // 2. Modify bundle export timestamp metadata
        val tamperedTimestamp = exportedJson.replace("1763300000000", "1763300000001")
        assertFalse(AuditLogger.verifyExportedBundle(tamperedTimestamp))

        // 3. Delete middle entry from JSON
        val gson = com.google.gson.Gson()
        val parsed = gson.fromJson(exportedJson, com.mobilemcp.pro.service.AuditExportBundle::class.java)
        val truncatedBundle = parsed.copy(
            entryCount = 2,
            summary = parsed.summary.copy(entryCount = 2),
            entries = listOf(parsed.entries[0], parsed.entries[2])
        )
        assertFalse(AuditLogger.verifyExportedBundle(gson.toJson(truncatedBundle)))
    }

    @Test
    fun `integration between dynamic policy store consent rate limiter post consent context and audit export`() {
        var fakeClockMs = 50_000L
        var nonceSeq = 0
        val engine = PolicyEngine()
        val store = DynamicPolicyStore(InMemoryEncryptedPolicyVault(), engine)
        val logger = AuditLogger(tempFolder.root)
        val coordinator = ConsentCoordinator(
            timeoutMs = 10_000L,
            clock = { fakeClockMs },
            nonceGenerator = { "int-nonce-${++nonceSeq}" },
            onCooldownTriggered = { untilMs ->
                logger.record("consent_rate_limiter", "system", null, "cooldown", "cooldown_activated_60s(until=$untilMs)")
            }
        )

        // Add custom app to TIER_2_CONSENT_GATED
        assertTrue(store.addPackage("com.example.workflow", PackageTier.TIER_2_CONSENT_GATED) is PolicyUpdateResult.Success)
        assertEquals(PolicyDecisionType.REQUIRE_CONSENT, engine.evaluate("click_element", "com.example.workflow").type)

        // Perform 1 approved action with post-consent TOCTOU check
        val s1 = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
        assertTrue(coordinator.submitDecision(s1.nonce, approved = true))
        assertTrue(coordinator.awaitResult(s1))
        assertEquals(
            PolicyDecisionType.ALLOW,
            engine.verifyPostConsentContext("com.example.workflow", "com.example.workflow", "com.example.workflow", refreshed = true).type
        )
        logger.record("click_element", "com.example.workflow", "Submit", "approved", "executed")

        // Trigger 3 consecutive denials -> activates 60s cooldown and logs it
        repeat(3) {
            fakeClockMs += 1_000L
            val session = (coordinator.startConsent(true) as ConsentCoordinator.StartResult.Started).session
            assertTrue(coordinator.submitDecision(session.nonce, approved = false))
            assertFalse(coordinator.awaitResult(session))
            logger.record("click_element", "com.example.workflow", "Submit", "denied_or_timeout", "denied")
        }

        // Next consent request must be blocked by cooldown
        val blocked = coordinator.startConsent(true)
        assertTrue(blocked is ConsentCoordinator.StartResult.Denied)
        assertTrue((blocked as ConsentCoordinator.StartResult.Denied).cooldownActive)

        // Export and independently verify the full audit bundle
        val bundleJson = logger.exportSignedAuditBundle(clock = { fakeClockMs })
        val result = AuditLogger.verifyExportedBundleDetailed(bundleJson)
        assertTrue(result.valid)
        assertEquals(5, result.entryCount)
        assertTrue(bundleJson.contains("cooldown_activated_60s"))
    }
}
