package com.mobilemcp.pro

import com.mobilemcp.pro.security.ConsentCoordinator
import com.mobilemcp.pro.security.NodeSanitizer
import com.mobilemcp.pro.security.PolicyDecisionType
import com.mobilemcp.pro.security.PolicyEngine
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
}
