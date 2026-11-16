package com.mobilemcp.pro

import com.mobilemcp.pro.security.ConsentCoordinator
import com.mobilemcp.pro.security.NodeSanitizer
import com.mobilemcp.pro.security.PolicyDecisionType
import com.mobilemcp.pro.security.PolicyEngine
import com.mobilemcp.pro.server.WebSocketCommandServer
import com.mobilemcp.pro.service.AuditLogger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.net.InetAddress

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
}
