package com.mobilemcp.pro.security

import java.security.SecureRandom

/**
 * Pure JVM node field sanitizer. Nullifies text and contentDescription on password inputs.
 */
object NodeSanitizer {
    fun sanitizeNodeFields(
        rawText: String?,
        rawContentDescription: String?,
        isPassword: Boolean
    ): Pair<String?, String?> {
        return if (isPassword) {
            Pair(null, null)
        } else {
            Pair(rawText, rawContentDescription)
        }
    }
}

/**
 * Pure JVM consent coordinator enforcing:
 * - Notification availability prerequisite
 * - Single active consent request (concurrency = 1)
 * - Single-use cryptographic nonce
 * - Configurable timeout with strict Default-Deny
 * - Injectable clock for deterministic unit testing
 */
class ConsentCoordinator(
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val clock: () -> Long = System::currentTimeMillis,
    private val nonceGenerator: () -> String = defaultNonceGenerator
) {
    companion object {
        const val DEFAULT_TIMEOUT_MS = 15_000L

        private val secureRandom = SecureRandom()
        val defaultNonceGenerator: () -> String = {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            bytes.joinToString("") { "%02x".format(it) }
        }
    }

    data class ConsentSession(
        val nonce: String,
        val createdAtMs: Long,
        val expiresAtMs: Long
    )

    sealed class StartResult {
        data class Started(val session: ConsentSession) : StartResult()
        data class Denied(val reason: String) : StartResult()
    }

    private val lock = Object()
    private var activeSession: ConsentSession? = null
    private var pendingDecision: Boolean? = null

    fun startConsent(notificationsEnabled: Boolean): StartResult {
        if (!notificationsEnabled) {
            return StartResult.Denied("Notifications are disabled; cannot gather explicit user consent.")
        }

        synchronized(lock) {
            val existing = activeSession
            if (existing != null) {
                if (clock() <= existing.expiresAtMs && pendingDecision == null) {
                    return StartResult.Denied("Another consent request is already pending.")
                }
                // Previous session already expired; clean up before starting new one
                activeSession = null
                pendingDecision = null
            }

            val now = clock()
            val session = ConsentSession(
                nonce = nonceGenerator(),
                createdAtMs = now,
                expiresAtMs = now + timeoutMs
            )
            activeSession = session
            pendingDecision = null
            return StartResult.Started(session)
        }
    }

    fun submitDecision(nonce: String?, approved: Boolean): Boolean {
        if (nonce.isNullOrBlank()) return false
        synchronized(lock) {
            val session = activeSession ?: return false
            if (session.nonce != nonce) return false

            if (clock() > session.expiresAtMs) {
                // Expired: default deny and invalidate session
                pendingDecision = false
                activeSession = null
                lock.notifyAll()
                return false
            }

            // Single-use resolution: consume session immediately
            pendingDecision = approved
            activeSession = null
            lock.notifyAll()
            return true
        }
    }

    fun awaitResult(
        session: ConsentSession,
        waitStep: ((Long) -> Unit)? = null
    ): Boolean {
        synchronized(lock) {
            try {
                while (true) {
                    val resolved = pendingDecision
                    if (resolved != null) {
                        pendingDecision = null
                        activeSession = null
                        return resolved
                    }

                    // If session was cleared externally without setting pendingDecision, deny
                    if (activeSession?.nonce != session.nonce) {
                        pendingDecision = null
                        return false
                    }

                    val remaining = session.expiresAtMs - clock()
                    if (remaining <= 0L) {
                        return false
                    }

                    if (waitStep != null) {
                        waitStep(remaining)
                    } else {
                        lock.wait(remaining)
                    }
                }
            } finally {
                // Always purge active session & nonce on timeout, cancellation, or exception
                if (activeSession?.nonce == session.nonce) {
                    activeSession = null
                    pendingDecision = null
                    lock.notifyAll()
                }
            }
        }
    }

    fun cancelActive() {
        synchronized(lock) {
            if (activeSession != null) {
                pendingDecision = false
                activeSession = null
                lock.notifyAll()
            }
        }
    }
}
