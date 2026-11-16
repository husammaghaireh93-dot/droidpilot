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
 * Pure JVM sliding-window consent rate limiter and consecutive-failure cooldown enforcer.
 * - Caps consent prompts at [maxRequestsPerWindow] within [windowMs] (default: 5 per 60s).
 * - Enforces a mandatory [cooldownMs] lockout (default: 60s) after [maxConsecutiveFailures]
 *   consecutive denials or timeouts (default: 3).
 */
class ConsentRateLimiter(
    private val maxRequestsPerWindow: Int = DEFAULT_MAX_REQUESTS_PER_WINDOW,
    private val windowMs: Long = DEFAULT_WINDOW_MS,
    private val maxConsecutiveFailures: Int = DEFAULT_MAX_CONSECUTIVE_FAILURES,
    private val cooldownMs: Long = DEFAULT_COOLDOWN_MS,
    private val clock: () -> Long = System::currentTimeMillis
) {
    companion object {
        const val DEFAULT_MAX_REQUESTS_PER_WINDOW = 5
        const val DEFAULT_WINDOW_MS = 60_000L
        const val DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
        const val DEFAULT_COOLDOWN_MS = 60_000L
    }

    sealed class AcquireResult {
        object Allowed : AcquireResult()
        data class Denied(val reason: String, val cooldownActive: Boolean) : AcquireResult()
    }

    data class OutcomeResult(
        val consecutiveFailures: Int,
        val cooldownTriggered: Boolean,
        val cooldownUntilMs: Long
    )

    private val requestTimestamps = ArrayDeque<Long>()
    private var consecutiveFailures: Int = 0
    private var cooldownUntilMs: Long = 0L

    @Synchronized
    private fun refreshCooldownState(now: Long) {
        if (cooldownUntilMs > 0L && now >= cooldownUntilMs) {
            cooldownUntilMs = 0L
            consecutiveFailures = 0
        }
    }

    @Synchronized
    fun tryAcquire(): AcquireResult {
        val now = clock()
        refreshCooldownState(now)

        if (now < cooldownUntilMs) {
            val remainingSec = (cooldownUntilMs - now + 999L) / 1000L
            return AcquireResult.Denied(
                reason = "Consent cooldown active for ${remainingSec}s after $maxConsecutiveFailures consecutive denials or timeouts.",
                cooldownActive = true
            )
        }

        while (requestTimestamps.isNotEmpty() && now - requestTimestamps.first() >= windowMs) {
            requestTimestamps.removeFirst()
        }

        if (requestTimestamps.size >= maxRequestsPerWindow) {
            return AcquireResult.Denied(
                reason = "Consent rate limit exceeded: maximum $maxRequestsPerWindow requests per ${windowMs / 1000L}s.",
                cooldownActive = false
            )
        }

        requestTimestamps.addLast(now)
        return AcquireResult.Allowed
    }

    @Synchronized
    fun recordOutcome(approved: Boolean): OutcomeResult {
        val now = clock()
        refreshCooldownState(now)

        if (approved) {
            consecutiveFailures = 0
            return OutcomeResult(
                consecutiveFailures = 0,
                cooldownTriggered = false,
                cooldownUntilMs = cooldownUntilMs
            )
        }

        consecutiveFailures += 1
        if (consecutiveFailures >= maxConsecutiveFailures) {
            cooldownUntilMs = now + cooldownMs
            consecutiveFailures = 0
            return OutcomeResult(
                consecutiveFailures = 0,
                cooldownTriggered = true,
                cooldownUntilMs = cooldownUntilMs
            )
        }

        return OutcomeResult(
            consecutiveFailures = consecutiveFailures,
            cooldownTriggered = false,
            cooldownUntilMs = cooldownUntilMs
        )
    }

    @Synchronized
    fun isCooldownActive(): Boolean {
        val now = clock()
        refreshCooldownState(now)
        return cooldownUntilMs > now
    }

    @Synchronized
    fun remainingCooldownMs(): Long {
        val now = clock()
        refreshCooldownState(now)
        return if (cooldownUntilMs > now) cooldownUntilMs - now else 0L
    }

    @Synchronized
    fun consecutiveFailureCount(): Int = consecutiveFailures
}

/**
 * Pure JVM consent coordinator enforcing:
 * - Notification availability prerequisite
 * - Sliding-window rate limiting & consecutive-denial cooldown via [ConsentRateLimiter]
 * - Single active consent request (concurrency = 1)
 * - Single-use cryptographic nonce
 * - Configurable timeout with strict Default-Deny
 * - Injectable clock for deterministic unit testing
 */
class ConsentCoordinator(
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    private val clock: () -> Long = System::currentTimeMillis,
    private val nonceGenerator: () -> String = defaultNonceGenerator,
    val rateLimiter: ConsentRateLimiter = ConsentRateLimiter(clock = clock),
    private val onCooldownTriggered: ((Long) -> Unit)? = null
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
        data class Denied(
            val reason: String,
            val rateLimited: Boolean = false,
            val cooldownActive: Boolean = false
        ) : StartResult()
    }

    private val lock = Object()
    private var activeSession: ConsentSession? = null
    private var pendingDecision: Boolean? = null
    private var lastRecordedNonce: String? = null

    private fun recordOutcomeLocked(nonce: String, approved: Boolean): ConsentRateLimiter.OutcomeResult? {
        if (lastRecordedNonce == nonce) return null
        lastRecordedNonce = nonce
        return rateLimiter.recordOutcome(approved)
    }

    fun startConsent(notificationsEnabled: Boolean): StartResult {
        if (!notificationsEnabled) {
            return StartResult.Denied("Notifications are disabled; cannot gather explicit user consent.")
        }

        var expiredCooldownUntil: Long? = null
        val result: StartResult

        synchronized(lock) {
            val existing = activeSession
            if (existing != null) {
                if (clock() <= existing.expiresAtMs && pendingDecision == null) {
                    return StartResult.Denied("Another consent request is already pending.")
                }
                // Previous session already expired; record timeout outcome if not yet recorded and clean up
                val outcome = recordOutcomeLocked(existing.nonce, false)
                if (outcome?.cooldownTriggered == true) {
                    expiredCooldownUntil = outcome.cooldownUntilMs
                }
                activeSession = null
                pendingDecision = null
            }

            val acquire = rateLimiter.tryAcquire()
            if (acquire is ConsentRateLimiter.AcquireResult.Denied) {
                result = StartResult.Denied(
                    reason = acquire.reason,
                    rateLimited = true,
                    cooldownActive = acquire.cooldownActive
                )
            } else {
                val now = clock()
                val session = ConsentSession(
                    nonce = nonceGenerator(),
                    createdAtMs = now,
                    expiresAtMs = now + timeoutMs
                )
                activeSession = session
                pendingDecision = null
                result = StartResult.Started(session)
            }
        }

        expiredCooldownUntil?.let { until ->
            onCooldownTriggered?.invoke(until)
        }
        return result
    }

    fun submitDecision(nonce: String?, approved: Boolean): Boolean {
        if (nonce.isNullOrBlank()) return false
        var outcome: ConsentRateLimiter.OutcomeResult? = null
        val accepted: Boolean

        synchronized(lock) {
            val session = activeSession ?: return false
            if (session.nonce != nonce) return false

            if (clock() > session.expiresAtMs) {
                // Expired: default deny and invalidate session
                pendingDecision = false
                activeSession = null
                outcome = recordOutcomeLocked(session.nonce, false)
                lock.notifyAll()
                accepted = false
            } else {
                // Single-use resolution: consume session immediately
                pendingDecision = approved
                activeSession = null
                outcome = recordOutcomeLocked(session.nonce, approved)
                lock.notifyAll()
                accepted = true
            }
        }

        if (outcome?.cooldownTriggered == true) {
            onCooldownTriggered?.invoke(outcome!!.cooldownUntilMs)
        }
        return accepted
    }

    fun awaitResult(
        session: ConsentSession,
        waitStep: ((Long) -> Unit)? = null
    ): Boolean {
        var cooldownTriggeredUntil: Long? = null
        try {
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
                            val outcome = recordOutcomeLocked(session.nonce, false)
                            if (outcome?.cooldownTriggered == true) {
                                cooldownTriggeredUntil = outcome.cooldownUntilMs
                            }
                            return false
                        }

                        val remaining = session.expiresAtMs - clock()
                        if (remaining <= 0L) {
                            val outcome = recordOutcomeLocked(session.nonce, false)
                            if (outcome?.cooldownTriggered == true) {
                                cooldownTriggeredUntil = outcome.cooldownUntilMs
                            }
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
                        val outcome = recordOutcomeLocked(session.nonce, false)
                        if (outcome?.cooldownTriggered == true) {
                            cooldownTriggeredUntil = outcome.cooldownUntilMs
                        }
                        activeSession = null
                        pendingDecision = null
                        lock.notifyAll()
                    }
                }
            }
        } finally {
            cooldownTriggeredUntil?.let { until ->
                onCooldownTriggered?.invoke(until)
            }
        }
    }

    fun cancelActive() {
        var outcome: ConsentRateLimiter.OutcomeResult? = null
        synchronized(lock) {
            val session = activeSession
            if (session != null) {
                outcome = recordOutcomeLocked(session.nonce, false)
                pendingDecision = false
                activeSession = null
                lock.notifyAll()
            }
        }
        if (outcome?.cooldownTriggered == true) {
            onCooldownTriggered?.invoke(outcome!!.cooldownUntilMs)
        }
    }
}
