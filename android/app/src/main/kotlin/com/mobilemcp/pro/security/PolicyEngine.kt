package com.mobilemcp.pro.security

enum class PackageTier {
    TIER_0_HARD_DENY,
    TIER_1_READ_ONLY,
    TIER_2_CONSENT_GATED
}

enum class PolicyDecisionType {
    ALLOW,
    REQUIRE_CONSENT,
    DENY
}

data class PolicyDecision(
    val type: PolicyDecisionType,
    val reason: String,
    val tier: PackageTier = PackageTier.TIER_0_HARD_DENY
)

/**
 * Pure JVM policy engine with zero Android framework dependencies.
 * Enforces strict default-deny command allowlist and tiered package classification:
 * - TIER_0_HARD_DENY: Permanent non-overridable block for financial/banking/wallet apps,
 *   system settings, password managers, package installers, and unlisted packages.
 * - TIER_1_READ_ONLY: Permits get_ui_tree (with NodeSanitizer) only; denies all mutations.
 * - TIER_2_CONSENT_GATED: Permits get_ui_tree and gates click_element/type_text behind
 *   per-action human consent and post-consent TOCTOU verification.
 */
class PolicyEngine(
    readOnlyPackages: Set<String> = DEFAULT_READ_ONLY_PACKAGES,
    consentGatedPackages: Set<String> = DEFAULT_CONSENT_GATED_PACKAGES
) {
    // Strip any TIER_0_HARD_DENY package so caller configuration can never override hard-deny rules.
    private val effectiveConsentGatedPackages: Set<String> =
        consentGatedPackages.filterNot { isHardDeniedPackage(it) }.toSet()

    private val effectiveReadOnlyPackages: Set<String> =
        readOnlyPackages.filterNot { isHardDeniedPackage(it) || it in effectiveConsentGatedPackages }.toSet()

    companion object {
        val ALLOWED_READ_COMMANDS = setOf("get_ui_tree")
        val ALLOWED_MUTATION_COMMANDS = setOf("click_element", "type_text")
        val ALLOWED_COMMANDS = ALLOWED_READ_COMMANDS + ALLOWED_MUTATION_COMMANDS

        /**
         * Complete inventory of commands present in upstream MobileAccessibilityService.handleCommand.
         */
        val ALL_KNOWN_COMMANDS = listOf(
            "tap",
            "long_press",
            "swipe",
            "type_text",
            "set_text",
            "press_key",
            "get_ui_tree",
            "find_element",
            "screenshot",
            "wait_for_element",
            "open_app",
            "get_device_info",
            "scroll",
            "pinch",
            "click_element",
            "get_focused",
            "notifications",
            "ping"
        )

        val HARD_DENY_EXACT_PACKAGES = setOf(
            // Financial / Digital Wallets / Banking
            "com.reflect",
            "com.umniah.uwallet",
            "com.paypal.android.p2pmobile",
            "com.venmo",
            "com.squareup.cash",
            "com.google.android.apps.walletnfcrel",
            "com.google.android.apps.nbu.paisa.user",
            "com.revolut.revolut",
            "com.wise.android",
            "com.binance.dev",
            "com.coinbase.android",
            // System Settings & Security Surfaces
            "com.android.settings",
            "com.android.providers.settings",
            "com.android.systemui",
            "com.huawei.systemmanager",
            "com.hihonor.systemmanager",
            "com.miui.securitycenter",
            "com.coloros.safecenter",
            "com.samsung.android.lool",
            // Password Managers & Authenticators
            "com.agilebits.onepassword",
            "com.lastpass.lpandroid",
            "com.x8bit.bitwarden",
            "com.dashlane",
            "com.nordpass",
            "io.enpass.app",
            "com.samsung.android.samsungpass",
            "com.google.android.apps.authenticator2",
            "com.authy.authy",
            "com.duosecurity.duomobile",
            // Package Installers & Self-Protection
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.samsung.android.packageinstaller",
            "com.miui.packageinstaller",
            "com.huawei.packageinstaller",
            "com.hihonor.packageinstaller",
            "com.mobilemcp.pro"
        )

        val HARD_DENY_PREFIXES = listOf(
            "com.reflect.",
            "com.android.settings.",
            "com.google.android.gms.credential"
        )

        val HARD_DENY_SUBSTRING_KEYWORDS = setOf(
            "bank",
            "banking",
            "wallet",
            "uwallet",
            "finance",
            "financial",
            "fintech",
            "payment",
            "paypal",
            "money",
            "cash",
            "crypto",
            "bitcoin",
            "exchange",
            "remit",
            "zaincash",
            "dinarak",
            "efawateer",
            "cliq",
            "iban",
            "password",
            "passman",
            "bitwarden",
            "onepassword",
            "lastpass",
            "dashlane",
            "nordpass",
            "keepass",
            "authenticator",
            "packageinstaller"
        )

        val HARD_DENY_SEGMENT_KEYWORDS = setOf(
            "pay",
            "card",
            "credit",
            "debit",
            "invest",
            "broker",
            "treasury",
            "trading",
            "reflect",
            "settings"
        )

        val DEFAULT_READ_ONLY_PACKAGES = setOf(
            "com.google.android.deskclock",
            "com.android.deskclock",
            "com.hihonor.deskclock",
            "com.huawei.deskclock",
            "com.google.android.calendar",
            "com.android.calendar"
        )

        val DEFAULT_CONSENT_GATED_PACKAGES = setOf(
            "com.google.android.calculator",
            "com.android.calculator2",
            "com.hihonor.calculator",
            "com.huawei.calculator"
        )

        val DEFAULT_ALLOWED_PACKAGES = DEFAULT_CONSENT_GATED_PACKAGES

        fun isHardDeniedPackage(packageName: String?): Boolean {
            if (packageName.isNullOrBlank()) return true
            val normalized = packageName.trim().lowercase()
            if (normalized in HARD_DENY_EXACT_PACKAGES) return true
            if (HARD_DENY_PREFIXES.any { normalized.startsWith(it) }) return true
            if (HARD_DENY_SUBSTRING_KEYWORDS.any { normalized.contains(it) }) return true

            val segments = normalized.split('.', '_', '-')
            if (segments.any { it in HARD_DENY_SEGMENT_KEYWORDS }) return true
            return false
        }
    }

    fun classifyPackage(packageName: String?): PackageTier {
        if (packageName.isNullOrBlank() || isHardDeniedPackage(packageName)) {
            return PackageTier.TIER_0_HARD_DENY
        }
        val normalized = packageName.trim()
        return when (normalized) {
            in effectiveConsentGatedPackages -> PackageTier.TIER_2_CONSENT_GATED
            in effectiveReadOnlyPackages -> PackageTier.TIER_1_READ_ONLY
            else -> PackageTier.TIER_0_HARD_DENY
        }
    }

    fun evaluate(command: String?, currentPackage: String?): PolicyDecision {
        val tier = classifyPackage(currentPackage)

        if (command.isNullOrBlank() || command !in ALLOWED_COMMANDS) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Command '${command ?: "null"}' is denied by default-deny allowlist.",
                tier = tier
            )
        }

        if (tier == PackageTier.TIER_0_HARD_DENY) {
            val detail = if (isHardDeniedPackage(currentPackage)) {
                "Package '${currentPackage ?: "null"}' is permanently blocked by TIER_0_HARD_DENY."
            } else {
                "Package '${currentPackage ?: "null"}' is not in an allowed package tier (default-deny)."
            }
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = detail,
                tier = tier
            )
        }

        return when (tier) {
            PackageTier.TIER_1_READ_ONLY -> {
                if (command in ALLOWED_READ_COMMANDS) {
                    PolicyDecision(
                        type = PolicyDecisionType.ALLOW,
                        reason = "Read command '$command' permitted on TIER_1_READ_ONLY package '$currentPackage'.",
                        tier = tier
                    )
                } else {
                    PolicyDecision(
                        type = PolicyDecisionType.DENY,
                        reason = "Mutation command '$command' is denied on TIER_1_READ_ONLY package '$currentPackage'.",
                        tier = tier
                    )
                }
            }
            PackageTier.TIER_2_CONSENT_GATED -> {
                when (command) {
                    in ALLOWED_READ_COMMANDS -> PolicyDecision(
                        type = PolicyDecisionType.ALLOW,
                        reason = "Read command '$command' permitted on TIER_2_CONSENT_GATED package '$currentPackage'.",
                        tier = tier
                    )
                    in ALLOWED_MUTATION_COMMANDS -> PolicyDecision(
                        type = PolicyDecisionType.REQUIRE_CONSENT,
                        reason = "Mutation command '$command' on TIER_2_CONSENT_GATED package '$currentPackage' requires explicit user consent.",
                        tier = tier
                    )
                    else -> PolicyDecision(
                        type = PolicyDecisionType.DENY,
                        reason = "Command '$command' denied.",
                        tier = tier
                    )
                }
            }
            PackageTier.TIER_0_HARD_DENY -> PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Package '${currentPackage ?: "null"}' is blocked.",
                tier = tier
            )
        }
    }

    fun verifyTargetNodePackage(
        targetPackage: String?,
        refreshed: Boolean,
        command: String = "get_ui_tree"
    ): PolicyDecision {
        val tier = classifyPackage(targetPackage)
        if (!refreshed) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Target node refresh() failed; UI hierarchy changed before execution.",
                tier = tier
            )
        }
        val evalDecision = evaluate(command, targetPackage)
        if (evalDecision.type == PolicyDecisionType.DENY) {
            return evalDecision
        }
        return PolicyDecision(
            type = PolicyDecisionType.ALLOW,
            reason = "Target node verified on $tier package '$targetPackage' for '$command'.",
            tier = tier
        )
    }

    /**
     * Post-consent TOCTOU guard: verifies that after user approval and right before
     * performAction(), the active foreground window package and refreshed target node package
     * still strictly match the exact TIER_2_CONSENT_GATED package the user approved.
     */
    fun verifyPostConsentContext(
        consentedPackage: String?,
        currentPackage: String?,
        targetPackage: String?,
        refreshed: Boolean
    ): PolicyDecision {
        val consentedTier = classifyPackage(consentedPackage)
        if (!refreshed) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Target node refresh() failed; UI hierarchy changed after consent.",
                tier = consentedTier
            )
        }
        if (consentedTier != PackageTier.TIER_2_CONSENT_GATED) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Consented package '${consentedPackage ?: "null"}' is in $consentedTier, not TIER_2_CONSENT_GATED.",
                tier = consentedTier
            )
        }
        if (currentPackage != consentedPackage) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Active foreground package '${currentPackage ?: "null"}' changed from consented '$consentedPackage'.",
                tier = classifyPackage(currentPackage)
            )
        }
        if (targetPackage != consentedPackage) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY,
                reason = "Target node package '${targetPackage ?: "null"}' does not match consented '$consentedPackage'.",
                tier = classifyPackage(targetPackage)
            )
        }
        return PolicyDecision(
            type = PolicyDecisionType.ALLOW,
            reason = "Post-consent foreground window and node verified for TIER_2_CONSENT_GATED '$consentedPackage'.",
            tier = consentedTier
        )
    }
}
