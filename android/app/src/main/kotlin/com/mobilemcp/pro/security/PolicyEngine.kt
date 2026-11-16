package com.mobilemcp.pro.security

enum class PolicyDecisionType {
    ALLOW,
    REQUIRE_CONSENT,
    DENY
}

data class PolicyDecision(
    val type: PolicyDecisionType,
    val reason: String
)

/**
 * Pure JVM policy engine with zero Android framework dependencies.
 * Enforces strict default-deny command allowlist and package whitelist.
 */
class PolicyEngine(
    private val allowedPackages: Set<String> = DEFAULT_ALLOWED_PACKAGES
) {
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

        val DEFAULT_ALLOWED_PACKAGES = setOf(
            "com.google.android.calculator",
            "com.android.calculator2"
        )
    }

    fun evaluate(command: String?, currentPackage: String?): PolicyDecision {
        if (command.isNullOrBlank() || command !in ALLOWED_COMMANDS) {
            return PolicyDecision(
                PolicyDecisionType.DENY,
                "Command '${command ?: "null"}' is denied by default-deny allowlist."
            )
        }

        if (currentPackage.isNullOrBlank() || currentPackage !in allowedPackages) {
            return PolicyDecision(
                PolicyDecisionType.DENY,
                "Package '${currentPackage ?: "null"}' is not in the allowed package whitelist."
            )
        }

        return when (command) {
            in ALLOWED_READ_COMMANDS -> PolicyDecision(
                PolicyDecisionType.ALLOW,
                "Read command '$command' permitted on whitelisted package '$currentPackage'."
            )
            in ALLOWED_MUTATION_COMMANDS -> PolicyDecision(
                PolicyDecisionType.REQUIRE_CONSENT,
                "Mutation command '$command' on '$currentPackage' requires explicit user consent."
            )
            else -> PolicyDecision(
                PolicyDecisionType.DENY,
                "Command '$command' denied."
            )
        }
    }

    fun verifyTargetNodePackage(targetPackage: String?, refreshed: Boolean): PolicyDecision {
        if (!refreshed) {
            return PolicyDecision(
                PolicyDecisionType.DENY,
                "Target node refresh() failed; UI hierarchy changed before execution."
            )
        }
        if (targetPackage.isNullOrBlank() || targetPackage !in allowedPackages) {
            return PolicyDecision(
                PolicyDecisionType.DENY,
                "Target node package '${targetPackage ?: "null"}' is not in the allowed package whitelist."
            )
        }
        return PolicyDecision(
            PolicyDecisionType.ALLOW,
            "Target node verified on whitelisted package '$targetPackage'."
        )
    }
}
