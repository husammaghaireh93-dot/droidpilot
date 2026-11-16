package com.mobilemcp.pro.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.gson.Gson
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface PolicyVaultBackend {
    fun readEncryptedPayload(): String?
    fun writeEncryptedPayload(plaintextJson: String)
    fun clear()
}

/**
 * Pure JVM AES/GCM/NoPadding vault backend for deterministic unit testing
 * without requiring Android Keystore hardware/system services.
 */
class InMemoryEncryptedPolicyVault : PolicyVaultBackend {
    private val secretKey: SecretKey = KeyGenerator.getInstance("AES").apply {
        init(256, SecureRandom())
    }.generateKey()

    private var encryptedBytes: ByteArray? = null
    private var ivBytes: ByteArray? = null

    @Synchronized
    override fun readEncryptedPayload(): String? {
        val cipherData = encryptedBytes ?: return null
        val iv = ivBytes ?: return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val plain = cipher.doFinal(cipherData)
        return String(plain, Charsets.UTF_8)
    }

    @Synchronized
    override fun writeEncryptedPayload(plaintextJson: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        ivBytes = cipher.iv
        encryptedBytes = cipher.doFinal(plaintextJson.toByteArray(Charsets.UTF_8))
    }

    @Synchronized
    override fun clear() {
        encryptedBytes = null
        ivBytes = null
    }
}

/**
 * Android Keystore-backed AES/GCM/NoPadding encrypted vault for dynamic package policies.
 */
class AndroidKeystorePolicyVault(context: Context) : PolicyVaultBackend {
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "droidpilot_dynamic_policy_key"
        private const val PREFS_NAME = "droidpilot_dynamic_policy_vault"
        private const val PREF_CIPHERTEXT = "enc_policy_data"
        private const val PREF_IV = "enc_policy_iv"
        private const val GCM_TAG_LENGTH = 128
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    init {
        ensureKeyExists()
    }

    private fun ensureKeyExists() {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }
    }

    private fun getSecretKey(): SecretKey {
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("Dynamic policy Keystore secret key entry missing")
        return entry.secretKey
    }

    @Synchronized
    override fun readEncryptedPayload(): String? {
        val encData = prefs.getString(PREF_CIPHERTEXT, null) ?: return null
        val ivData = prefs.getString(PREF_IV, null) ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = java.util.Base64.getDecoder().decode(ivData)
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), GCMParameterSpec(GCM_TAG_LENGTH, iv))
            val plainBytes = cipher.doFinal(java.util.Base64.getDecoder().decode(encData))
            String(plainBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    override fun writeEncryptedPayload(plaintextJson: String) {
        ensureKeyExists()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintextJson.toByteArray(Charsets.UTF_8))
        prefs.edit()
            .putString(PREF_CIPHERTEXT, java.util.Base64.getEncoder().encodeToString(encrypted))
            .putString(PREF_IV, java.util.Base64.getEncoder().encodeToString(iv))
            .apply()
    }

    @Synchronized
    override fun clear() {
        prefs.edit().remove(PREF_CIPHERTEXT).remove(PREF_IV).apply()
    }
}

data class DynamicPolicyConfig(
    val readOnlyPackages: Set<String> = emptySet(),
    val consentGatedPackages: Set<String> = emptySet()
)

sealed class PolicyUpdateResult {
    data class Success(val packageName: String, val tier: PackageTier) : PolicyUpdateResult()
    data class Rejected(val packageName: String, val reason: String) : PolicyUpdateResult()
}

/**
 * Encrypted storage and enforcement gate for user-managed dynamic package tiers.
 * Strictly refuses any TIER_0_HARD_DENY package both at write time and on load.
 */
class DynamicPolicyStore(
    private val backend: PolicyVaultBackend,
    private val policyEngine: PolicyEngine? = null
) {
    companion object {
        private val PACKAGE_NAME_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+$")

        fun createAndroid(context: Context, policyEngine: PolicyEngine? = null): DynamicPolicyStore {
            return DynamicPolicyStore(AndroidKeystorePolicyVault(context.applicationContext), policyEngine)
        }
    }

    private val gson = Gson()
    private var readOnlySet = mutableSetOf<String>()
    private var consentGatedSet = mutableSetOf<String>()

    init {
        reload()
    }

    @Synchronized
    fun reload(): DynamicPolicyConfig {
        val rawJson = backend.readEncryptedPayload()
        if (rawJson.isNullOrBlank()) {
            readOnlySet = mutableSetOf()
            consentGatedSet = mutableSetOf()
        } else {
            val parsed = try {
                gson.fromJson(rawJson, DynamicPolicyConfig::class.java)
            } catch (_: Exception) {
                null
            }
            val safeConsent = parsed?.consentGatedPackages
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() && !PolicyEngine.isHardDeniedPackage(it) }
                ?.toMutableSet()
                ?: mutableSetOf()

            val safeReadOnly = parsed?.readOnlyPackages
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() && !PolicyEngine.isHardDeniedPackage(it) && it !in safeConsent }
                ?.toMutableSet()
                ?: mutableSetOf()

            consentGatedSet = safeConsent
            readOnlySet = safeReadOnly
        }
        syncPolicyEngine()
        return DynamicPolicyConfig(readOnlySet.toSet(), consentGatedSet.toSet())
    }

    @Synchronized
    fun addPackage(packageName: String?, tier: PackageTier): PolicyUpdateResult {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty() || !PACKAGE_NAME_REGEX.matches(pkg)) {
            return PolicyUpdateResult.Rejected(
                pkg,
                "Invalid Android package name '$pkg'."
            )
        }
        if (tier == PackageTier.TIER_0_HARD_DENY) {
            return PolicyUpdateResult.Rejected(
                pkg,
                "Cannot dynamically add packages to TIER_0_HARD_DENY; use removePackage instead."
            )
        }
        if (PolicyEngine.isHardDeniedPackage(pkg)) {
            return PolicyUpdateResult.Rejected(
                pkg,
                "Package '$pkg' is permanently blocked by TIER_0_HARD_DENY and cannot be added to $tier."
            )
        }

        when (tier) {
            PackageTier.TIER_1_READ_ONLY -> {
                consentGatedSet.remove(pkg)
                readOnlySet.add(pkg)
            }
            PackageTier.TIER_2_CONSENT_GATED -> {
                readOnlySet.remove(pkg)
                consentGatedSet.add(pkg)
            }
            PackageTier.TIER_0_HARD_DENY -> Unit
        }

        persistLocked()
        syncPolicyEngine()
        return PolicyUpdateResult.Success(pkg, tier)
    }

    @Synchronized
    fun removePackage(packageName: String?): Boolean {
        val pkg = packageName?.trim().orEmpty()
        if (pkg.isEmpty()) return false
        val removedRead = readOnlySet.remove(pkg)
        val removedConsent = consentGatedSet.remove(pkg)
        if (removedRead || removedConsent) {
            persistLocked()
            syncPolicyEngine()
            return true
        }
        return false
    }

    @Synchronized
    fun getReadOnlyPackages(): Set<String> {
        return readOnlySet.filterNot { PolicyEngine.isHardDeniedPackage(it) }.toSet()
    }

    @Synchronized
    fun getConsentGatedPackages(): Set<String> {
        return consentGatedSet.filterNot { PolicyEngine.isHardDeniedPackage(it) }.toSet()
    }

    private fun persistLocked() {
        val config = DynamicPolicyConfig(
            readOnlyPackages = getReadOnlyPackages(),
            consentGatedPackages = getConsentGatedPackages()
        )
        backend.writeEncryptedPayload(gson.toJson(config))
    }

    private fun syncPolicyEngine() {
        policyEngine?.updateDynamicPackages(
            readOnly = getReadOnlyPackages(),
            consentGated = getConsentGatedPackages()
        )
    }
}
