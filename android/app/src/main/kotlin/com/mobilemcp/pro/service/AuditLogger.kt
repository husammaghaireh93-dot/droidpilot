package com.mobilemcp.pro.service

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

data class AuditRecord(
    val index: Long,
    val timestamp: String,
    val action: String,
    val targetPackage: String,
    val targetElement: String?,
    val consent: String,
    val status: String,
    val previousHash: String,
    var recordHash: String = ""
)

data class ExportedAuditEntry(
    val index: Long,
    val timestamp: String,
    val action: String,
    val targetPackage: String,
    val targetElement: String?,
    val consent: String,
    val status: String,
    val prevHash: String,
    val hash: String
)

data class AuditBundleSummary(
    val chainValid: Boolean,
    val entryCount: Int,
    val firstHash: String,
    val lastHash: String,
    val exportedAtEpochMs: Long
)

data class AuditExportBundle(
    val version: Int = 1,
    val chainValid: Boolean,
    val entryCount: Int,
    val firstHash: String,
    val lastHash: String,
    val exportedAtEpochMs: Long,
    val summary: AuditBundleSummary,
    val entries: List<ExportedAuditEntry>,
    val bundleDigestSha256: String
)

data class BundleVerificationResult(
    val valid: Boolean,
    val reason: String,
    val entryCount: Int
)

/**
 * Hash-chained append-only audit logger stored in a private directory.
 * Supports exporting a self-verifying JSON audit bundle and independently verifying
 * exported bundles against tampering, truncation, or entry deletion.
 */
class AuditLogger(private val storageDir: File) {

    companion object {
        const val GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

        fun calculateHash(record: AuditRecord): String {
            val raw = "${record.index}|${record.timestamp}|${record.action}|${record.targetPackage}|" +
                "${record.targetElement ?: ""}|${record.consent}|${record.status}|${record.previousHash}"
            return sha256Hex(raw)
        }

        private fun sha256Hex(input: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }

        fun calculateBundleDigest(
            version: Int,
            chainValid: Boolean,
            entryCount: Int,
            firstHash: String,
            lastHash: String,
            exportedAtEpochMs: Long,
            entries: List<ExportedAuditEntry>
        ): String {
            val sb = StringBuilder()
            sb.append(version).append('|')
                .append(chainValid).append('|')
                .append(entryCount).append('|')
                .append(firstHash).append('|')
                .append(lastHash).append('|')
                .append(exportedAtEpochMs)
            for (entry in entries) {
                sb.append('\n')
                    .append(entry.index).append('|')
                    .append(entry.timestamp).append('|')
                    .append(entry.action).append('|')
                    .append(entry.targetPackage).append('|')
                    .append(entry.targetElement ?: "").append('|')
                    .append(entry.consent).append('|')
                    .append(entry.status).append('|')
                    .append(entry.prevHash).append('|')
                    .append(entry.hash)
            }
            return sha256Hex(sb.toString())
        }

        fun verifyChainIntegrity(lines: List<String>): Boolean {
            val gson = Gson()
            var expectedPrev = GENESIS_HASH
            for (line in lines) {
                if (line.isBlank()) continue
                val record = try {
                    gson.fromJson(line, AuditRecord::class.java)
                } catch (_: Exception) {
                    return false
                } ?: return false
                if (record.previousHash != expectedPrev) return false
                if (calculateHash(record) != record.recordHash) return false
                expectedPrev = record.recordHash
            }
            return true
        }

        fun verifyExportedBundle(bundleJson: String): Boolean {
            return verifyExportedBundleDetailed(bundleJson).valid
        }

        fun verifyExportedBundleDetailed(bundleJson: String): BundleVerificationResult {
            if (bundleJson.isBlank()) {
                return BundleVerificationResult(false, "Exported audit bundle is empty.", 0)
            }
            val bundle = try {
                Gson().fromJson(bundleJson, AuditExportBundle::class.java)
            } catch (e: Exception) {
                return BundleVerificationResult(false, "Malformed audit bundle JSON: ${e.message}", 0)
            } ?: return BundleVerificationResult(false, "Null audit bundle.", 0)

            @Suppress("USELESS_ELVIS")
            val entries = bundle.entries ?: return BundleVerificationResult(false, "Missing entries array.", 0)
            @Suppress("USELESS_ELVIS")
            val summary = bundle.summary ?: return BundleVerificationResult(false, "Missing summary object.", entries.size)
            @Suppress("USELESS_ELVIS")
            val firstHash = bundle.firstHash ?: return BundleVerificationResult(false, "Missing firstHash.", entries.size)
            @Suppress("USELESS_ELVIS")
            val lastHash = bundle.lastHash ?: return BundleVerificationResult(false, "Missing lastHash.", entries.size)
            @Suppress("USELESS_ELVIS")
            val bundleDigest = bundle.bundleDigestSha256 ?: return BundleVerificationResult(false, "Missing bundleDigestSha256.", entries.size)

            if (!bundle.chainValid || !summary.chainValid) {
                return BundleVerificationResult(false, "Bundle reports chainValid=false.", entries.size)
            }
            if (bundle.entryCount != entries.size || summary.entryCount != entries.size) {
                return BundleVerificationResult(false, "entryCount mismatch against entries.size.", entries.size)
            }
            if (summary.firstHash != firstHash ||
                summary.lastHash != lastHash ||
                summary.exportedAtEpochMs != bundle.exportedAtEpochMs
            ) {
                return BundleVerificationResult(false, "Summary metadata does not match bundle header.", entries.size)
            }

            if (entries.isEmpty()) {
                if (firstHash != GENESIS_HASH || lastHash != GENESIS_HASH) {
                    return BundleVerificationResult(false, "Empty bundle must reference GENESIS_HASH.", 0)
                }
            } else {
                if (firstHash != entries.first().hash || lastHash != entries.last().hash) {
                    return BundleVerificationResult(false, "firstHash or lastHash does not match entries.", entries.size)
                }
                var expectedPrev = GENESIS_HASH
                for ((position, entry) in entries.withIndex()) {
                    @Suppress("USELESS_ELVIS")
                    if (entry.timestamp == null || entry.action == null || entry.targetPackage == null ||
                        entry.consent == null || entry.status == null || entry.prevHash == null || entry.hash == null
                    ) {
                        return BundleVerificationResult(false, "Entry $position has missing required fields.", entries.size)
                    }
                    if (entry.index != position.toLong()) {
                        return BundleVerificationResult(false, "Entry index gap or tampering at position $position.", entries.size)
                    }
                    if (entry.prevHash != expectedPrev) {
                        return BundleVerificationResult(false, "prevHash chain break at entry $position.", entries.size)
                    }
                    val reconstructed = AuditRecord(
                        index = entry.index,
                        timestamp = entry.timestamp,
                        action = entry.action,
                        targetPackage = entry.targetPackage,
                        targetElement = entry.targetElement,
                        consent = entry.consent,
                        status = entry.status,
                        previousHash = entry.prevHash,
                        recordHash = entry.hash
                    )
                    if (calculateHash(reconstructed) != entry.hash) {
                        return BundleVerificationResult(false, "Hash mismatch at entry $position.", entries.size)
                    }
                    expectedPrev = entry.hash
                }
            }

            val expectedBundleDigest = calculateBundleDigest(
                version = bundle.version,
                chainValid = bundle.chainValid,
                entryCount = bundle.entryCount,
                firstHash = firstHash,
                lastHash = lastHash,
                exportedAtEpochMs = bundle.exportedAtEpochMs,
                entries = entries
            )
            if (expectedBundleDigest != bundleDigest) {
                return BundleVerificationResult(false, "Bundle digest mismatch (tampered metadata or entries).", entries.size)
            }

            return BundleVerificationResult(true, "Audit bundle verified (${entries.size} entries).", entries.size)
        }
    }

    private val logFile: File by lazy {
        if (!storageDir.exists()) storageDir.mkdirs()
        File(storageDir, "audit_chain.jsonl")
    }
    private val gson = Gson()
    private val prettyGson = GsonBuilder().setPrettyPrinting().create()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    private var lastHash: String = GENESIS_HASH
    private var currentIndex: Long = 0

    init {
        initializeChainState()
    }

    @Synchronized
    private fun initializeChainState() {
        if (logFile.exists() && logFile.length() > 0) {
            logFile.useLines { lines ->
                lines.filter { it.isNotBlank() }.forEach { line ->
                    try {
                        val record = gson.fromJson(line, AuditRecord::class.java)
                        if (record != null) {
                            lastHash = record.recordHash
                            currentIndex = record.index + 1
                        }
                    } catch (_: Exception) {}
                }
            }
        }
    }

    @Synchronized
    fun record(
        action: String,
        targetPackage: String,
        targetElement: String?,
        consent: String,
        status: String
    ): AuditRecord {
        val timestamp = dateFormat.format(Date())
        val record = AuditRecord(
            index = currentIndex++,
            timestamp = timestamp,
            action = action,
            targetPackage = targetPackage,
            targetElement = targetElement,
            consent = consent,
            status = status,
            previousHash = lastHash
        )
        record.recordHash = calculateHash(record)
        lastHash = record.recordHash

        logFile.appendText(gson.toJson(record) + "\n")
        return record
    }

    @Synchronized
    fun getLogLines(): List<String> {
        return if (logFile.exists()) logFile.readLines() else emptyList()
    }

    @Synchronized
    fun exportSignedAuditBundle(clock: () -> Long = System::currentTimeMillis): String {
        val lines = getLogLines().filter { it.isNotBlank() }
        val entries = mutableListOf<ExportedAuditEntry>()
        var expectedPrev = GENESIS_HASH
        var chainValid = true

        for ((position, line) in lines.withIndex()) {
            val record = try {
                gson.fromJson(line, AuditRecord::class.java)
            } catch (_: Exception) {
                null
            }
            if (record == null) {
                chainValid = false
                continue
            }
            if (record.index != position.toLong() ||
                record.previousHash != expectedPrev ||
                calculateHash(record) != record.recordHash
            ) {
                chainValid = false
            }
            expectedPrev = record.recordHash
            entries.add(
                ExportedAuditEntry(
                    index = record.index,
                    timestamp = record.timestamp,
                    action = record.action,
                    targetPackage = record.targetPackage,
                    targetElement = record.targetElement,
                    consent = record.consent,
                    status = record.status,
                    prevHash = record.previousHash,
                    hash = record.recordHash
                )
            )
        }

        val entryCount = entries.size
        val firstHash = if (entries.isNotEmpty()) entries.first().hash else GENESIS_HASH
        val lastEntryHash = if (entries.isNotEmpty()) entries.last().hash else GENESIS_HASH
        val exportedAt = clock()

        val summary = AuditBundleSummary(
            chainValid = chainValid,
            entryCount = entryCount,
            firstHash = firstHash,
            lastHash = lastEntryHash,
            exportedAtEpochMs = exportedAt
        )
        val digest = calculateBundleDigest(
            version = 1,
            chainValid = chainValid,
            entryCount = entryCount,
            firstHash = firstHash,
            lastHash = lastEntryHash,
            exportedAtEpochMs = exportedAt,
            entries = entries
        )

        val bundle = AuditExportBundle(
            version = 1,
            chainValid = chainValid,
            entryCount = entryCount,
            firstHash = firstHash,
            lastHash = lastEntryHash,
            exportedAtEpochMs = exportedAt,
            summary = summary,
            entries = entries,
            bundleDigestSha256 = digest
        )
        return prettyGson.toJson(bundle)
    }
}
