package com.mobilemcp.pro.service

import com.google.gson.Gson
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

/**
 * Hash-chained append-only audit logger stored in a private directory.
 * Note: Hash chaining detects tampering or line modification/deletion,
 * though uninstalling the app or clearing app data deletes the file itself.
 */
class AuditLogger(private val storageDir: File) {

    companion object {
        const val GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

        fun calculateHash(record: AuditRecord): String {
            val raw = "${record.index}|${record.timestamp}|${record.action}|${record.targetPackage}|" +
                "${record.targetElement ?: ""}|${record.consent}|${record.status}|${record.previousHash}"
            val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
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
    }

    private val logFile: File by lazy {
        if (!storageDir.exists()) storageDir.mkdirs()
        File(storageDir, "audit_chain.jsonl")
    }
    private val gson = Gson()
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

    fun getLogLines(): List<String> {
        return if (logFile.exists()) logFile.readLines() else emptyList()
    }
}
