package com.mobilemcp.pro

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.mobilemcp.pro.databinding.ActivityMainBinding
import com.mobilemcp.pro.security.DynamicPolicyStore
import com.mobilemcp.pro.security.KeyStoreManager
import com.mobilemcp.pro.security.PackageTier
import com.mobilemcp.pro.security.PolicyUpdateResult
import com.mobilemcp.pro.server.WebSocketCommandServer
import com.mobilemcp.pro.service.AuditLogger
import com.mobilemcp.pro.service.ConnectionForegroundService
import com.mobilemcp.pro.service.MobileAccessibilityService
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var wsServer: WebSocketCommandServer? = null
    private var isServerRunning = false
    private val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
    private val keyStoreManager: KeyStoreManager by lazy { KeyStoreManager(applicationContext) }
    private val dynamicPolicyStore: DynamicPolicyStore by lazy { DynamicPolicyStore.createAndroid(applicationContext) }
    private val auditLogger: AuditLogger by lazy { AuditLogger(applicationContext.filesDir) }

    private val createAuditExportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri == null) {
            appendLog("Audit export cancelled.")
            return@registerForActivityResult
        }
        try {
            val bundleJson = MobileAccessibilityService.instance?.exportAuditBundleJson()
                ?: auditLogger.exportSignedAuditBundle()
            contentResolver.openOutputStream(uri)?.use { stream ->
                stream.write(bundleJson.toByteArray(Charsets.UTF_8))
            } ?: throw IllegalStateException("Unable to open destination document stream")

            val verification = AuditLogger.verifyExportedBundleDetailed(bundleJson)
            appendLog("Audit bundle exported (${verification.entryCount} entries, verified=${verification.valid}).")
            Toast.makeText(
                this,
                "Audit exported (${verification.entryCount} entries, valid=${verification.valid})",
                Toast.LENGTH_SHORT
            ).show()
        } catch (e: Exception) {
            appendLog("Audit export failed: ${e.message}")
            Toast.makeText(this, "Audit export failed", Toast.LENGTH_SHORT).show()
        }
    }

    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            appendLog("Notification permission granted (required for consent prompts).")
        } else {
            appendLog("WARNING: Notification permission denied; all actions will default-deny.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupUI()
        updateAccessibilityStatus()
        ensureNotificationPermission()
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateAccessibilityStatus()
        updateIPAddress()
    }

    private fun setupUI() {
        binding.btnToggleServer.setOnClickListener {
            if (isServerRunning) stopServer() else startServer()
        }

        binding.btnOpenAccessibility.setOnClickListener {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }

        binding.tvIpAddress.setOnClickListener {
            copyAuthTokenSafely()
        }

        binding.btnRotateToken.setOnClickListener {
            rotateAuthTokenSafely()
        }

        binding.btnExportAudit.setOnClickListener {
            createAuditExportLauncher.launch("droidpilot-audit-bundle.json")
        }

        binding.btnAddTier1.setOnClickListener {
            handleAddDynamicPolicy(PackageTier.TIER_1_READ_ONLY)
        }

        binding.btnAddTier2.setOnClickListener {
            handleAddDynamicPolicy(PackageTier.TIER_2_CONSENT_GATED)
        }

        binding.btnRemovePolicy.setOnClickListener {
            handleRemoveDynamicPolicy()
        }

        updateIPAddress()
        refreshPolicyStatusDisplay()
    }

    private fun rotateAuthTokenSafely() {
        try {
            val newToken = keyStoreManager.rotateAuthToken()
            wsServer?.rotateAuthToken(newToken)
            appendLog("Auth token rotated safely; all active WebSocket sessions disconnected (4001).")
            Toast.makeText(this, "Auth token rotated (sessions closed)", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            appendLog("Failed to rotate auth token: ${e.message}")
        }
    }

    private fun handleAddDynamicPolicy(tier: PackageTier) {
        val pkg = binding.etPolicyPackage.text?.toString()?.trim().orEmpty()
        when (val result = dynamicPolicyStore.addPackage(pkg, tier)) {
            is PolicyUpdateResult.Success -> {
                MobileAccessibilityService.instance?.reloadDynamicPolicies()
                binding.etPolicyPackage.setText("")
                val msg = "Added ${result.packageName} -> ${result.tier}"
                refreshPolicyStatusDisplay(msg)
                appendLog(msg)
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            }
            is PolicyUpdateResult.Rejected -> {
                refreshPolicyStatusDisplay("DENIED: ${result.reason}")
                appendLog("POLICY REJECTED: ${result.reason}")
                Toast.makeText(this, result.reason, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun handleRemoveDynamicPolicy() {
        val pkg = binding.etPolicyPackage.text?.toString()?.trim().orEmpty()
        if (pkg.isEmpty()) {
            refreshPolicyStatusDisplay("Enter a package name to remove.")
            return
        }
        val removed = dynamicPolicyStore.removePackage(pkg)
        MobileAccessibilityService.instance?.reloadDynamicPolicies()
        val msg = if (removed) {
            binding.etPolicyPackage.setText("")
            "Removed $pkg from dynamic tiers."
        } else {
            "Package $pkg not present in dynamic tiers."
        }
        refreshPolicyStatusDisplay(msg)
        appendLog(msg)
    }

    private fun refreshPolicyStatusDisplay(feedback: String? = null) {
        val t1 = dynamicPolicyStore.getReadOnlyPackages().sorted()
        val t2 = dynamicPolicyStore.getConsentGatedPackages().sorted()
        val sb = StringBuilder()
        if (!feedback.isNullOrBlank()) {
            sb.append(feedback).append('\n')
        }
        sb.append("TIER_1 (Read-Only): ").append(if (t1.isEmpty()) "none" else t1.joinToString(", ")).append('\n')
        sb.append("TIER_2 (Consent-Gated): ").append(if (t2.isEmpty()) "none" else t2.joinToString(", "))
        binding.tvPolicyStatus.text = sb.toString()
    }

    private fun copyAuthTokenSafely() {
        try {
            val token = keyStoreManager.getOrCreateAuthToken()
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("DroidPilot Auth Token", token).apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    description.extras = PersistableBundle().apply {
                        putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                    }
                }
            }
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Auth token copied to clipboard (masked)", Toast.LENGTH_SHORT).show()
            appendLog("Auth token copied to clipboard.")
        } catch (e: Exception) {
            appendLog("Failed to copy auth token: ${e.message}")
        }
    }

    private fun startServer() {
        if (!MobileAccessibilityService.isRunning) {
            appendLog("ERROR: Accessibility service is not enabled!")
            appendLog("Please enable 'Mobile MCP Pro' in Accessibility Settings")
            return
        }

        ensureNotificationPermission()
        val port = binding.etPort.text.toString().toIntOrNull() ?: 8765

        try {
            val authToken = keyStoreManager.getOrCreateAuthToken()
            wsServer = WebSocketCommandServer(
                port = port,
                onLog = { message -> runOnUiThread { appendLog(message) } },
                onConnectionChange = { count ->
                    runOnUiThread { binding.tvConnections.text = count.toString() }
                }
            ).apply {
                this.authToken = authToken
            }
            wsServer?.start()

            // Start foreground service to keep alive
            val serviceIntent = Intent(this, ConnectionForegroundService::class.java).apply {
                putExtra(ConnectionForegroundService.EXTRA_PORT, port)
            }
            startForegroundService(serviceIntent)

            isServerRunning = true
            updateServerUI()
            appendLog("Server started on 127.0.0.1:$port (auth enabled)")

        } catch (e: Exception) {
            appendLog("Failed to start server: ${e.message}")
        }
    }

    private fun stopServer() {
        try {
            wsServer?.shutdown()
            wsServer = null

            stopService(Intent(this, ConnectionForegroundService::class.java))

            isServerRunning = false
            updateServerUI()
            appendLog("Server stopped")

        } catch (e: Exception) {
            appendLog("Error stopping server: ${e.message}")
        }
    }

    private fun updateServerUI() {
        if (isServerRunning) {
            binding.btnToggleServer.text = getString(R.string.btn_stop_server)
            binding.tvStatus.text = getString(R.string.status_waiting)
            setStatusColor(R.color.status_waiting)
            binding.etPort.isEnabled = false
        } else {
            binding.btnToggleServer.text = getString(R.string.btn_start_server)
            binding.tvStatus.text = getString(R.string.status_disconnected)
            setStatusColor(R.color.status_disconnected)
            binding.tvConnections.text = "0"
            binding.etPort.isEnabled = true
        }
    }

    private fun updateAccessibilityStatus() {
        val isEnabled = isAccessibilityServiceEnabled()
        val indicator = binding.accessibilityIndicator.background as? GradientDrawable
            ?: GradientDrawable().also { binding.accessibilityIndicator.background = it }

        if (isEnabled) {
            indicator.setColor(ContextCompat.getColor(this, R.color.status_connected))
            binding.tvAccessibilityStatus.text = "Accessibility Service: ON"
        } else {
            indicator.setColor(ContextCompat.getColor(this, R.color.status_disconnected))
            binding.tvAccessibilityStatus.text = "Accessibility Service: OFF"
        }
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val am = getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(
            AccessibilityServiceInfo.FEEDBACK_GENERIC
        )
        return enabledServices.any {
            it.resolveInfo.serviceInfo.packageName == packageName
        }
    }

    private fun setStatusColor(colorRes: Int) {
        val color = ContextCompat.getColor(this, colorRes)
        val indicator = binding.statusIndicator.background as? GradientDrawable
            ?: GradientDrawable().also {
                it.shape = GradientDrawable.OVAL
                binding.statusIndicator.background = it
            }
        indicator.setColor(color)
    }

    private fun updateIPAddress() {
        binding.tvIpAddress.text = "Bound to: 127.0.0.1 (Loopback)\n[Tap to Copy Token Safely]"
    }

    private fun appendLog(message: String) {
        val timestamp = dateFormat.format(Date())
        val logLine = "[$timestamp] $message\n"
        binding.tvLog.append(logLine)

        // Auto-scroll
        binding.logScrollView.post {
            binding.logScrollView.fullScroll(android.view.View.FOCUS_DOWN)
        }

        // Keep log size reasonable
        val text = binding.tvLog.text.toString()
        if (text.length > 10000) {
            binding.tvLog.text = text.substring(text.length - 5000)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isServerRunning) {
            stopServer()
        }
    }
}
