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
import com.mobilemcp.pro.security.KeyStoreManager
import com.mobilemcp.pro.server.WebSocketCommandServer
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

        updateIPAddress()
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
