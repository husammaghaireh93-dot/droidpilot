package com.mobilemcp.pro.service

import android.Manifest
import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Path
import android.os.Build
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.mobilemcp.pro.model.CommandRequest
import com.mobilemcp.pro.model.CommandResponse
import com.mobilemcp.pro.model.UINode
import com.mobilemcp.pro.security.ConsentCoordinator
import com.mobilemcp.pro.security.NodeSanitizer
import com.mobilemcp.pro.security.PolicyDecisionType
import com.mobilemcp.pro.security.PolicyEngine
import com.mobilemcp.pro.server.WebSocketCommandServer
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class MobileAccessibilityService : AccessibilityService() {

    companion object {
        private const val TAG = "MobileAccessibility"
        private const val CONSENT_CHANNEL_ID = "droidpilot_consent_channel"
        var instance: MobileAccessibilityService? = null
            private set
        var isRunning = false
            private set
    }

    private val gson = Gson()
    private val serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val policyEngine = PolicyEngine()
    private val auditLogger: AuditLogger by lazy { AuditLogger(filesDir) }
    private val consentCoordinator: ConsentCoordinator by lazy {
        ConsentCoordinator(
            onCooldownTriggered = { cooldownUntilMs ->
                auditLogger.record(
                    action = "consent_rate_limiter",
                    targetPackage = "system",
                    targetElement = null,
                    consent = "cooldown",
                    status = "cooldown_activated_60s(until=$cooldownUntilMs)"
                )
            }
        )
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        isRunning = true
        ensureConsentNotificationChannel()
        Log.i(TAG, "Accessibility service connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // Events are not actively processed; UI tree is fetched on demand
    }

    override fun onInterrupt() {
        Log.w(TAG, "Accessibility service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        consentCoordinator.cancelActive()
        instance = null
        isRunning = false
        serviceScope.cancel()
        Log.i(TAG, "Accessibility service destroyed")
    }

    fun resolveConsent(nonce: String?, approved: Boolean) {
        consentCoordinator.submitDecision(nonce, approved)
    }

    private fun ensureConsentNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CONSENT_CHANNEL_ID,
                "Action Approval Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Requires explicit user confirmation before executing UI actions"
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
    }

    private fun areNotificationsEnabled(): Boolean {
        if (!NotificationManagerCompat.from(this).areNotificationsEnabled()) {
            return false
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    /**
     * Requests explicit user approval via a high-priority notification backed by an internal
     * (non-exported) BroadcastReceiver and a single-use 128-bit cryptographic nonce.
     * Note: WebSocketCommandServer invokes handleCommand on its background worker pool,
     * never blocking the Android Main thread where ConsentReceiver.onReceive runs.
     */
    private fun requestUserConsent(
        action: String,
        targetPackage: String,
        targetElement: String,
        description: String
    ): Pair<Boolean, String> {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            val reason = "Refusing to block Main thread for interactive consent."
            auditLogger.record(action, targetPackage, targetElement, "denied", reason)
            return Pair(false, reason)
        }

        val startResult = consentCoordinator.startConsent(areNotificationsEnabled())
        if (startResult is ConsentCoordinator.StartResult.Denied) {
            val consentTag = when {
                startResult.cooldownActive -> "cooldown_active"
                startResult.rateLimited -> "rate_limited"
                else -> "denied"
            }
            auditLogger.record(action, targetPackage, targetElement, consentTag, startResult.reason)
            return Pair(false, startResult.reason)
        }

        val session = (startResult as ConsentCoordinator.StartResult.Started).session
        val notificationId = session.nonce.hashCode()

        val approveIntent = Intent(this, ConsentReceiver::class.java).apply {
            this.action = ConsentReceiver.ACTION_CONSENT_DECISION
            setPackage(packageName)
            putExtra(ConsentReceiver.EXTRA_NONCE, session.nonce)
            putExtra(ConsentReceiver.EXTRA_APPROVED, true)
        }
        val denyIntent = Intent(this, ConsentReceiver::class.java).apply {
            this.action = ConsentReceiver.ACTION_CONSENT_DECISION
            setPackage(packageName)
            putExtra(ConsentReceiver.EXTRA_NONCE, session.nonce)
            putExtra(ConsentReceiver.EXTRA_APPROVED, false)
        }

        val approvePending = PendingIntent.getBroadcast(
            this,
            notificationId * 31 + 1,
            approveIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val denyPending = PendingIntent.getBroadcast(
            this,
            notificationId * 31 + 2,
            denyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CONSENT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Approve agent action?")
            .setContentText(description)
            .setStyle(NotificationCompat.BigTextStyle().bigText(description))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setAutoCancel(true)
            .setTimeoutAfter(ConsentCoordinator.DEFAULT_TIMEOUT_MS)
            .setDeleteIntent(denyPending)
            .addAction(0, "Approve", approvePending)
            .addAction(0, "Deny", denyPending)
            .build()

        NotificationManagerCompat.from(this).notify(notificationId, notification)

        val approved = try {
            consentCoordinator.awaitResult(session)
        } finally {
            NotificationManagerCompat.from(this).cancel(notificationId)
        }

        return if (approved) {
            Pair(true, "approved")
        } else {
            val reason = "User denied or consent timed out (default-deny)."
            auditLogger.record(action, targetPackage, targetElement, "denied_or_timeout", reason)
            Pair(false, reason)
        }
    }

    /**
     * Dispatches incoming WebSocket commands through strict PolicyEngine default-deny allowlist.
     * Executed on WebSocketCommandServer's worker thread pool (Executors.newFixedThreadPool(4)).
     */
    fun handleCommand(request: CommandRequest): CommandResponse {
        return try {
            val root = rootInActiveWindow
            val currentPackage = root?.packageName?.toString()
            root?.recycle()

            val decision = policyEngine.evaluate(request.command, currentPackage)
            if (decision.type == PolicyDecisionType.DENY) {
                auditLogger.record(
                    action = request.command ?: "unknown",
                    targetPackage = currentPackage ?: "none",
                    targetElement = null,
                    consent = "n/a",
                    status = "denied: ${decision.reason}"
                )
                return CommandResponse.error(request.id, decision.reason)
            }

            when (request.command) {
                "get_ui_tree" -> executeGetUITree(request.params, currentPackage!!)
                "click_element" -> executeClickElement(request.params, currentPackage!!)
                "type_text" -> executeTypeText(request.params, currentPackage!!)
                else -> {
                    val reason = "Command '${request.command}' denied by default-deny policy."
                    auditLogger.record(
                        action = request.command ?: "unknown",
                        targetPackage = currentPackage ?: "none",
                        targetElement = null,
                        consent = "n/a",
                        status = "denied: $reason"
                    )
                    CommandResponse.error(request.id, reason)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error handling command ${request.command}", e)
            CommandResponse.error(request.id, "Error: ${e.message}")
        }
    }

    // --- Gesture Commands ---

    private fun executeTap(params: JsonObject?): CommandResponse {
        val x = params?.get("x")?.asFloat ?: return CommandResponse.error(null, "Missing x")
        val y = params.get("y")?.asFloat ?: return CommandResponse.error(null, "Missing y")
        val duration = params.get("duration")?.asLong ?: 100L

        val path = Path().apply { moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, duration)
        val gesture = GestureDescription.Builder().addStroke(stroke).build()

        return dispatchGestureSync(gesture, "tap($x, $y)")
    }

    private fun executeLongPress(params: JsonObject?): CommandResponse {
        val x = params?.get("x")?.asFloat ?: return CommandResponse.error(null, "Missing x")
        val y = params.get("y")?.asFloat ?: return CommandResponse.error(null, "Missing y")
        val duration = params.get("duration")?.asLong ?: 1000L

        val path = Path().apply { moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, duration)
        val gesture = GestureDescription.Builder().addStroke(stroke).build()

        return dispatchGestureSync(gesture, "longPress($x, $y)")
    }

    private fun executeSwipe(params: JsonObject?): CommandResponse {
        val startX = params?.get("startX")?.asFloat ?: return CommandResponse.error(null, "Missing startX")
        val startY = params.get("startY")?.asFloat ?: return CommandResponse.error(null, "Missing startY")
        val endX = params.get("endX")?.asFloat ?: return CommandResponse.error(null, "Missing endX")
        val endY = params.get("endY")?.asFloat ?: return CommandResponse.error(null, "Missing endY")
        val duration = params.get("duration")?.asLong ?: 300L

        val path = Path().apply {
            moveTo(startX, startY)
            lineTo(endX, endY)
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, duration)
        val gesture = GestureDescription.Builder().addStroke(stroke).build()

        return dispatchGestureSync(gesture, "swipe($startX,$startY -> $endX,$endY)")
    }

    private fun executeScroll(params: JsonObject?): CommandResponse {
        val direction = params?.get("direction")?.asString ?: "down"
        val amount = params?.get("amount")?.asFloat ?: 500f

        val displayMetrics = resources.displayMetrics
        val centerX = displayMetrics.widthPixels / 2f
        val centerY = displayMetrics.heightPixels / 2f

        val (startX, startY, endX, endY) = when (direction) {
            "up" -> listOf(centerX, centerY - amount / 2, centerX, centerY + amount / 2)
            "down" -> listOf(centerX, centerY + amount / 2, centerX, centerY - amount / 2)
            "left" -> listOf(centerX - amount / 2, centerY, centerX + amount / 2, centerY)
            "right" -> listOf(centerX + amount / 2, centerY, centerX - amount / 2, centerY)
            else -> return CommandResponse.error(null, "Invalid direction: $direction")
        }

        val path = Path().apply {
            moveTo(startX, startY)
            lineTo(endX, endY)
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, 400)
        val gesture = GestureDescription.Builder().addStroke(stroke).build()

        return dispatchGestureSync(gesture, "scroll($direction)")
    }

    private fun executePinch(params: JsonObject?): CommandResponse {
        val centerX = params?.get("x")?.asFloat ?: (resources.displayMetrics.widthPixels / 2f)
        val centerY = params?.get("y")?.asFloat ?: (resources.displayMetrics.heightPixels / 2f)
        val scale = params?.get("scale")?.asFloat ?: 1.5f // >1 = zoom in, <1 = zoom out
        val duration = params?.get("duration")?.asLong ?: 400L

        val startDist = 100f
        val endDist = startDist * scale

        val path1 = Path().apply {
            moveTo(centerX - startDist, centerY)
            lineTo(centerX - endDist, centerY)
        }
        val path2 = Path().apply {
            moveTo(centerX + startDist, centerY)
            lineTo(centerX + endDist, centerY)
        }

        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path1, 0, duration))
            .addStroke(GestureDescription.StrokeDescription(path2, 0, duration))
            .build()

        return dispatchGestureSync(gesture, "pinch(scale=$scale)")
    }

    private fun dispatchGestureSync(gesture: GestureDescription, label: String): CommandResponse {
        val latch = CountDownLatch(1)
        var success = false

        dispatchGesture(gesture, object : GestureResultCallback() {
            override fun onCompleted(gestureDescription: GestureDescription?) {
                success = true
                latch.countDown()
            }

            override fun onCancelled(gestureDescription: GestureDescription?) {
                success = false
                latch.countDown()
            }
        }, null)

        latch.await(5, TimeUnit.SECONDS)
        return if (success) {
            CommandResponse.success(null, JsonObject().apply { addProperty("action", label) })
        } else {
            CommandResponse.error(null, "Gesture $label failed or timed out")
        }
    }

    // --- Text Commands ---

    private fun executeTypeText(params: JsonObject?, currentPackage: String): CommandResponse {
        val text = params?.get("text")?.asString ?: return CommandResponse.error(null, "Missing text")
        val preFocused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
            ?: return CommandResponse.error(null, "No focused input field")

        val preIsPassword = preFocused.isPassword
        val prePkg = preFocused.packageName?.toString()
        val preRefreshed = preFocused.refresh()
        preFocused.recycle()

        if (preIsPassword) {
            auditLogger.record("type_text", currentPackage, "password_field", "n/a", "denied: password field protected")
            return CommandResponse.error(null, "Typing into password fields is blocked")
        }
        val prePkgCheck = policyEngine.verifyTargetNodePackage(prePkg, preRefreshed, "type_text")
        if (prePkgCheck.type == PolicyDecisionType.DENY) {
            auditLogger.record("type_text", prePkg ?: currentPackage, "focused_input", "n/a", "denied: ${prePkgCheck.reason}")
            return CommandResponse.error(null, prePkgCheck.reason)
        }

        val (approved, consentReason) = requestUserConsent(
            action = "type_text",
            targetPackage = currentPackage,
            targetElement = "focused_input(${text.length} chars)",
            description = "Type ${text.length} char(s) into focused field in $currentPackage"
        )
        if (!approved) {
            return CommandResponse.error(null, consentReason)
        }

        // Re-check active foreground window package AFTER consent approval and BEFORE execution
        val postRoot = rootInActiveWindow ?: run {
            auditLogger.record("type_text", currentPackage, "focused_input", "approved", "denied: no active window after consent")
            return CommandResponse.error(null, "No active window after consent")
        }
        val postPackage = postRoot.packageName?.toString()
        val postRootRefreshed = postRoot.refresh()
        postRoot.recycle()

        val windowCheck = policyEngine.verifyPostConsentContext(
            consentedPackage = currentPackage,
            currentPackage = postPackage,
            targetPackage = postPackage,
            refreshed = postRootRefreshed
        )
        if (windowCheck.type == PolicyDecisionType.DENY) {
            auditLogger.record("type_text", postPackage ?: "none", "focused_input", "approved", "denied: ${windowCheck.reason}")
            return CommandResponse.error(null, windowCheck.reason)
        }

        val focused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: run {
            auditLogger.record("type_text", postPackage!!, "focused_input", "approved", "denied: no focused input after consent")
            return CommandResponse.error(null, "No focused input field")
        }

        val refreshed = focused.refresh()
        val targetPackage = focused.packageName?.toString()
        val focusedIsPassword = focused.isPassword
        val targetCheck = policyEngine.verifyPostConsentContext(
            consentedPackage = currentPackage,
            currentPackage = postPackage,
            targetPackage = targetPackage,
            refreshed = refreshed
        )
        if (targetCheck.type == PolicyDecisionType.DENY || focusedIsPassword) {
            focused.recycle()
            val reason = if (focusedIsPassword) "Typing into password fields is blocked" else targetCheck.reason
            auditLogger.record("type_text", targetPackage ?: postPackage!!, "focused_input", "approved", "denied: $reason")
            return CommandResponse.error(null, reason)
        }

        val args = android.os.Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                (focused.text?.toString() ?: "") + text)
        }
        val result = focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        focused.recycle()

        return if (result) {
            auditLogger.record("type_text", targetPackage!!, "focused_input(${text.length} chars)", "approved", "executed")
            CommandResponse.success(null, JsonObject().apply { addProperty("typed_length", text.length) })
        } else {
            auditLogger.record("type_text", targetPackage!!, "focused_input(${text.length} chars)", "approved", "failed")
            CommandResponse.error(null, "Failed to type text")
        }
    }

    private fun executeSetText(params: JsonObject?): CommandResponse {
        val text = params?.get("text")?.asString ?: return CommandResponse.error(null, "Missing text")
        val focused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
            ?: return CommandResponse.error(null, "No focused input field")

        val args = android.os.Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, text)
        }
        val result = focused.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
        focused.recycle()

        return if (result) {
            CommandResponse.success(null, JsonObject().apply { addProperty("text_set", text) })
        } else {
            CommandResponse.error(null, "Failed to set text")
        }
    }

    // --- Key Commands ---

    private fun executePressKey(params: JsonObject?): CommandResponse {
        val key = params?.get("key")?.asString ?: return CommandResponse.error(null, "Missing key")
        val action = when (key.lowercase()) {
            "back" -> GLOBAL_ACTION_BACK
            "home" -> GLOBAL_ACTION_HOME
            "recents", "recent" -> GLOBAL_ACTION_RECENTS
            "notifications" -> GLOBAL_ACTION_NOTIFICATIONS
            "quick_settings" -> GLOBAL_ACTION_QUICK_SETTINGS
            "power_dialog" -> GLOBAL_ACTION_POWER_DIALOG
            "split_screen" -> GLOBAL_ACTION_TOGGLE_SPLIT_SCREEN
            "lock_screen" -> if (Build.VERSION.SDK_INT >= 28) GLOBAL_ACTION_LOCK_SCREEN else
                return CommandResponse.error(null, "lock_screen requires API 28+")
            "take_screenshot" -> if (Build.VERSION.SDK_INT >= 28) GLOBAL_ACTION_TAKE_SCREENSHOT else
                return CommandResponse.error(null, "take_screenshot requires API 28+")
            else -> return CommandResponse.error(null, "Unknown key: $key")
        }

        val result = performGlobalAction(action)
        return if (result) {
            CommandResponse.success(null, JsonObject().apply { addProperty("key", key) })
        } else {
            CommandResponse.error(null, "Failed to press key: $key")
        }
    }

    // --- UI Tree Commands ---

    private fun executeGetUITree(params: JsonObject?, currentPackage: String): CommandResponse {
        val maxDepth = params?.get("maxDepth")?.asInt ?: 15
        val root = rootInActiveWindow ?: return CommandResponse.error(null, "No active window")

        val refreshed = root.refresh()
        val rootPkg = root.packageName?.toString()
        val pkgCheck = policyEngine.verifyTargetNodePackage(rootPkg, refreshed, "get_ui_tree")
        if (pkgCheck.type == PolicyDecisionType.DENY) {
            root.recycle()
            auditLogger.record("get_ui_tree", rootPkg ?: currentPackage, null, "not_required", "denied: ${pkgCheck.reason}")
            return CommandResponse.error(null, pkgCheck.reason)
        }

        val tree = buildUITree(root, 0, maxDepth)
        root.recycle()

        auditLogger.record("get_ui_tree", rootPkg!!, null, "not_required", "executed")
        val json = gson.toJsonTree(tree)
        return CommandResponse.success(null, JsonObject().apply { add("tree", json) })
    }

    private fun executeFindElement(params: JsonObject?): CommandResponse {
        val root = rootInActiveWindow ?: return CommandResponse.error(null, "No active window")

        val results = mutableListOf<UINode>()
        val text = params?.get("text")?.asString
        val id = params?.get("id")?.asString
        val className = params?.get("className")?.asString
        val contentDesc = params?.get("contentDescription")?.asString
        val maxResults = params?.get("maxResults")?.asInt ?: 10

        findElements(root, text, id, className, contentDesc, results, maxResults)
        root.recycle()

        val json = gson.toJsonTree(results)
        return CommandResponse.success(null, JsonObject().apply {
            add("elements", json)
            addProperty("count", results.size)
        })
    }

    private fun executeClickElement(params: JsonObject?, currentPackage: String): CommandResponse {
        val preRoot = rootInActiveWindow ?: return CommandResponse.error(null, "No active window")

        val text = params?.get("text")?.asString
        val id = params?.get("id")?.asString
        val contentDesc = params?.get("contentDescription")?.asString

        val preNode = findFirstElement(preRoot, text, id, null, contentDesc)
        preRoot.recycle()

        if (preNode == null) return CommandResponse.error(null, "Element not found")

        // Walk up to find clickable ancestor if this node isn't clickable
        var preTarget: AccessibilityNodeInfo? = preNode
        while (preTarget != null && !preTarget.isClickable) {
            val parent = preTarget.parent
            if (preTarget != preNode) preTarget.recycle()
            preTarget = parent
        }

        if (preTarget == null) {
            preNode.recycle()
            return CommandResponse.error(null, "No clickable element found")
        }

        val preTargetCheck = policyEngine.verifyTargetNodePackage(
            preTarget.packageName?.toString(),
            preTarget.refresh() && preNode.refresh(),
            "click_element"
        )
        val (safeText, safeDesc) = NodeSanitizer.sanitizeNodeFields(
            preNode.text?.toString(),
            preNode.contentDescription?.toString(),
            preNode.isPassword
        )
        val elemSummary = safeText ?: safeDesc ?: id ?: "element"

        if (preTarget != preNode) preTarget.recycle()
        preNode.recycle()

        if (preTargetCheck.type == PolicyDecisionType.DENY) {
            auditLogger.record("click_element", currentPackage, elemSummary, "n/a", "denied: ${preTargetCheck.reason}")
            return CommandResponse.error(null, preTargetCheck.reason)
        }

        val (approved, consentReason) = requestUserConsent(
            action = "click_element",
            targetPackage = currentPackage,
            targetElement = elemSummary,
            description = "Click '$elemSummary' in $currentPackage"
        )
        if (!approved) {
            return CommandResponse.error(null, consentReason)
        }

        // Re-check active foreground window package AFTER consent approval and BEFORE execution
        val postRoot = rootInActiveWindow ?: run {
            auditLogger.record("click_element", currentPackage, elemSummary, "approved", "denied: no active window after consent")
            return CommandResponse.error(null, "No active window after consent")
        }
        val postPackage = postRoot.packageName?.toString()
        val postRootCheck = policyEngine.verifyPostConsentContext(
            consentedPackage = currentPackage,
            currentPackage = postPackage,
            targetPackage = postPackage,
            refreshed = postRoot.refresh()
        )
        if (postRootCheck.type == PolicyDecisionType.DENY) {
            postRoot.recycle()
            auditLogger.record("click_element", postPackage ?: "none", elemSummary, "approved", "denied: ${postRootCheck.reason}")
            return CommandResponse.error(null, postRootCheck.reason)
        }

        val node = findFirstElement(postRoot, text, id, null, contentDesc)
        postRoot.recycle()

        if (node == null) {
            auditLogger.record("click_element", postPackage!!, elemSummary, "approved", "denied: element disappeared after consent")
            return CommandResponse.error(null, "Element not found after consent")
        }

        var target: AccessibilityNodeInfo? = node
        while (target != null && !target.isClickable) {
            val parent = target.parent
            if (target != node) target.recycle()
            target = parent
        }

        if (target == null) {
            node.recycle()
            auditLogger.record("click_element", postPackage!!, elemSummary, "approved", "denied: no clickable target after consent")
            return CommandResponse.error(null, "No clickable element found after consent")
        }

        val refreshed = target.refresh() && node.refresh()
        val targetPkg = target.packageName?.toString()
        val nodePkg = node.packageName?.toString()
        val targetCheck = policyEngine.verifyPostConsentContext(
            consentedPackage = currentPackage,
            currentPackage = postPackage,
            targetPackage = targetPkg,
            refreshed = refreshed
        )
        val nodeCheck = policyEngine.verifyPostConsentContext(
            consentedPackage = currentPackage,
            currentPackage = postPackage,
            targetPackage = nodePkg,
            refreshed = refreshed
        )
        if (targetCheck.type == PolicyDecisionType.DENY || nodeCheck.type == PolicyDecisionType.DENY) {
            val reason = if (targetCheck.type == PolicyDecisionType.DENY) targetCheck.reason else nodeCheck.reason
            if (target != node) target.recycle()
            node.recycle()
            auditLogger.record("click_element", targetPkg ?: postPackage!!, elemSummary, "approved", "denied: $reason")
            return CommandResponse.error(null, reason)
        }

        val result = target.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        if (target != node) target.recycle()
        node.recycle()

        return if (result) {
            auditLogger.record("click_element", targetPkg!!, elemSummary, "approved", "executed")
            CommandResponse.success(null, JsonObject().apply { addProperty("clicked", elemSummary) })
        } else {
            auditLogger.record("click_element", targetPkg!!, elemSummary, "approved", "failed")
            CommandResponse.error(null, "Click action failed")
        }
    }

    private fun executeWaitForElement(params: JsonObject?): CommandResponse {
        val text = params?.get("text")?.asString
        val id = params?.get("id")?.asString
        val className = params?.get("className")?.asString
        val contentDesc = params?.get("contentDescription")?.asString
        val timeoutMs = params?.get("timeout")?.asLong ?: 10000L
        val pollIntervalMs = 500L

        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            val root = rootInActiveWindow
            if (root != null) {
                val node = findFirstElement(root, text, id, className, contentDesc)
                if (node != null) {
                    val uiNode = nodeToUINode(node)
                    node.recycle()
                    root.recycle()
                    return CommandResponse.success(null, JsonObject().apply {
                        add("element", gson.toJsonTree(uiNode))
                        addProperty("found", true)
                        addProperty("elapsed_ms", System.currentTimeMillis() - startTime)
                    })
                }
                root.recycle()
            }
            Thread.sleep(pollIntervalMs)
        }

        return CommandResponse.success(null, JsonObject().apply {
            addProperty("found", false)
            addProperty("elapsed_ms", timeoutMs)
        })
    }

    private fun executeGetFocused(): CommandResponse {
        val focused = findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (focused == null) {
            return CommandResponse.success(null, JsonObject().apply { addProperty("focused", false) })
        }
        val uiNode = nodeToUINode(focused)
        focused.recycle()
        return CommandResponse.success(null, JsonObject().apply {
            addProperty("focused", true)
            add("element", gson.toJsonTree(uiNode))
        })
    }

    private fun executeGetNotifications(): CommandResponse {
        // Use the accessibility events - we have access through service info
        val root = rootInActiveWindow
        // Trigger notifications panel
        performGlobalAction(GLOBAL_ACTION_NOTIFICATIONS)
        Thread.sleep(500)

        val notifRoot = rootInActiveWindow
        val results = mutableListOf<UINode>()
        if (notifRoot != null) {
            findElements(notifRoot, null, null, "android.widget.FrameLayout", null, results, 50)
            notifRoot.recycle()
        }

        performGlobalAction(GLOBAL_ACTION_BACK)

        val json = gson.toJsonTree(results)
        return CommandResponse.success(null, JsonObject().apply {
            add("notifications", json)
        })
    }

    // --- Screenshot ---

    private fun executeScreenshot(params: JsonObject?): CommandResponse {
        if (Build.VERSION.SDK_INT < 30) {
            return CommandResponse.error(null, "Screenshot requires API 30+")
        }

        val quality = params?.get("quality")?.asInt ?: 80
        val latch = CountDownLatch(1)
        var resultBitmap: Bitmap? = null

        takeScreenshot(android.view.Display.DEFAULT_DISPLAY,
            mainExecutor,
            object : TakeScreenshotCallback {
                override fun onSuccess(screenshot: ScreenshotResult) {
                    val hwBitmap = Bitmap.wrapHardwareBuffer(
                        screenshot.hardwareBuffer, screenshot.colorSpace
                    )
                    resultBitmap = hwBitmap?.copy(Bitmap.Config.ARGB_8888, false)
                    hwBitmap?.recycle()
                    screenshot.hardwareBuffer.close()
                    latch.countDown()
                }

                override fun onFailure(errorCode: Int) {
                    Log.e(TAG, "Screenshot failed with code: $errorCode")
                    latch.countDown()
                }
            })

        latch.await(10, TimeUnit.SECONDS)

        val bitmap = resultBitmap ?: return CommandResponse.error(null, "Screenshot failed")
        val baos = ByteArrayOutputStream()
        bitmap.compress(Bitmap.CompressFormat.JPEG, quality, baos)
        val base64 = Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP)
        val width = bitmap.width
        val height = bitmap.height
        bitmap.recycle()

        return CommandResponse.success(null, JsonObject().apply {
            addProperty("image", base64)
            addProperty("format", "jpeg")
            addProperty("width", width)
            addProperty("height", height)
        })
    }

    // --- App Commands ---

    private fun executeOpenApp(params: JsonObject?): CommandResponse {
        val packageName = params?.get("package")?.asString
            ?: return CommandResponse.error(null, "Missing package name")

        val intent = packageManager.getLaunchIntentForPackage(packageName)
            ?: return CommandResponse.error(null, "App not found: $packageName")

        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startActivity(intent)

        return CommandResponse.success(null, JsonObject().apply {
            addProperty("opened", packageName)
        })
    }

    private fun executeGetDeviceInfo(): CommandResponse {
        val displayMetrics = resources.displayMetrics
        return CommandResponse.success(null, JsonObject().apply {
            addProperty("manufacturer", Build.MANUFACTURER)
            addProperty("model", Build.MODEL)
            addProperty("sdk", Build.VERSION.SDK_INT)
            addProperty("release", Build.VERSION.RELEASE)
            addProperty("screenWidth", displayMetrics.widthPixels)
            addProperty("screenHeight", displayMetrics.heightPixels)
            addProperty("density", displayMetrics.density)
            addProperty("densityDpi", displayMetrics.densityDpi)
        })
    }

    // --- UI Tree Helpers ---

    private fun buildUITree(node: AccessibilityNodeInfo, depth: Int, maxDepth: Int): UINode {
        val uiNode = nodeToUINode(node)

        if (depth < maxDepth) {
            val children = mutableListOf<UINode>()
            for (i in 0 until node.childCount) {
                val child = node.getChild(i) ?: continue
                children.add(buildUITree(child, depth + 1, maxDepth))
                child.recycle()
            }
            if (children.isNotEmpty()) {
                uiNode.children = children
            }
        }
        return uiNode
    }

    private fun nodeToUINode(node: AccessibilityNodeInfo): UINode {
        val rect = android.graphics.Rect()
        node.getBoundsInScreen(rect)
        val isPwd = node.isPassword
        val (safeText, safeDesc) = NodeSanitizer.sanitizeNodeFields(
            node.text?.toString(),
            node.contentDescription?.toString(),
            isPwd
        )

        return UINode(
            className = node.className?.toString(),
            text = safeText,
            contentDescription = safeDesc,
            viewId = node.viewIdResourceName,
            isClickable = node.isClickable,
            isScrollable = node.isScrollable,
            isEditable = node.isEditable,
            isEnabled = node.isEnabled,
            isChecked = node.isChecked,
            isFocused = node.isFocused,
            isSelected = node.isSelected,
            isPassword = isPwd,
            bounds = mapOf(
                "left" to rect.left,
                "top" to rect.top,
                "right" to rect.right,
                "bottom" to rect.bottom
            ),
            packageName = node.packageName?.toString()
        )
    }

    private fun findElements(
        node: AccessibilityNodeInfo,
        text: String?,
        id: String?,
        className: String?,
        contentDesc: String?,
        results: MutableList<UINode>,
        maxResults: Int
    ) {
        if (results.size >= maxResults) return

        if (matchesFilter(node, text, id, className, contentDesc)) {
            results.add(nodeToUINode(node))
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            findElements(child, text, id, className, contentDesc, results, maxResults)
            child.recycle()
        }
    }

    private fun findFirstElement(
        node: AccessibilityNodeInfo,
        text: String?,
        id: String?,
        className: String?,
        contentDesc: String?
    ): AccessibilityNodeInfo? {
        if (matchesFilter(node, text, id, className, contentDesc)) {
            return AccessibilityNodeInfo.obtain(node)
        }

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            val found = findFirstElement(child, text, id, className, contentDesc)
            if (found != null) {
                child.recycle()
                return found
            }
            child.recycle()
        }
        return null
    }

    private fun matchesFilter(
        node: AccessibilityNodeInfo,
        text: String?,
        id: String?,
        className: String?,
        contentDesc: String?
    ): Boolean {
        if (text != null) {
            val nodeText = node.text?.toString() ?: ""
            val nodeDesc = node.contentDescription?.toString() ?: ""
            if (!nodeText.contains(text, ignoreCase = true) &&
                !nodeDesc.contains(text, ignoreCase = true)) return false
        }
        if (id != null && node.viewIdResourceName?.contains(id, ignoreCase = true) != true) return false
        if (className != null && node.className?.toString()?.contains(className, ignoreCase = true) != true) return false
        if (contentDesc != null && node.contentDescription?.toString()?.contains(contentDesc, ignoreCase = true) != true) return false
        return true
    }
}
