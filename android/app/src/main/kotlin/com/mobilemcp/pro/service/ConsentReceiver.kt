package com.mobilemcp.pro.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationManagerCompat

class ConsentReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_CONSENT_DECISION = "com.mobilemcp.pro.ACTION_CONSENT_DECISION"
        const val EXTRA_NONCE = "extra_nonce"
        const val EXTRA_APPROVED = "extra_approved"
    }

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return
        if (intent.action != ACTION_CONSENT_DECISION) return

        val nonce = intent.getStringExtra(EXTRA_NONCE) ?: return
        val approved = intent.getBooleanExtra(EXTRA_APPROVED, false)

        NotificationManagerCompat.from(context).cancel(nonce.hashCode())
        MobileAccessibilityService.instance?.resolveConsent(nonce, approved)
    }
}
