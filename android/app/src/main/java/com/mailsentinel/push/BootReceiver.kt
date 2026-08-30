package com.mailsentinel.push

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && CredentialStore(context).load() != null) {
            WorkScheduling.register(context)
            WorkScheduling.sync(context)
        }
    }
}
