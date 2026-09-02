package com.mailsentinel.push

import android.content.Context
import java.time.Instant

data class ProcessResult(val messageId: String, val result: String, val highPriority: Boolean)

class MessageProcessor(private val context: Context) {
    private val credentials = CredentialStore(context)
    private val messages = MessageStore(context)

    fun process(gatewayMessageId: String, envelope: Envelope): ProcessResult? {
        if (!messages.claimForProcessing(gatewayMessageId, envelope)) {
            val existing = messages.find(envelope.messageId)
            return existing?.ackResult?.let {
                ProcessResult(envelope.messageId, it, envelope.priority == "high")
            }
        }
        val state = credentials.load() ?: throw IllegalStateException("pairing_required")
        if (!Instant.parse(envelope.expiresAt).isAfter(Instant.now())) {
            messages.markProcessed(envelope.messageId, false, "expired")
            return ProcessResult(envelope.messageId, "expired", envelope.priority == "high")
        }
        val plain = try {
            Crypto.decrypt(state.pairing, envelope)
        } catch (_: Exception) {
            messages.markProcessed(envelope.messageId, false, "decrypt_failed")
            return ProcessResult(envelope.messageId, "decrypt_failed", envelope.priority == "high")
        }
        val shown = NotificationHelper.show(context, envelope.messageId, plain)
        val result = if (shown) "shown" else "stored_notifications_disabled"
        messages.markProcessed(envelope.messageId, shown, result)
        return ProcessResult(envelope.messageId, result, envelope.priority == "high")
    }

    fun showStoredWhenPermissionReturns() {
        if (!NotificationHelper.notificationsEnabled(context)) return
        val state = credentials.load() ?: return
        for (row in messages.pendingDisplay()) {
            val envelopeJson = row.envelopeJson ?: continue
            try {
                val envelope = Envelope.fromJson(org.json.JSONObject(envelopeJson))
                if (Instant.ofEpochSecond(row.expiresAtEpoch).isAfter(Instant.now())) {
                    val plain = Crypto.decrypt(state.pairing, envelope)
                    if (NotificationHelper.show(context, row.messageId, plain)) {
                        messages.markProcessed(row.messageId, true, "shown")
                    }
                }
            } catch (_: Exception) {
                // The stored value remains ciphertext and is removed by expiry cleanup.
            }
        }
    }
}
