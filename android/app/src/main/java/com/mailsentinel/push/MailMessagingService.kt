package com.mailsentinel.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class MailMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        val gatewayMessageId = message.data["gateway_message_id"] ?: return
        try {
            val envelope = Envelope.fromMap(message.data)
            val result = MessageProcessor(applicationContext).process(gatewayMessageId, envelope)
            WorkScheduling.acknowledge(applicationContext, result.messageId, result.highPriority)
        } catch (_: Exception) {
            WorkScheduling.sync(applicationContext)
        }
    }

    override fun onRegistered(installationId: String) {
        val store = CredentialStore(applicationContext)
        if (store.load() != null) {
            store.saveFcmRegistration(installationId)
            WorkScheduling.register(applicationContext)
        }
    }

    override fun onUnregistered(installationId: String) {
        CredentialStore(applicationContext).clearFcmRegistration()
    }

    override fun onDeletedMessages() {
        WorkScheduling.sync(applicationContext)
    }
}
