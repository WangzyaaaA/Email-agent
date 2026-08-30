package com.mailsentinel.push

import android.app.NotificationManager
import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.google.android.gms.tasks.Tasks
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

object WorkScheduling {
    private val network = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

    fun register(context: Context) {
        val request = OneTimeWorkRequestBuilder<RegisterWorker>()
            .setConstraints(network)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork("device-registration", ExistingWorkPolicy.REPLACE, request)
    }

    fun sync(context: Context) {
        val request = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(network)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork("pending-sync", ExistingWorkPolicy.KEEP, request)
    }

    fun acknowledge(context: Context, messageId: String, highPriority: Boolean) {
        val builder = OneTimeWorkRequestBuilder<AckWorker>()
            .setInputData(Data.Builder().putString("message_id", messageId).build())
            .setConstraints(network)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.SECONDS)
        if (highPriority) builder.setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
        WorkManager.getInstance(context).enqueueUniqueWork("ack:$messageId", ExistingWorkPolicy.KEEP, builder.build())
    }
}

private fun clearRevokedState(context: Context) {
    CredentialStore(context).clear()
    MessageStore(context).clearAll()
}

class RegisterWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val store = CredentialStore(applicationContext)
        var state = store.load() ?: return@withContext Result.success()
        if (state.fcmRegistrationId == null) {
            try { Tasks.await(FirebaseMessaging.getInstance().register(), 15, TimeUnit.SECONDS) } catch (_: Exception) {
                return@withContext Result.retry()
            }
            state = store.load() ?: return@withContext Result.failure()
            if (state.fcmRegistrationId == null) return@withContext Result.retry()
        }
        try {
            val api = GatewayApi(state)
            try {
                api.register()
            } catch (exc: GatewayApiException) {
                if (exc.code != "stale_registration_version") throw exc
            }
            val status = NotificationState.read(applicationContext)
            api.updateStatus(status.notifications, status.otp, status.important, status.digest)
            WorkScheduling.sync(applicationContext)
            Result.success()
        } catch (exc: GatewayApiException) {
            if (exc.code in setOf("invalid_device_credentials", "pairing_expired", "device_mismatch")) {
                clearRevokedState(applicationContext)
                Result.failure()
            } else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}

class AckWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val messageId = inputData.getString("message_id") ?: return@withContext Result.failure()
        val localStore = MessageStore(applicationContext)
        val row = localStore.find(messageId) ?: return@withContext Result.success()
        val result = row.ackResult ?: return@withContext Result.success()
        val state = CredentialStore(applicationContext).load() ?: return@withContext Result.failure()
        try {
            GatewayApi(state).acknowledge(row.gatewayMessageId, result)
            localStore.markAcknowledged(messageId)
            Result.success()
        } catch (exc: GatewayApiException) {
            if (exc.code == "not_found") {
                localStore.markAcknowledged(messageId)
                Result.success()
            } else if (exc.code in setOf("invalid_device_credentials", "device_mismatch")) {
                clearRevokedState(applicationContext)
                Result.failure()
            } else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}

class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val state = CredentialStore(applicationContext).load() ?: return@withContext Result.success()
        val api = GatewayApi(state)
        val processor = MessageProcessor(applicationContext)
        try {
            var cursor: String? = null
            var pages = 0
            do {
                val page = api.pending(cursor)
                for ((gatewayId, envelope) in page.items) {
                    val result = processor.process(gatewayId, envelope)
                    WorkScheduling.acknowledge(applicationContext, result.messageId, result.highPriority)
                }
                cursor = page.nextCursor
                pages += 1
            } while (cursor != null && pages < 10)
            processor.showStoredWhenPermissionReturns()
            val status = NotificationState.read(applicationContext)
            api.updateStatus(status.notifications, status.otp, status.important, status.digest)
            MessageStore(applicationContext).cleanup()
            for (row in MessageStore(applicationContext).unacknowledged()) {
                WorkScheduling.acknowledge(applicationContext, row.messageId, false)
            }
            Result.success()
        } catch (exc: GatewayApiException) {
            if (exc.code in setOf("invalid_device_credentials", "device_mismatch")) {
                clearRevokedState(applicationContext)
                Result.failure()
            } else Result.retry()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}

data class NotificationState(val notifications: Boolean, val otp: Boolean, val important: Boolean, val digest: Boolean) {
    companion object {
        fun read(context: Context): NotificationState {
            return NotificationState(
                NotificationHelper.notificationsEnabled(context),
                NotificationHelper.channelEnabled(context, NotificationHelper.CHANNEL_SENSITIVE),
                NotificationHelper.channelEnabled(context, NotificationHelper.CHANNEL_IMPORTANT),
                NotificationHelper.channelEnabled(context, NotificationHelper.CHANNEL_DIGEST),
            )
        }
    }
}
