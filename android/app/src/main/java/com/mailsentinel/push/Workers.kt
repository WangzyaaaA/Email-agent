package com.mailsentinel.push

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.ListenableWorker.Result
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
        val state = CredentialStore(context).load() ?: return
        if (!state.registered) {
            // The gateway only serves a device it has registered. A sync request inside that
            // activation window used to come back as an authentication failure and delete the
            // fresh pairing, so registration owns this window instead.
            register(context)
            return
        }
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

/** Codes that mean the gateway no longer accepts this device once it was activated. */
private val revokedDeviceCodes = setOf("invalid_device_credentials", "device_mismatch", "pairing_expired")

private fun clearRevokedState(context: Context) {
    CredentialStore(context).clear()
    MessageStore(context).clearAll()
}

/**
 * Maps a stable gateway error code onto a work result.
 *
 * Local key material and ciphertext are deleted only for a device the gateway has already
 * accepted, so the activation window (provisioned but not yet registered) can never destroy a
 * fresh pairing. Every code is kept as a displayable diagnostic instead.
 */
private fun gatewayFailureOutcome(context: Context, state: CredentialState, code: String): Result {
    val store = CredentialStore(context)
    if (code == "device_not_activated") {
        store.recordError(code)
        return Result.retry()
    }
    if (code in revokedDeviceCodes && state.registered) {
        clearRevokedState(context)
        return Result.failure()
    }
    store.recordError(code)
    return if (code == "pairing_expired") Result.failure() else Result.retry()
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
                // The gateway already holds a registration for this device; it is activated.
                if (exc.code != "stale_registration_version") throw exc
            }
            store.markRegistered()
            val status = NotificationState.read(applicationContext)
            api.updateStatus(status.notifications, status.otp, status.important, status.digest)
            WorkScheduling.sync(applicationContext)
            Result.success()
        } catch (exc: GatewayApiException) {
            gatewayFailureOutcome(applicationContext, state, exc.code)
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
            CredentialStore(applicationContext).recordError(null)
            Result.success()
        } catch (exc: GatewayApiException) {
            if (exc.code == "not_found") {
                localStore.markAcknowledged(messageId)
                Result.success()
            } else gatewayFailureOutcome(applicationContext, state, exc.code)
        } catch (_: Exception) {
            Result.retry()
        }
    }
}

class SyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val state = CredentialStore(applicationContext).load() ?: return@withContext Result.success()
        if (!state.registered) {
            WorkScheduling.register(applicationContext)
            return@withContext Result.success()
        }
        val api = GatewayApi(state)
        val processor = MessageProcessor(applicationContext)
        try {
            var cursor: String? = null
            var pages = 0
            var retryNeeded = false
            do {
                val page = api.pending(cursor)
                for ((gatewayId, envelope) in page.items) {
                    val result = processor.process(gatewayId, envelope)
                    if (result == null) {
                        retryNeeded = true
                        continue
                    }
                    WorkScheduling.acknowledge(applicationContext, result.messageId, result.highPriority)
                }
                cursor = page.nextCursor
                pages += 1
            } while (cursor != null && pages < 10)
            processor.showStoredWhenPermissionReturns()
            val status = NotificationState.read(applicationContext)
            api.updateStatus(status.notifications, status.otp, status.important, status.digest)
            CredentialStore(applicationContext).recordError(null)
            MessageStore(applicationContext).cleanup()
            for (row in MessageStore(applicationContext).unacknowledged()) {
                WorkScheduling.acknowledge(applicationContext, row.messageId, false)
            }
            if (retryNeeded) Result.retry() else Result.success()
        } catch (exc: GatewayApiException) {
            gatewayFailureOutcome(applicationContext, state, exc.code)
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
