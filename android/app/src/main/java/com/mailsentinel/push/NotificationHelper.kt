package com.mailsentinel.push

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

object NotificationHelper {
    const val CHANNEL_SENSITIVE = "otp_security"
    const val CHANNEL_IMPORTANT = "important_mail"
    const val CHANNEL_DIGEST = "digests"

    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannels(
            listOf(
                NotificationChannel(CHANNEL_SENSITIVE, "验证码与安全告警", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "验证码、账号安全和临近截止事项"
                    lockscreenVisibility = Notification.VISIBILITY_SECRET
                },
                NotificationChannel(CHANNEL_IMPORTANT, "重要邮件", NotificationManager.IMPORTANCE_DEFAULT).apply {
                    description = "重要邮件和待回复提醒"
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                },
                NotificationChannel(CHANNEL_DIGEST, "周期总结", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "日、周、月邮箱总结"
                    lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                },
            )
        )
    }

    fun notificationsEnabled(context: Context): Boolean {
        val runtimeGranted = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(
            context, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
        return runtimeGranted && NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    fun channelEnabled(context: Context, channelId: String): Boolean {
        val channel = context.getSystemService(NotificationManager::class.java).getNotificationChannel(channelId)
        return channel == null || channel.importance != NotificationManager.IMPORTANCE_NONE
    }

    fun channelFor(kind: String): String = when (kind) {
        "otp", "security", "deadline" -> CHANNEL_SENSITIVE
        "digest" -> CHANNEL_DIGEST
        else -> CHANNEL_IMPORTANT
    }

    fun show(context: Context, messageId: String, value: PlainNotification): Boolean {
        val channel = channelFor(value.kind)
        if (!notificationsEnabled(context) || !channelEnabled(context, channel)) return false
        val intent = Intent(context, MainActivity::class.java).putExtra("message_id", messageId)
        val pendingIntent = PendingIntent.getActivity(
            context, messageId.hashCode(), intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val previewSensitive = CredentialStore(context).sensitivePreviewEnabled()
        val publicVersion = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Mail Sentinel 有一条敏感通知")
            .setContentText("解锁设备后查看")
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
        val builder = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(value.title)
            .setContentText(value.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(value.body))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setCategory(if (value.kind in setOf("otp", "security", "deadline")) NotificationCompat.CATEGORY_ALARM else NotificationCompat.CATEGORY_EMAIL)
            .setPriority(if (channel == CHANNEL_SENSITIVE) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
        if (value.sensitive && !previewSensitive) {
            builder.setVisibility(NotificationCompat.VISIBILITY_SECRET).setPublicVersion(publicVersion)
        } else {
            builder.setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
        }
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) return false
        return try {
            NotificationManagerCompat.from(context).notify(messageId.hashCode(), builder.build())
            true
        } catch (_: SecurityException) {
            false
        }
    }
}
