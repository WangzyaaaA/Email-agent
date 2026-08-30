package com.mailsentinel.push

import android.app.Application
import android.net.ConnectivityManager
import android.net.Network
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging

class MailSentinelApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannels(this)
        MessageStore(this).cleanup()
        initializeFirebase()
        if (CredentialStore(this).load() != null) {
            if (FirebaseApp.getApps(this).isNotEmpty()) FirebaseMessaging.getInstance().register()
            WorkScheduling.register(this)
            WorkScheduling.sync(this)
        }
        getSystemService(ConnectivityManager::class.java).registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (CredentialStore(this@MailSentinelApplication).load() != null) {
                        WorkScheduling.sync(this@MailSentinelApplication)
                    }
                }
            }
        )
    }

    private fun initializeFirebase() {
        if (FirebaseApp.getApps(this).isNotEmpty()) return
        if (listOf(
                BuildConfig.FIREBASE_API_KEY,
                BuildConfig.FIREBASE_APPLICATION_ID,
                BuildConfig.FIREBASE_PROJECT_ID,
                BuildConfig.FIREBASE_SENDER_ID,
            ).any { it.isBlank() }
        ) return
        val options = FirebaseOptions.Builder()
            .setApiKey(BuildConfig.FIREBASE_API_KEY)
            .setApplicationId(BuildConfig.FIREBASE_APPLICATION_ID)
            .setProjectId(BuildConfig.FIREBASE_PROJECT_ID)
            .setGcmSenderId(BuildConfig.FIREBASE_SENDER_ID)
            .build()
        FirebaseApp.initializeApp(this, options)
    }
}
