package com.mailsentinel.push

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class CredentialState(
    val pairing: PairingConfig,
    val fcmRegistrationId: String?,
    val registrationVersion: Int,
)

class CredentialStore(context: Context) {
    private val prefs = context.getSharedPreferences("private_credentials", Context.MODE_PRIVATE)
    private val alias = "mail_sentinel_device_wrap_v1"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    @Synchronized
    fun savePairing(pairing: PairingConfig) {
        save(CredentialState(pairing, null, 0))
    }

    @Synchronized
    fun saveFcmRegistration(installationId: String): CredentialState? {
        val current = load() ?: return null
        val next = current.copy(fcmRegistrationId = installationId, registrationVersion = current.registrationVersion + 1)
        save(next)
        return next
    }

    @Synchronized
    fun clearFcmRegistration() {
        val current = load() ?: return
        save(current.copy(fcmRegistrationId = null))
    }

    @Synchronized
    fun load(): CredentialState? {
        val wrapped = prefs.getString("state", null) ?: return null
        return try {
            val container = JSONObject(wrapped)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, Crypto.b64Decode(container.getString("nonce"))))
            val clear = cipher.doFinal(Crypto.b64Decode(container.getString("ciphertext"))).toString(Charsets.UTF_8)
            val json = JSONObject(clear)
            CredentialState(
                PairingConfig.parse(json.getJSONObject("pairing").toString(), requireUnexpired = false),
                json.optString("fcm_registration_id").takeIf { it.isNotEmpty() }
                    ?: json.optString("fcm_token").takeIf { it.isNotEmpty() },
                json.getInt("registration_version"),
            )
        } catch (_: Exception) {
            clear()
            null
        }
    }

    @Synchronized
    private fun save(state: CredentialState) {
        val clear = JSONObject()
            .put("pairing", state.pairing.toJson())
            .put("fcm_registration_id", state.fcmRegistrationId ?: "")
            .put("registration_version", state.registrationVersion)
            .toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val container = JSONObject()
            .put("nonce", Crypto.b64Encode(cipher.iv))
            .put("ciphertext", Crypto.b64Encode(cipher.doFinal(clear)))
        prefs.edit().putString("state", container.toString()).apply()
    }

    fun sensitivePreviewEnabled(): Boolean = prefs.getBoolean("sensitive_preview", false)
    fun setSensitivePreviewEnabled(enabled: Boolean) = prefs.edit().putBoolean("sensitive_preview", enabled).apply()

    @Synchronized
    fun clear() {
        prefs.edit().clear().commit()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }
}
