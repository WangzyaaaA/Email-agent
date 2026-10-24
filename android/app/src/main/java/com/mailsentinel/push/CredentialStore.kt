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
    /** True once the gateway confirmed this device and reported it as active. */
    val registered: Boolean,
    /** Last stable gateway error code, safe to display; never carries payload data. */
    val lastError: String?,
)

/**
 * Every call site builds its own instance, so instance level synchronization was not enough:
 * two threads could generate competing wrapping keys and make previously stored state
 * undecryptable. All reads and writes share one process wide lock.
 */
private val credentialLock = Any()
private inline fun <T> locked(block: () -> T): T = synchronized(credentialLock, block)

class CredentialStore(context: Context) {
    private val prefs = context.getSharedPreferences("private_credentials", Context.MODE_PRIVATE)
    private val alias = "mail_sentinel_device_wrap_v1"

    private fun key(): SecretKey {
        (keystore().getKey(alias, null) as? SecretKey)?.let { return it }
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

    private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun savePairing(pairing: PairingConfig) = locked {
        save(CredentialState(pairing, null, 0, registered = false, lastError = null))
    }

    fun saveFcmRegistration(installationId: String): CredentialState? = locked {
        val current = loadLocked() ?: return@locked null
        val next = current.copy(fcmRegistrationId = installationId, registrationVersion = current.registrationVersion + 1)
        save(next)
        next
    }

    /** Records that the gateway accepted this device; sync work stays blocked until then. */
    fun markRegistered(): CredentialState? = locked {
        val current = loadLocked() ?: return@locked null
        val next = current.copy(registered = true, lastError = null)
        save(next)
        next
    }

    fun clearFcmRegistration() = locked {
        val current = loadLocked() ?: return@locked
        save(current.copy(fcmRegistrationId = null))
    }

    /** Stores a stable gateway error code for display; never stores payloads or credentials. */
    fun recordError(code: String?): CredentialState? = locked {
        val current = loadLocked() ?: return@locked null
        val next = current.copy(lastError = code?.takeIf { it.matches(Regex("^[a-z0-9_]{1,60}$")) })
        save(next)
        next
    }

    fun load(): CredentialState? = locked { loadLocked() }

    private fun loadLocked(): CredentialState? {
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
                // States written before this flag existed are treated as already registered so
                // an upgrade never turns a genuinely revoked device into a silent one.
                if (json.has("registered")) json.getBoolean("registered") else true,
                json.optString("last_error").takeIf { it.isNotEmpty() },
            )
        } catch (_: Exception) {
            clearLocked()
            null
        }
    }

    private fun save(state: CredentialState) {
        val clear = JSONObject()
            .put("pairing", state.pairing.toJson())
            .put("fcm_registration_id", state.fcmRegistrationId ?: "")
            .put("registration_version", state.registrationVersion)
            .put("registered", state.registered)
            .put("last_error", state.lastError ?: "")
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

    fun clear() = locked { clearLocked() }

    private fun clearLocked() {
        prefs.edit().clear().commit()
        val store = keystore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }
}
