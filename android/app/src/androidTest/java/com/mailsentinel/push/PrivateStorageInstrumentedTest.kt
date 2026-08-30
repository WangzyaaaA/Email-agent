package com.mailsentinel.push

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PrivateStorageInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @After
    fun cleanup() {
        CredentialStore(context).clear()
        MessageStore(context).clearAll()
    }

    @Test
    fun pairingSecretsAreWrappedByAndroidKeystore() {
        val pairing = PairingConfig(
            "https://push.example.com",
            "device_0123456789",
            "key_0123456789",
            Crypto.b64Encode(ByteArray(32) { 7 }),
            Crypto.b64Encode(ByteArray(32) { it.toByte() }),
            "2030-01-01T00:10:00Z",
        )
        val store = CredentialStore(context)
        store.savePairing(pairing)
        val raw = context.getSharedPreferences("private_credentials", Context.MODE_PRIVATE).all.toString()
        assertFalse(raw.contains(pairing.deviceToken))
        assertFalse(raw.contains(pairing.contentRootKey))
        assertEquals(pairing.deviceId, store.load()?.pairing?.deviceId)
    }

    @Test
    fun localMessageDatabaseStoresOnlyEnvelopeCiphertextAndMetadata() {
        val envelope = Envelope(
            "1", "message_0123456789", "device_0123456789", "key_0123456789", "high",
            "2030-01-01T00:10:00Z", Crypto.b64Encode(ByteArray(12) { 1 }), Crypto.b64Encode(ByteArray(32) { 2 })
        )
        val store = MessageStore(context)
        assertTrue(store.insertIfAbsent("gateway_0123456789", envelope))
        val row = store.find(envelope.messageId)!!
        assertEquals(envelope.ciphertext, org.json.JSONObject(row.envelopeJson!!).getString("ciphertext"))
        assertFalse(row.envelopeJson!!.contains("notification title"))
        assertNotEquals("gateway_0123456789", envelope.ciphertext)
    }
}
