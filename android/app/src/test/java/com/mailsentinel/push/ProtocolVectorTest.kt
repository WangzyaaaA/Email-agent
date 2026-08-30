package com.mailsentinel.push

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class ProtocolVectorTest {
    private fun vector(): JSONObject {
        val candidates = listOf(
            File("../protocol_vectors.json"),
            File("../../protocol_vectors.json"),
            File("protocol_vectors.json"),
        )
        val file = candidates.firstOrNull { it.isFile } ?: error("protocol_vectors.json not found")
        return JSONObject(file.readText())
    }

    @Test
    fun sharedHkdfAadAesGcmAndHmacVectorMatches() {
        val value = vector()
        val root = Crypto.b64Decode(value.getString("content_root_key"))
        val deviceId = value.getString("device_id")
        assertEquals(value.getString("message_key"), Crypto.b64Encode(Crypto.messageKey(root, deviceId)))
        val authKey = Crypto.deviceAuthKey(root, deviceId)
        assertEquals(value.getString("device_auth_key"), Crypto.b64Encode(authKey))

        val envelope = Envelope.fromJson(value.getJSONObject("envelope"))
        val config = PairingConfig(
            "https://push.example.com", deviceId, value.getString("key_id"),
            Crypto.b64Encode(ByteArray(32) { 7 }), value.getString("content_root_key"), "2030-01-01T00:05:00Z"
        )
        val clear = Crypto.decrypt(config, envelope)
        assertEquals("otp", clear.kind)
        assertEquals("OTP example", clear.title)

        val request = value.getJSONObject("request")
        val signature = Crypto.signRequest(
            authKey, request.getString("method"), request.getString("path_and_query"),
            request.getString("body").toByteArray(), request.getString("timestamp"), request.getString("nonce")
        )
        assertEquals(request.getString("signature"), signature)
    }

    @Test(expected = Exception::class)
    fun tamperedCiphertextFailsClosed() {
        val value = vector()
        val original = value.getJSONObject("envelope")
        val bytes = Crypto.b64Decode(original.getString("ciphertext"))
        bytes[0] = (bytes[0].toInt() xor 1).toByte()
        original.put("ciphertext", Crypto.b64Encode(bytes))
        val config = PairingConfig(
            "https://push.example.com", value.getString("device_id"), value.getString("key_id"),
            Crypto.b64Encode(ByteArray(32) { 7 }), value.getString("content_root_key"), "2030-01-01T00:05:00Z"
        )
        Crypto.decrypt(config, Envelope.fromJson(original))
    }
}
