package com.mailsentinel.push

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Crypto {
    private const val messageInfo = "mail-sentinel/android/message/v1"
    private const val authInfo = "mail-sentinel/android/device-auth/v1"

    fun b64Encode(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)
    fun b64Decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    private fun hkdf(input: ByteArray, salt: ByteArray, info: String): ByteArray {
        val extract = Mac.getInstance("HmacSHA256")
        extract.init(SecretKeySpec(salt, "HmacSHA256"))
        val pseudoRandomKey = extract.doFinal(input)
        val expand = Mac.getInstance("HmacSHA256")
        expand.init(SecretKeySpec(pseudoRandomKey, "HmacSHA256"))
        expand.update(info.toByteArray(Charsets.UTF_8))
        expand.update(1.toByte())
        return expand.doFinal().copyOf(32)
    }

    fun messageKey(root: ByteArray, deviceId: String): ByteArray = hkdf(root, deviceId.toByteArray(Charsets.UTF_8), messageInfo)
    fun deviceAuthKey(root: ByteArray, deviceId: String): ByteArray = hkdf(root, deviceId.toByteArray(Charsets.UTF_8), authInfo)

    fun aad(envelope: Envelope): ByteArray = listOf(
        "v1", envelope.messageId, envelope.deviceId, envelope.keyId, envelope.priority, envelope.expiresAt
    ).joinToString("\n").toByteArray(Charsets.UTF_8)

    fun decrypt(config: PairingConfig, envelope: Envelope): PlainNotification {
        require(envelope.deviceId == config.deviceId && envelope.keyId == config.keyId) { "device_key_mismatch" }
        val key = messageKey(b64Decode(config.contentRootKey), config.deviceId)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, b64Decode(envelope.nonce)))
        cipher.updateAAD(aad(envelope))
        val clear = cipher.doFinal(b64Decode(envelope.ciphertext))
        return PlainNotification.parse(clear)
    }

    fun canonicalRequest(
        method: String,
        pathAndQuery: String,
        body: ByteArray,
        timestamp: String,
        nonce: String,
    ): ByteArray {
        require(pathAndQuery.startsWith('/') && '\n' !in pathAndQuery && '\r' !in pathAndQuery)
        val digest = MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }
        return listOf("v1", method.uppercase(), pathAndQuery, digest, timestamp, nonce)
            .joinToString("\n").toByteArray(Charsets.UTF_8)
    }

    fun signRequest(
        key: ByteArray,
        method: String,
        pathAndQuery: String,
        body: ByteArray,
        timestamp: String,
        nonce: String,
    ): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return b64Encode(mac.doFinal(canonicalRequest(method, pathAndQuery, body, timestamp, nonce)))
    }
}
