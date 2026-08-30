package com.mailsentinel.push

import android.net.Uri
import org.json.JSONObject
import java.time.Instant

private val idPattern = Regex("^[A-Za-z0-9_-]{8,128}$")
private val b64Pattern = Regex("^[A-Za-z0-9_-]+$")

data class PairingConfig(
    val gatewayUrl: String,
    val deviceId: String,
    val keyId: String,
    val deviceToken: String,
    val contentRootKey: String,
    val pairingExpiresAt: String,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("version", 1)
        .put("gateway_url", gatewayUrl)
        .put("device_id", deviceId)
        .put("key_id", keyId)
        .put("device_token", deviceToken)
        .put("content_root_key", contentRootKey)
        .put("expires_at", pairingExpiresAt)

    companion object {
        private val keys = setOf("version", "gateway_url", "device_id", "key_id", "device_token", "content_root_key", "expires_at")

        fun parse(raw: String, requireUnexpired: Boolean = true): PairingConfig {
            require(raw.toByteArray(Charsets.UTF_8).size <= 4096) { "pairing_payload_too_large" }
            val json = JSONObject(raw)
            require(json.keys().asSequence().toSet() == keys && json.getInt("version") == 1) { "invalid_pairing_payload" }
            val gateway = json.getString("gateway_url")
            val uri = Uri.parse(gateway)
            require(
                uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null &&
                    (uri.path.isNullOrEmpty() || uri.path == "/") && uri.query == null && uri.fragment == null &&
                    (uri.port == -1 || uri.port == 443)
            ) { "invalid_gateway_url" }
            val expires = Instant.parse(json.getString("expires_at"))
            if (requireUnexpired) require(expires.isAfter(Instant.now())) { "pairing_expired" }
            val deviceId = json.getString("device_id")
            val keyId = json.getString("key_id")
            val deviceToken = json.getString("device_token")
            val root = json.getString("content_root_key")
            require(idPattern.matches(deviceId) && idPattern.matches(keyId)) { "invalid_device_identifier" }
            require(b64Pattern.matches(deviceToken) && Crypto.b64Decode(deviceToken).size == 32) { "invalid_device_token" }
            require(b64Pattern.matches(root) && Crypto.b64Decode(root).size == 32) { "invalid_content_key" }
            return PairingConfig(gateway.trimEnd('/'), deviceId, keyId, deviceToken, root, json.getString("expires_at"))
        }
    }
}

data class Envelope(
    val version: String,
    val messageId: String,
    val deviceId: String,
    val keyId: String,
    val priority: String,
    val expiresAt: String,
    val nonce: String,
    val ciphertext: String,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("version", version)
        .put("message_id", messageId)
        .put("device_id", deviceId)
        .put("key_id", keyId)
        .put("priority", priority)
        .put("expires_at", expiresAt)
        .put("nonce", nonce)
        .put("ciphertext", ciphertext)

    companion object {
        private val keys = setOf("version", "message_id", "device_id", "key_id", "priority", "expires_at", "nonce", "ciphertext")

        fun fromMap(data: Map<String, String>): Envelope {
            require(data.keys == keys + "gateway_message_id") { "invalid_envelope_fields" }
            return fromJson(JSONObject(data.filterKeys { it in keys }))
        }

        fun fromJson(json: JSONObject): Envelope {
            require(json.keys().asSequence().toSet() == keys) { "invalid_envelope_fields" }
            val value = Envelope(
                json.getString("version"), json.getString("message_id"), json.getString("device_id"),
                json.getString("key_id"), json.getString("priority"), json.getString("expires_at"),
                json.getString("nonce"), json.getString("ciphertext")
            )
            require(value.version == "1") { "unsupported_protocol" }
            require(idPattern.matches(value.messageId) && idPattern.matches(value.deviceId) && idPattern.matches(value.keyId)) { "invalid_envelope_identifier" }
            require(value.priority == "normal" || value.priority == "high") { "invalid_priority" }
            require(Crypto.b64Decode(value.nonce).size == 12) { "invalid_nonce" }
            require(value.ciphertext.length <= 3500 && Crypto.b64Decode(value.ciphertext).size >= 16) { "invalid_ciphertext" }
            Instant.parse(value.expiresAt)
            return value
        }
    }
}

data class PlainNotification(
    val kind: String,
    val title: String,
    val body: String,
    val createdAt: String,
    val sensitive: Boolean,
) {
    companion object {
        private val keys = setOf("schema", "kind", "title", "body", "created_at", "sensitive")
        private val kinds = setOf("otp", "security", "deadline", "important", "followup", "digest", "test")

        fun parse(bytes: ByteArray): PlainNotification {
            require(bytes.size <= 2200) { "plaintext_too_large" }
            val json = JSONObject(bytes.toString(Charsets.UTF_8))
            require(json.keys().asSequence().toSet() == keys && json.getInt("schema") == 1) { "invalid_plaintext" }
            val kind = json.getString("kind")
            val title = json.getString("title")
            val body = json.getString("body")
            require(kind in kinds && title.length <= 160 && body.length <= 1600) { "invalid_plaintext_limits" }
            Instant.parse(json.getString("created_at"))
            return PlainNotification(kind, title, body, json.getString("created_at"), json.getBoolean("sensitive"))
        }
    }
}
