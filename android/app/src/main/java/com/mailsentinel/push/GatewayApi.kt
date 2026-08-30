package com.mailsentinel.push

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.TimeUnit

class GatewayApiException(val code: String) : Exception(code)

data class PendingPage(val items: List<Pair<String, Envelope>>, val nextCursor: String?)

class GatewayApi(private val state: CredentialState) {
    private val jsonType = "application/json; charset=utf-8".toMediaType()
    private val random = SecureRandom()
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .callTimeout(15, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private fun execute(method: String, url: HttpUrl, body: ByteArray = ByteArray(0)): JSONObject {
        val target = url.encodedPath + (url.encodedQuery?.let { "?$it" } ?: "")
        val timestamp = Instant.now().epochSecond.toString()
        val nonce = Crypto.b64Encode(ByteArray(16).also(random::nextBytes))
        val authKey = Crypto.deviceAuthKey(Crypto.b64Decode(state.pairing.contentRootKey), state.pairing.deviceId)
        val signature = Crypto.signRequest(authKey, method, target, body, timestamp, nonce)
        val builder = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer ${state.pairing.deviceToken}")
            .header("Accept", "application/json")
            .header("X-MS-Timestamp", timestamp)
            .header("X-MS-Nonce", nonce)
            .header("X-MS-Signature", signature)
        if (method == "POST") builder.post(body.toRequestBody(jsonType)) else builder.get()
        client.newCall(builder.build()).execute().use { response ->
            val responseBody = response.body.string().take(8192)
            val parsed = try { JSONObject(responseBody) } catch (_: Exception) { JSONObject() }
            if (!response.isSuccessful) {
                val code = parsed.optJSONObject("error")?.optString("code")?.takeIf { it.matches(Regex("^[a-z0-9_]{1,60}$")) }
                throw GatewayApiException(code ?: "gateway_request_failed")
            }
            return parsed
        }
    }

    private fun url(path: String): HttpUrl {
        require(path.startsWith('/'))
        return (state.pairing.gatewayUrl + path).toHttpUrl()
    }

    fun register(): JSONObject {
        val registrationId = state.fcmRegistrationId ?: throw GatewayApiException("fcm_token_unavailable")
        val body = JSONObject()
            .put("device_id", state.pairing.deviceId)
            // The gateway protocol keeps this field name for compatibility; current FCM uses a FID.
            .put("fcm_token", registrationId)
            .put("registration_version", state.registrationVersion)
            .put("app_protocol_version", 1)
            .toString().toByteArray(Charsets.UTF_8)
        return execute("POST", url("/v1/devices/register"), body)
    }

    fun updateStatus(
        notificationsEnabled: Boolean,
        otpEnabled: Boolean,
        importantEnabled: Boolean,
        digestEnabled: Boolean,
    ) {
        val body = JSONObject()
            .put("device_id", state.pairing.deviceId)
            .put("notifications_enabled", notificationsEnabled)
            .put("otp_channel_enabled", otpEnabled)
            .put("important_channel_enabled", importantEnabled)
            .put("digest_channel_enabled", digestEnabled)
            .put("app_protocol_version", 1)
            .toString().toByteArray(Charsets.UTF_8)
        execute("POST", url("/v1/devices/status"), body)
    }

    fun pending(cursor: String? = null): PendingPage {
        val builder = url("/v1/messages/pending").newBuilder().addQueryParameter("limit", "50")
        if (cursor != null) builder.addQueryParameter("cursor", cursor)
        val response = execute("GET", builder.build())
        val array = response.optJSONArray("items") ?: JSONArray()
        val items = buildList {
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                add(item.getString("gateway_message_id") to Envelope.fromJson(item.getJSONObject("envelope")))
            }
        }
        return PendingPage(items, response.optString("next_cursor").takeIf { it.isNotEmpty() && it != "null" })
    }

    fun acknowledge(gatewayMessageId: String, result: String) {
        val body = JSONObject().put("device_id", state.pairing.deviceId).put("result", result)
            .toString().toByteArray(Charsets.UTF_8)
        execute("POST", url("/v1/messages/$gatewayMessageId/ack"), body)
    }
}
