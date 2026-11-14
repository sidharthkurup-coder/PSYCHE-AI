package com.psycheai.companion.sync

import android.util.Base64
import com.psycheai.companion.security.FortressKeystoreManager
import com.psycheai.companion.storage.EncryptedOfflineQueue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.PrivateKey
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.net.ssl.SSLContext

/**
 * TLSv1.3 Mutual-TLS LAN/USB client targeting the Windows 11 PsycheGatewayService.
 * Handles 423/503 VAULT_LOCKED cleanly by holding encrypted batches in HOLD_UNTIL_UNLOCKED.
 */
class CompanionSyncClient(
    private val baseUrl: String,
    private val clientSslContext: SSLContext,
    private val trustManager: javax.net.ssl.X509TrustManager,
    private val keystoreManager: FortressKeystoreManager = FortressKeystoreManager(),
) {

    companion object {
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
    }

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(clientSslContext.socketFactory, trustManager)
        .build()

    sealed class SyncResult {
        data class Delivered(val payload: JSONObject) : SyncResult()
        data class VaultLockedHold(val statusCode: Int, val message: String) : SyncResult()
        data class HttpError(val statusCode: Int, val body: String) : SyncResult()
    }

    fun getHealth(): SyncResult = executeGet("/v1/health")

    fun postPairInit(windowsTlsSha256: String): SyncResult {
        val body = JSONObject().apply {
            put("windows_host_endpoint", baseUrl)
            put("windows_tls_cert_sha256", windowsTlsSha256)
            put("ttl_seconds", 300)
        }
        return executePost("/v1/pair/init", body)
    }

    fun postPairConfirm(confirmPayload: JSONObject, userConfirmedSas6Digit: String): SyncResult {
        val req = Request.Builder()
            .url("${baseUrl.trimEnd('/')}/v1/pair/confirm")
            .addHeader("X-User-Confirmed-SAS", userConfirmedSas6Digit)
            .post(confirmPayload.toString().toRequestBody(JSON_MEDIA))
            .build()
        return dispatchRequest(req)
    }

    fun postContactsSync(signedContactSync: JSONObject): SyncResult =
        executePost("/v1/contacts/sync", signedContactSync)

    fun postNotificationBatch(signedBatch: JSONObject): SyncResult =
        executePost("/v1/notifications/ingest", signedBatch)

    fun postPresenceHeartbeat(
        deviceId: String,
        presenceState: String,
        pendingQueueCount: Int,
        batteryPercent: Int,
        ed25519PrivateKey: PrivateKey,
    ): SyncResult {
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val canonical = keystoreManager.canonicalPresenceHeartbeatBytes(
            deviceId = deviceId,
            timestampUtc = nowUtc,
            userPresenceState = presenceState,
            pendingQueueCount = pendingQueueCount,
        )
        val sigB64 = keystoreManager.ed25519SignB64(ed25519PrivateKey, canonical)
        val payload = JSONObject().apply {
            put("schema_version", "1.0.0")
            put("device_id", deviceId)
            put("timestamp_utc", nowUtc)
            put("user_presence_state", presenceState)
            put("dnd_active", false)
            put("pending_queue_count", pendingQueueCount)
            put("battery_percent", batteryPercent)
            put("ed25519_signature", sigB64)
        }
        return executePost("/v1/presence/heartbeat", payload)
    }

    fun requestSynthesisForEvent(eventId: String): SyncResult =
        executePost("/v1/syntheses/$eventId", JSONObject())

    fun submitSynthesisReview(
        synthesisId: String,
        decision: String,
        userFinalEditedText: String? = null,
    ): SyncResult {
        val body = JSONObject().apply {
            put("decision", decision)
            put("requires_user_review", REQUIRES_USER_REVIEW)
            put("auto_send_permitted", AUTO_SEND_PERMITTED)
            if (userFinalEditedText != null) {
                put("user_final_edited_text", userFinalEditedText)
            }
        }
        return executePost("/v1/syntheses/$synthesisId/review", body)
    }

    /**
     * Flushes encrypted offline batches once Windows Desktop Gateway returns healthy & unlocked.
     * Signs each queued batch and transitions queue to HOLD_UNTIL_UNLOCKED if Windows returns 423/503.
     */
    fun flushOfflineQueue(
        queue: EncryptedOfflineQueue,
        deviceId: String,
        ed25519PrivateKey: PrivateKey,
    ): Int {
        var flushed = 0
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        for (item in queue.peekPendingBatches()) {
            val batch = JSONObject(item.payloadJson)
            batch.put("device_id", deviceId)
            batch.put("sent_at_utc", nowUtc)
            val events = batch.getJSONArray("events")
            val eventPairs = mutableListOf<Pair<String, String>>()
            for (i in 0 until events.length()) {
                val ev = events.getJSONObject(i)
                val evId = ev.getString("event_id")
                val pkg = ev.getString("package_name")
                val convKey = ev.getString("conversation_key")
                val postedAt = ev.getString("posted_at_utc")
                val sha256 = ev.getJSONObject("content").getString("raw_text_sha256")
                val evCanonical = keystoreManager.canonicalEventBytes(evId, pkg, convKey, sha256, postedAt)
                ev.getJSONObject("security").put(
                    "ed25519_event_signature",
                    keystoreManager.ed25519SignB64(ed25519PrivateKey, evCanonical),
                )
                eventPairs += (evId to sha256)
            }
            val batchCanonical = keystoreManager.canonicalBatchBytes(
                batchId = batch.getString("batch_id"),
                deviceId = deviceId,
                sentAtUtc = nowUtc,
                eventPairs = eventPairs,
            )
            batch.put("batch_ed25519_signature", keystoreManager.ed25519SignB64(ed25519PrivateKey, batchCanonical))

            when (postNotificationBatch(batch)) {
                is SyncResult.Delivered -> {
                    queue.ackBatch(item.batchId)
                    flushed++
                }
                is SyncResult.VaultLockedHold -> {
                    queue.markAllHoldUntilUnlocked()
                    return flushed
                }
                is SyncResult.HttpError -> return flushed
            }
        }
        return flushed
    }

    private fun executeGet(path: String): SyncResult {
        val req = Request.Builder().url("${baseUrl.trimEnd('/')}$path").get().build()
        return dispatchRequest(req)
    }

    private fun executePost(path: String, body: JSONObject): SyncResult {
        val req = Request.Builder()
            .url("${baseUrl.trimEnd('/')}$path")
            .post(body.toString().toRequestBody(JSON_MEDIA))
            .build()
        return dispatchRequest(req)
    }

    private fun dispatchRequest(req: Request): SyncResult {
        httpClient.newCall(req).execute().use { resp ->
            val raw = resp.body?.string().orEmpty()
            val json = if (raw.isNotBlank()) runCatching { JSONObject(raw) }.getOrNull() else null
            if (resp.isSuccessful) {
                return SyncResult.Delivered(json ?: JSONObject())
            }
            val errCode = json?.optString("error_code", "").orEmpty()
            if (resp.code == 423 || resp.code == 503 || errCode == "VAULT_LOCKED") {
                return SyncResult.VaultLockedHold(
                    statusCode = resp.code,
                    message = json?.optString("detail", "VAULT_LOCKED") ?: "VAULT_LOCKED",
                )
            }
            return SyncResult.HttpError(resp.code, raw)
        }
    }
}
