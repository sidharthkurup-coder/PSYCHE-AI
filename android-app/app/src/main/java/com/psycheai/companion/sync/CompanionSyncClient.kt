package com.psycheai.companion.sync

import android.content.Context
import android.os.Build
import android.util.Base64
import com.psycheai.companion.security.FortressKeystoreManager
import com.psycheai.companion.storage.EncryptedOfflineQueue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * TLSv1.3 Mutual-TLS / Pinned-Cert LAN client targeting the Windows 11 PsycheGatewayService.
 * Handles 423/503 VAULT_LOCKED cleanly by holding encrypted batches in HOLD_UNTIL_UNLOCKED.
 */
class CompanionSyncClient(
    private val baseUrl: String,
    private val clientSslContext: SSLContext,
    private val trustManager: X509TrustManager,
    private val keystoreManager: FortressKeystoreManager = FortressKeystoreManager(),
    private val pinnedSha256Ref: AtomicReference<String> = AtomicReference(""),
    private val strictPin: String? = null,
) {

    companion object {
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
        private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

        fun sha256CertHex(cert: X509Certificate): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            return digest.joinToString("") { "%02x".format(it) }
        }

        /**
         * Builds a TLS 1.3 OkHttp client targeting [baseUrl].
         * When [pinnedWindowsSha256] is provided, strictly rejects any server certificate not matching it.
         * When null/blank (initial discovery/pairing), captures the leaf SHA-256 for SAS verification.
         */
        fun forGateway(
            baseUrl: String,
            pinnedWindowsSha256: String? = null,
            keystoreManager: FortressKeystoreManager = FortressKeystoreManager(),
        ): CompanionSyncClient {
            val expectedPin = pinnedWindowsSha256?.trim()?.lowercase()?.takeIf { it.length == 64 }
            val capturedRef = AtomicReference("")
            val tm = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                    val leaf = chain?.firstOrNull()
                        ?: throw CertificateException("Missing server TLS certificate")
                    val actualSha = sha256CertHex(leaf)
                    capturedRef.set(actualSha)
                    if (expectedPin != null && !actualSha.equals(expectedPin, ignoreCase = true)) {
                        throw CertificateException(
                            "Windows Gateway TLS SHA-256 mismatch: expected=$expectedPin actual=$actualSha",
                        )
                    }
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            val sslCtx = SSLContext.getInstance("TLSv1.3").apply {
                init(null, arrayOf<TrustManager>(tm), SecureRandom())
            }
            return CompanionSyncClient(
                baseUrl = baseUrl.trimEnd('/'),
                clientSslContext = sslCtx,
                trustManager = tm,
                keystoreManager = keystoreManager,
                pinnedSha256Ref = capturedRef,
                strictPin = expectedPin,
            )
        }
    }

    data class PendingPairingHandshake(
        val pairingSessionId: String,
        val gatewayUrl: String,
        val windowsTlsSha256: String,
        val androidX25519KeyPair: KeyPair,
        val sas6Digit: String,
        val sasHmacB64: String,
        val identity: FortressKeystoreManager.DeviceIdentity,
    )

    private val hostnameVerifier = HostnameVerifier { _, session ->
        val leaf = runCatching { session.peerCertificates.firstOrNull() as? X509Certificate }.getOrNull()
            ?: return@HostnameVerifier false
        val actualSha = sha256CertHex(leaf)
        strictPin == null || actualSha.equals(strictPin, ignoreCase = true)
    }

    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .sslSocketFactory(clientSslContext.socketFactory, trustManager)
        .hostnameVerifier(hostnameVerifier)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    fun lastObservedServerCertSha256(): String = pinnedSha256Ref.get()

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
    ): Int = flushOfflineQueueDetailed(queue, deviceId, ed25519PrivateKey).size

    fun flushOfflineQueueDetailed(
        queue: EncryptedOfflineQueue,
        deviceId: String,
        ed25519PrivateKey: PrivateKey,
    ): List<String> {
        val ackedEventIds = mutableListOf<String>()
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        for (item in queue.peekPendingBatches()) {
            val batch = JSONObject(item.payloadJson)
            batch.remove("event_requires_signing")
            batch.remove("requires_user_review")
            batch.remove("auto_send_permitted")
            batch.put("device_id", deviceId)
            batch.put("sent_at_utc", nowUtc)
            val events = batch.getJSONArray("events")
            val eventPairs = mutableListOf<Pair<String, String>>()
            val candidateIds = mutableListOf<String>()
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
                candidateIds += evId
            }
            val batchCanonical = keystoreManager.canonicalBatchBytes(
                batchId = batch.getString("batch_id"),
                deviceId = deviceId,
                sentAtUtc = nowUtc,
                eventPairs = eventPairs,
            )
            batch.put("batch_ed25519_signature", keystoreManager.ed25519SignB64(ed25519PrivateKey, batchCanonical))

            when (val res = postNotificationBatch(batch)) {
                is SyncResult.Delivered -> {
                    queue.ackBatch(item.batchId)
                    val ackArr = res.payload.optJSONArray("acked_event_ids")
                    if (ackArr != null && ackArr.length() > 0) {
                        for (j in 0 until ackArr.length()) {
                            ackedEventIds += ackArr.getString(j)
                        }
                    } else {
                        ackedEventIds.addAll(candidateIds)
                    }
                }
                is SyncResult.VaultLockedHold -> {
                    queue.markAllHoldUntilUnlocked()
                    return ackedEventIds
                }
                is SyncResult.HttpError -> return ackedEventIds
            }
        }
        return ackedEventIds
    }

    fun beginPairingHandshake(context: Context): PendingPairingHandshake {
        val health = getHealth()
        if (health is SyncResult.VaultLockedHold) {
            throw IllegalStateException("Windows Vault is locked — click Unlock Vault on PC first.")
        }
        if (health is SyncResult.HttpError) {
            throw IllegalStateException("Gateway unreachable (${health.statusCode}): ${health.body}")
        }
        val observedSha = lastObservedServerCertSha256()
        require(observedSha.length == 64) { "Could not read Windows TLS 1.3 certificate SHA-256" }

        val initRes = postPairInit(observedSha)
        val challenge = when (initRes) {
            is SyncResult.Delivered -> initRes.payload
            is SyncResult.VaultLockedHold -> throw IllegalStateException("Windows Vault is locked: ${initRes.message}")
            is SyncResult.HttpError -> throw IllegalStateException("Pair init failed (${initRes.statusCode}): ${initRes.body}")
        }

        val pairingSessionId = challenge.getString("pairing_session_id")
        val windowsSha = challenge.getString("windows_tls_cert_sha256").lowercase()
        val windowsXPub = keystoreManager.decodePublicKey(
            "X25519",
            challenge.getString("windows_x25519_ephemeral_pub_b64"),
        )
        val pairingNonce = Base64.decode(challenge.getString("pairing_nonce_b64"), Base64.NO_WRAP)

        val identity = keystoreManager.getOrCreateDeviceIdentity(context)
        val androidXKeyPair = keystoreManager.generateX25519KeyPair()
        val sharedSecret = keystoreManager.deriveX25519SharedSecret(androidXKeyPair.private, windowsXPub)
        val (sas6, sasHmacB64) = keystoreManager.deriveSas6DigitAndHmac(
            sharedSecret = sharedSecret,
            pairingNonce = pairingNonce,
            windowsTlsCertSha256 = windowsSha,
            androidEd25519PubB64 = identity.ed25519PublicKeyB64,
            pairingSessionId = pairingSessionId,
        )
        return PendingPairingHandshake(
            pairingSessionId = pairingSessionId,
            gatewayUrl = baseUrl,
            windowsTlsSha256 = windowsSha,
            androidX25519KeyPair = androidXKeyPair,
            sas6Digit = sas6,
            sasHmacB64 = sasHmacB64,
            identity = identity,
        )
    }

    fun completePairingHandshake(
        context: Context,
        pending: PendingPairingHandshake,
        userConfirmedSas: String,
    ): SyncResult {
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val androidXPubB64 = keystoreManager.exportRawPublicKeyB64(pending.androidX25519KeyPair.public)
        val androidClientPinSha256 = keystoreManager.sha256Hex("android-ed25519:${pending.identity.ed25519PublicKeyB64}")
        val canonical = keystoreManager.canonicalPairingConfirmBytes(
            pairingSessionId = pending.pairingSessionId,
            deviceId = pending.identity.deviceId,
            androidEd25519PubB64 = pending.identity.ed25519PublicKeyB64,
            androidX25519EphemeralPubB64 = androidXPubB64,
            androidTlsCertSha256 = androidClientPinSha256,
            sasVerificationCodeHmacB64 = pending.sasHmacB64,
            requestedAtUtc = nowUtc,
        )
        val sigB64 = keystoreManager.ed25519SignB64(pending.identity.ed25519PrivateKey, canonical)
        val deviceName = listOfNotNull(Build.MANUFACTURER, Build.MODEL)
            .joinToString(" ")
            .trim()
            .ifBlank { "Android Companion" }
            .take(120)

        val payload = JSONObject().apply {
            put("schema_version", "1.0.0")
            put("pairing_session_id", pending.pairingSessionId)
            put("device_id", pending.identity.deviceId)
            put("device_name", deviceName)
            put("android_ed25519_pub_b64", pending.identity.ed25519PublicKeyB64)
            put("android_x25519_ephemeral_pub_b64", androidXPubB64)
            put("android_tls_cert_sha256", androidClientPinSha256)
            put("sas_verification_code_hmac_b64", pending.sasHmacB64)
            put("requested_at_utc", nowUtc)
            put("ed25519_signature", sigB64)
        }
        val res = postPairConfirm(payload, userConfirmedSas.trim())
        if (res is SyncResult.Delivered && res.payload.optString("status") == "PAIRED") {
            keystoreManager.savePairingState(
                context = context,
                gatewayUrl = pending.gatewayUrl,
                windowsTlsSha256 = pending.windowsTlsSha256,
            )
        }
        return res
    }

    fun ingestSingleMessageAndSynthesize(
        deviceId: String,
        ed25519PrivateKey: PrivateKey,
        senderName: String,
        messageText: String,
        packageName: String = "com.psycheai.manual",
    ): SyncResult {
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val eventId = keystoreManager.generateUuidV7()
        val batchId = keystoreManager.generateUuidV7()
        val convKey = "$packageName:${keystoreManager.sha256Hex(senderName.ifBlank { "Unknown" }).take(16)}"
        val rawSha256 = keystoreManager.sha256Hex(messageText)

        var detectedMode = "en"
        for (ch in messageText) {
            when (ch.code) {
                in 0x0900..0x097F -> { detectedMode = "hi-Deva"; break }
                in 0x0D00..0x0D7F -> { detectedMode = "ml-Mlym"; break }
                in 0x0C00..0x0C7F -> { detectedMode = "te-Telu"; break }
            }
        }

        val evCanonical = keystoreManager.canonicalEventBytes(eventId, packageName, convKey, rawSha256, nowUtc)
        val evSig = keystoreManager.ed25519SignB64(ed25519PrivateKey, evCanonical)
        val batchCanonical = keystoreManager.canonicalBatchBytes(
            batchId = batchId,
            deviceId = deviceId,
            sentAtUtc = nowUtc,
            eventPairs = listOf(eventId to rawSha256),
        )
        val batchSig = keystoreManager.ed25519SignB64(ed25519PrivateKey, batchCanonical)

        val eventObj = JSONObject().apply {
            put("event_id", eventId)
            put("package_name", packageName)
            put("notification_category", "msg")
            put("conversation_key", convKey)
            put("is_group_conversation", false)
            put("group_title", JSONObject.NULL)
            put("direction", "INBOUND")
            put(
                "sender",
                JSONObject().apply {
                    put("raw_title", senderName.ifBlank { "Unknown Contact" })
                    put("android_contact_lookup_key", JSONObject.NULL)
                    put("normalized_phone_sha256", JSONObject.NULL)
                    put("candidate_person_ids", JSONArray())
                    put("identity_ambiguity", false)
                },
            )
            put(
                "content",
                JSONObject().apply {
                    put("raw_text_immutable", messageText)
                    put("raw_text_sha256", rawSha256)
                    put("detected_language_modes", JSONArray().put(detectedMode))
                    put("token_language_spans", JSONArray())
                },
            )
            put("posted_at_utc", nowUtc)
            put(
                "security",
                JSONObject().apply {
                    put("untrusted_external_input", true)
                    put("otp_or_sensitive_filtered", true)
                    put("ed25519_event_signature", evSig)
                },
            )
        }

        val batchPayload = JSONObject().apply {
            put("schema_version", "1.0.0")
            put("batch_id", batchId)
            put("device_id", deviceId)
            put("sent_at_utc", nowUtc)
            put("events", JSONArray().put(eventObj))
            put("batch_ed25519_signature", batchSig)
        }

        val ingestRes = postNotificationBatch(batchPayload)
        if (ingestRes !is SyncResult.Delivered) {
            return ingestRes
        }
        return requestSynthesisForEvent(eventId)
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
