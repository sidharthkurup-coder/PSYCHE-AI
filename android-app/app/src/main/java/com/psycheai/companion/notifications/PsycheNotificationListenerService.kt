package com.psycheai.companion.notifications

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.psycheai.companion.security.FortressKeystoreManager
import com.psycheai.companion.security.SensitiveNotificationFilter
import com.psycheai.companion.storage.EncryptedOfflineQueue
import com.psycheai.companion.sync.CompanionSyncClient
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Passive NotificationListenerService constrained strictly to allowlisted messaging packages.
 * Runs SensitiveNotificationFilter BEFORE persistence or transmission; never acts autonomously.
 */
class PsycheNotificationListenerService : NotificationListenerService() {

    companion object {
        val droppedSensitiveCounter = AtomicInteger(0)
        val capturedEventCounter = AtomicInteger(0)
        val deliveredEventCounter = AtomicInteger(0)
        val lastSyncStatus = AtomicReference("Listening passively for allowlisted notifications.")
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
        private val VALID_CATEGORIES = setOf("msg", "call", "email", "social", "system_allowed")
    }

    private lateinit var offlineQueue: EncryptedOfflineQueue
    private val keystoreManager = FortressKeystoreManager()
    private val syncExecutor = Executors.newSingleThreadExecutor()

    override fun onCreate() {
        super.onCreate()
        offlineQueue = EncryptedOfflineQueue(applicationContext, keystoreManager)
    }

    override fun onDestroy() {
        syncExecutor.shutdown()
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return
        val pkg = sbn.packageName ?: return
        if (!SensitiveNotificationFilter.isPackageAllowed(pkg)) {
            return
        }

        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim().orEmpty()
        val body = (
            extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
                ?: extras.getCharSequence(Notification.EXTRA_TEXT)
            )?.toString()?.trim().orEmpty()

        if (title.isEmpty() || body.isEmpty()) {
            return
        }

        // Pre-persistence OTP / banking / Aadhaar / authenticator filter
        if (SensitiveNotificationFilter.isSensitiveOrOtpNotification(body, pkg)) {
            droppedSensitiveCounter.incrementAndGet()
            return
        }

        val eventId = keystoreManager.generateUuidV7()
        val batchId = keystoreManager.generateUuidV7()
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val isGroup = extras.getBoolean(Notification.EXTRA_IS_GROUP_CONVERSATION, false)
        val convTitle = extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)?.toString()
        val threadLabel = if (isGroup && !convTitle.isNullOrBlank()) convTitle else title
        val convKey = "$pkg:${keystoreManager.sha256Hex(threadLabel).take(16)}"
        val sha256 = keystoreManager.sha256Hex(body)
        val rawCategory = sbn.notification.category
        val validCategory = if (rawCategory in VALID_CATEGORIES) rawCategory!! else "msg"

        val eventObj = JSONObject().apply {
            put("event_id", eventId)
            put("package_name", pkg)
            put("notification_category", validCategory)
            put("conversation_key", convKey)
            put("is_group_conversation", isGroup)
            put("group_title", if (isGroup && !convTitle.isNullOrBlank()) convTitle else JSONObject.NULL)
            put("direction", "INBOUND")
            put(
                "sender",
                JSONObject().apply {
                    put("raw_title", title)
                    put("android_contact_lookup_key", JSONObject.NULL)
                    put("normalized_phone_sha256", JSONObject.NULL)
                    put("candidate_person_ids", JSONArray())
                    put("identity_ambiguity", false)
                },
            )
            put(
                "content",
                JSONObject().apply {
                    put("raw_text_immutable", body)
                    put("raw_text_sha256", sha256)
                    put("detected_language_modes", JSONArray().put(detectPrimaryScriptMode(body)))
                    put("token_language_spans", JSONArray())
                },
            )
            put("posted_at_utc", nowUtc)
            put(
                "security",
                JSONObject().apply {
                    put("untrusted_external_input", true)
                    put("otp_or_sensitive_filtered", true)
                    put("ed25519_event_signature", "")
                },
            )
        }

        val batchPayload = JSONObject().apply {
            put("schema_version", "1.0.0")
            put("batch_id", batchId)
            put("events", JSONArray().put(eventObj))
        }

        offlineQueue.enqueueEncryptedBatch(
            batchId = batchId,
            payloadJson = batchPayload.toString(),
            syncState = "PENDING",
        )
        capturedEventCounter.incrementAndGet()
        syncExecutor.execute { flushIfPaired() }
    }

    private fun flushIfPaired() {
        val state = keystoreManager.loadPairingState(applicationContext)
        val identity = state.identity
        if (!state.paired || identity == null) {
            lastSyncStatus.set("Queued encrypted locally (pair with Windows PC to sync).")
            return
        }
        runCatching {
            val client = CompanionSyncClient.forGateway(
                baseUrl = state.gatewayUrl,
                pinnedWindowsSha256 = state.windowsTlsSha256,
                keystoreManager = keystoreManager,
            )
            val ackedIds = client.flushOfflineQueueDetailed(
                queue = offlineQueue,
                deviceId = identity.deviceId,
                ed25519PrivateKey = identity.ed25519PrivateKey,
            )
            ackedIds.forEach { evId ->
                runCatching { client.requestSynthesisForEvent(evId) }
            }
            if (ackedIds.isNotEmpty()) {
                deliveredEventCounter.addAndGet(ackedIds.size)
                lastSyncStatus.set("Synced ${ackedIds.size} notification(s) to Legion 5 Pro.")
            } else {
                lastSyncStatus.set("Queued offline (Windows unreachable or Vault locked).")
            }
        }.onFailure { err ->
            lastSyncStatus.set("Queued offline: ${err.message ?: err.javaClass.simpleName}")
        }
    }

    private fun detectPrimaryScriptMode(text: String): String {
        for (ch in text) {
            when (ch.code) {
                in 0x0900..0x097F -> return "hi-Deva"
                in 0x0D00..0x0D7F -> return "ml-Mlym"
                in 0x0C00..0x0C7F -> return "te-Telu"
            }
        }
        return "en"
    }
}
