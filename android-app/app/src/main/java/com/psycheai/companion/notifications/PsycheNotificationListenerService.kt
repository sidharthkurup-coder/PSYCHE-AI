package com.psycheai.companion.notifications

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.psycheai.companion.security.FortressKeystoreManager
import com.psycheai.companion.security.SensitiveNotificationFilter
import com.psycheai.companion.storage.EncryptedOfflineQueue
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger

/**
 * Passive NotificationListenerService constrained strictly to allowlisted messaging packages.
 * Runs SensitiveNotificationFilter BEFORE persistence or transmission; never acts autonomously.
 */
class PsycheNotificationListenerService : NotificationListenerService() {

    companion object {
        val droppedSensitiveCounter = AtomicInteger(0)
        val capturedEventCounter = AtomicInteger(0)
        const val REQUIRES_USER_REVIEW = true
        const val AUTO_SEND_PERMITTED = false
    }

    private lateinit var offlineQueue: EncryptedOfflineQueue
    private val keystoreManager = FortressKeystoreManager()

    override fun onCreate() {
        super.onCreate()
        offlineQueue = EncryptedOfflineQueue(applicationContext, keystoreManager)
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

        val eventId = UUID.randomUUID().toString()
        val batchId = UUID.randomUUID().toString()
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val convKey = sbn.key ?: "$pkg:${keystoreManager.sha256Hex(title).take(12)}"
        val sha256 = keystoreManager.sha256Hex(body)
        val isGroup = extras.getBoolean(Notification.EXTRA_IS_GROUP_CONVERSATION, false)
        val convTitle = extras.getCharSequence(Notification.EXTRA_CONVERSATION_TITLE)?.toString()

        val eventObj = JSONObject().apply {
            put("event_id", eventId)
            put("package_name", pkg)
            put("notification_category", sbn.notification.category ?: "msg")
            put("conversation_key", convKey)
            put("is_group_conversation", isGroup)
            put("group_title", if (isGroup) convTitle else JSONObject.NULL)
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
            put("event_requires_signing", true)
            put("requires_user_review", REQUIRES_USER_REVIEW)
            put("auto_send_permitted", AUTO_SEND_PERMITTED)
            put("events", JSONArray().put(eventObj))
        }

        offlineQueue.enqueueEncryptedBatch(
            batchId = batchId,
            payloadJson = batchPayload.toString(),
            syncState = "PENDING",
        )
        capturedEventCounter.incrementAndGet()
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
