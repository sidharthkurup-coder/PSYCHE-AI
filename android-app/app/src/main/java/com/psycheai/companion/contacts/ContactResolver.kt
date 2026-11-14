package com.psycheai.companion.contacts

import android.content.ContentResolver
import android.provider.ContactsContract
import com.psycheai.companion.security.FortressKeystoreManager
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Resolves Android ContactsContract entries into privacy-preserving ContactSyncRequest batches
 * using SHA-256 E.164 phone hashes and Unicode script detection for Hindi/Malayalam/Telugu/English.
 */
class ContactResolver(
    private val contentResolver: ContentResolver,
    private val keystoreManager: FortressKeystoreManager = FortressKeystoreManager(),
) {

    data class ResolvedContact(
        val lookupKey: String,
        val displayName: String,
        val normalizedPhoneHashes: List<String>,
        val languageMode: String,
        val starred: Boolean,
    )

    fun detectScriptLanguageMode(text: String): String {
        for (ch in text) {
            val cp = ch.code
            when (cp) {
                in 0x0900..0x097F -> return "hi-Deva"
                in 0x0D00..0x0D7F -> return "ml-Mlym"
                in 0x0C00..0x0C7F -> return "te-Telu"
            }
        }
        return "en"
    }

    fun normalizeAndHashPhone(rawNumber: String): String {
        val cleaned = buildString {
            rawNumber.forEachIndexed { idx, ch ->
                if (ch.isDigit() || (idx == 0 && ch == '+')) append(ch)
            }
        }
        return keystoreManager.sha256Hex(cleaned)
    }

    fun readDeviceContacts(limit: Int = 500): List<ResolvedContact> {
        val byLookup = linkedMapOf<String, Triple<String, MutableSet<String>, Boolean>>()
        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Phone.LOOKUP_KEY,
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME_PRIMARY,
            ContactsContract.CommonDataKinds.Phone.NUMBER,
            ContactsContract.CommonDataKinds.Phone.STARRED,
        )
        contentResolver.query(
            ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
            projection,
            null,
            null,
            "${ContactsContract.CommonDataKinds.Phone.STARRED} DESC, ${ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME_PRIMARY} ASC",
        )?.use { cursor ->
            val idxLookup = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.LOOKUP_KEY)
            val idxName = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME_PRIMARY)
            val idxNum = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            val idxStarred = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.STARRED)
            while (cursor.moveToNext() && byLookup.size < limit) {
                val lookup = cursor.getString(idxLookup) ?: continue
                val name = cursor.getString(idxName)?.trim().orEmpty()
                if (name.isEmpty()) continue
                val phone = cursor.getString(idxNum)?.trim().orEmpty()
                val starred = cursor.getInt(idxStarred) == 1
                val entry = byLookup.getOrPut(lookup) { Triple(name, linkedSetOf(), starred) }
                if (phone.isNotEmpty()) {
                    entry.second += normalizeAndHashPhone(phone)
                }
            }
        }
        return byLookup.map { (lookup, triple) ->
            ResolvedContact(
                lookupKey = lookup,
                displayName = triple.first,
                normalizedPhoneHashes = triple.second.toList(),
                languageMode = detectScriptLanguageMode(triple.first),
                starred = triple.third,
            )
        }
    }

    fun buildSignedContactSyncJson(
        deviceId: String,
        contacts: List<ResolvedContact>,
        ed25519PrivateKey: java.security.PrivateKey,
    ): JSONObject {
        val nowUtc = DateTimeFormatter.ISO_INSTANT.withZone(ZoneOffset.UTC).format(Instant.now())
        val syncBatchId = keystoreManager.generateUuidV7()
        val contactsArray = JSONArray()
        contacts.forEach { c ->
            contactsArray.put(
                JSONObject().apply {
                    put("android_contact_lookup_key", c.lookupKey)
                    put("display_name", c.displayName)
                    put("normalized_phone_hashes", JSONArray(c.normalizedPhoneHashes))
                    put(
                        "aliases",
                        JSONArray().put(
                            JSONObject().apply {
                                put("alias_text", c.displayName)
                                put("language_mode", c.languageMode)
                                put("match_confidence", 0.98)
                            }
                        ),
                    )
                    put("starred_on_android", c.starred)
                    put("updated_at_utc", nowUtc)
                }
            )
        }

        val canonical = keystoreManager.canonicalContactSyncBytes(
            syncBatchId = syncBatchId,
            deviceId = deviceId,
            sentAtUtc = nowUtc,
            contactCount = contacts.size,
        )
        val sigB64 = keystoreManager.ed25519SignB64(ed25519PrivateKey, canonical)
        return JSONObject().apply {
            put("schema_version", "1.0.0")
            put("sync_batch_id", syncBatchId)
            put("device_id", deviceId)
            put("sent_at_utc", nowUtc)
            put("ed25519_signature", sigB64)
            put("contacts", contactsArray)
        }
    }
}
