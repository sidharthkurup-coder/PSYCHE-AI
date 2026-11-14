package com.psycheai.companion.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Hardware-backed Android Keystore AES-256-GCM key protection plus
 * Ed25519/X25519 pairing, HKDF-SHA256 6-digit SAS derivation, and canonical signing.
 */
class FortressKeystoreManager {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val QUEUE_KEY_ALIAS = "psyche_fortress_offline_queue_v1"
        private const val PAIRING_PREFS = "psyche_fortress_pairing_v1"
        private const val PREF_IDENTITY_IV = "identity_iv_b64"
        private const val PREF_IDENTITY_CT = "identity_ct_b64"
        private const val PREF_PAIRING_GATEWAY_URL = "gateway_url"
        private const val PREF_PAIRING_TLS_SHA256 = "windows_tls_sha256"
        private const val PREF_PAIRED_FLAG = "is_paired"
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_LEN = 12

        // 12-byte ASN.1 SubjectPublicKeyInfo headers for 32-byte raw public keys
        private val X25519_SPKI_PREFIX = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
        )
        private val ED25519_SPKI_PREFIX = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        )
    }

    private val bcProvider = BouncyCastleProvider()
    private val secureRandom = SecureRandom()

    data class EncryptedPayload(val ivB64: String, val ciphertextB64: String)

    data class DeviceIdentity(
        val deviceId: String,
        val ed25519PrivateKey: PrivateKey,
        val ed25519PublicKeyB64: String,
    )

    data class PairingState(
        val paired: Boolean,
        val gatewayUrl: String,
        val windowsTlsSha256: String,
        val identity: DeviceIdentity?,
    )

    private fun getOrCreateQueueAesKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = ks.getKey(QUEUE_KEY_ALIAS, null) as? SecretKey
        if (existing != null) {
            return existing
        }
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            QUEUE_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    fun encryptForOfflineQueue(plaintextUtf8: String, aadUtf8: String = "psyche_offline_queue"): EncryptedPayload {
        val key = getOrCreateQueueAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aadUtf8.toByteArray(StandardCharsets.UTF_8))
        val sealed = cipher.doFinal(plaintextUtf8.toByteArray(StandardCharsets.UTF_8))
        val iv = cipher.iv
        require(iv.size == GCM_IV_LEN) { "Expected 12-byte GCM IV" }
        return EncryptedPayload(
            ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP),
            ciphertextB64 = Base64.encodeToString(sealed, Base64.NO_WRAP),
        )
    }

    fun decryptFromOfflineQueue(ivB64: String, ciphertextB64: String, aadUtf8: String = "psyche_offline_queue"): String {
        val key = getOrCreateQueueAesKey()
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)
        val sealed = Base64.decode(ciphertextB64, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(aadUtf8.toByteArray(StandardCharsets.UTF_8))
        val plaintext = cipher.doFinal(sealed)
        return String(plaintext, StandardCharsets.UTF_8)
    }

    fun generateUuidV7(): String {
        val tsMs = System.currentTimeMillis()
        val randomBytes = ByteArray(10)
        secureRandom.nextBytes(randomBytes)
        val msb = (tsMs shl 16) or
            0x7000L or
            (((randomBytes[0].toLong() and 0x0F) shl 8) or (randomBytes[1].toLong() and 0xFF))
        val lsbRand = ByteBuffer.wrap(randomBytes, 2, 8).long
        val lsb = (lsbRand and 0x3FFFFFFFFFFFFFFFL) or Long.MIN_VALUE
        return UUID(msb, lsb).toString()
    }

    fun generateEd25519KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("Ed25519", bcProvider)
        return kpg.generateKeyPair()
    }

    fun generateX25519KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519", bcProvider)
        return kpg.generateKeyPair()
    }

    fun exportRawPublicKeyB64(publicKey: PublicKey): String {
        val encoded = publicKey.encoded
        val raw = if (encoded.size == 44) encoded.copyOfRange(12, 44) else encoded
        return Base64.encodeToString(raw, Base64.NO_WRAP)
    }

    fun decodePublicKey(algorithm: String, keyB64: String): PublicKey {
        val decoded = Base64.decode(keyB64, Base64.NO_WRAP)
        val spkiBytes = if (decoded.size == 32) {
            val prefix = if (algorithm.equals("X25519", ignoreCase = true)) {
                X25519_SPKI_PREFIX
            } else {
                ED25519_SPKI_PREFIX
            }
            prefix + decoded
        } else {
            decoded
        }
        val kf = KeyFactory.getInstance(algorithm, bcProvider)
        return kf.generatePublic(X509EncodedKeySpec(spkiBytes))
    }

    fun deriveX25519SharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519", bcProvider)
        ka.init(privateKey)
        ka.doPhase(peerPublicKey, true)
        return ka.generateSecret()
    }

    fun ed25519SignB64(privateKey: PrivateKey, messageBytes: ByteArray): String {
        val sig = Signature.getInstance("Ed25519", bcProvider)
        sig.initSign(privateKey)
        sig.update(messageBytes)
        return Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
    }

    fun sha256Hex(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val expandMac = Mac.getInstance("HmacSHA256")
            expandMac.init(SecretKeySpec(prk, "HmacSHA256"))
            expandMac.update(t)
            expandMac.update(info)
            expandMac.update(counter.toByte())
            t = expandMac.doFinal()
            val copyLen = minOf(t.size, length - offset)
            System.arraycopy(t, 0, okm, offset, copyLen)
            offset += copyLen
            counter++
        }
        return okm
    }

    fun deriveSas6DigitAndHmac(
        sharedSecret: ByteArray,
        pairingNonce: ByteArray,
        windowsTlsCertSha256: String,
        androidEd25519PubB64: String,
        pairingSessionId: String,
    ): Pair<String, String> {
        val info = "PSYCHE-SAS-v1|$windowsTlsCertSha256|$androidEd25519PubB64".toByteArray(StandardCharsets.UTF_8)
        val okm = hkdfSha256(sharedSecret, pairingNonce, info, 32)
        val value = ((okm[0].toLong() and 0xFF) shl 24) or
            ((okm[1].toLong() and 0xFF) shl 16) or
            ((okm[2].toLong() and 0xFF) shl 8) or
            (okm[3].toLong() and 0xFF)
        val sas6Digit = "%06d".format(value % 1_000_000L)
        val confirmMsg = "SAS-CONFIRM:$sas6Digit:$pairingSessionId".toByteArray(StandardCharsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(okm, "HmacSHA256"))
        val hmacB64 = Base64.encodeToString(mac.doFinal(confirmMsg), Base64.NO_WRAP)
        return sas6Digit to hmacB64
    }

    fun canonicalEventBytes(
        eventId: String,
        packageName: String,
        conversationKey: String,
        rawTextSha256: String,
        postedAtUtc: String,
    ): ByteArray {
        return "$eventId|$packageName|$conversationKey|$rawTextSha256|$postedAtUtc"
            .toByteArray(StandardCharsets.UTF_8)
    }

    fun canonicalBatchBytes(
        batchId: String,
        deviceId: String,
        sentAtUtc: String,
        eventPairs: List<Pair<String, String>>,
    ): ByteArray {
        val eventDigestSrc = eventPairs.joinToString("|") { "${it.first}:${it.second}" }
        val eventsSha256 = sha256Hex(eventDigestSrc)
        return "$batchId|$deviceId|$sentAtUtc|$eventsSha256".toByteArray(StandardCharsets.UTF_8)
    }

    fun canonicalContactSyncBytes(
        syncBatchId: String,
        deviceId: String,
        sentAtUtc: String,
        contactCount: Int,
    ): ByteArray {
        return "$syncBatchId|$deviceId|$sentAtUtc|$contactCount".toByteArray(StandardCharsets.UTF_8)
    }

    fun canonicalPairingConfirmBytes(
        pairingSessionId: String,
        deviceId: String,
        androidEd25519PubB64: String,
        androidX25519EphemeralPubB64: String,
        androidTlsCertSha256: String,
        sasVerificationCodeHmacB64: String,
        requestedAtUtc: String,
    ): ByteArray {
        return (
            "$pairingSessionId|$deviceId|$androidEd25519PubB64|$androidX25519EphemeralPubB64|" +
                "$androidTlsCertSha256|$sasVerificationCodeHmacB64|$requestedAtUtc"
            ).toByteArray(StandardCharsets.UTF_8)
    }

    fun canonicalPresenceHeartbeatBytes(
        deviceId: String,
        timestampUtc: String,
        userPresenceState: String,
        pendingQueueCount: Int,
    ): ByteArray {
        return "$deviceId|$timestampUtc|$userPresenceState|$pendingQueueCount".toByteArray(StandardCharsets.UTF_8)
    }

    @Synchronized
    fun getOrCreateDeviceIdentity(context: Context): DeviceIdentity {
        val prefs = context.getSharedPreferences(PAIRING_PREFS, Context.MODE_PRIVATE)
        val ivB64 = prefs.getString(PREF_IDENTITY_IV, null)
        val ctB64 = prefs.getString(PREF_IDENTITY_CT, null)
        if (!ivB64.isNullOrBlank() && !ctB64.isNullOrBlank()) {
            runCatching {
                val raw = decryptFromOfflineQueue(ivB64, ctB64, aadUtf8 = "psyche_device_identity")
                val obj = JSONObject(raw)
                val privBytes = Base64.decode(obj.getString("priv_pkcs8_b64"), Base64.NO_WRAP)
                val priv = KeyFactory.getInstance("Ed25519", bcProvider)
                    .generatePrivate(PKCS8EncodedKeySpec(privBytes))
                return DeviceIdentity(
                    deviceId = obj.getString("device_id"),
                    ed25519PrivateKey = priv,
                    ed25519PublicKeyB64 = obj.getString("pub_raw_b64"),
                )
            }.onSuccess { return it }
        }

        val deviceId = generateUuidV7()
        val kp = generateEd25519KeyPair()
        val pubB64 = exportRawPublicKeyB64(kp.public)
        val privB64 = Base64.encodeToString(kp.private.encoded, Base64.NO_WRAP)
        val json = JSONObject().apply {
            put("device_id", deviceId)
            put("priv_pkcs8_b64", privB64)
            put("pub_raw_b64", pubB64)
        }.toString()
        val sealed = encryptForOfflineQueue(json, aadUtf8 = "psyche_device_identity")
        prefs.edit()
            .putString(PREF_IDENTITY_IV, sealed.ivB64)
            .putString(PREF_IDENTITY_CT, sealed.ciphertextB64)
            .apply()
        return DeviceIdentity(
            deviceId = deviceId,
            ed25519PrivateKey = kp.private,
            ed25519PublicKeyB64 = pubB64,
        )
    }

    @Synchronized
    fun savePairingState(context: Context, gatewayUrl: String, windowsTlsSha256: String): PairingState {
        val identity = getOrCreateDeviceIdentity(context)
        val prefs = context.getSharedPreferences(PAIRING_PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putBoolean(PREF_PAIRED_FLAG, true)
            .putString(PREF_PAIRING_GATEWAY_URL, gatewayUrl.trimEnd('/'))
            .putString(PREF_PAIRING_TLS_SHA256, windowsTlsSha256.lowercase())
            .apply()
        return PairingState(
            paired = true,
            gatewayUrl = gatewayUrl.trimEnd('/'),
            windowsTlsSha256 = windowsTlsSha256.lowercase(),
            identity = identity,
        )
    }

    @Synchronized
    fun loadPairingState(context: Context): PairingState {
        val prefs = context.getSharedPreferences(PAIRING_PREFS, Context.MODE_PRIVATE)
        val paired = prefs.getBoolean(PREF_PAIRED_FLAG, false)
        val url = prefs.getString(PREF_PAIRING_GATEWAY_URL, "").orEmpty()
        val sha = prefs.getString(PREF_PAIRING_TLS_SHA256, "").orEmpty()
        val identity = if (paired || !prefs.getString(PREF_IDENTITY_CT, null).isNullOrBlank()) {
            runCatching { getOrCreateDeviceIdentity(context) }.getOrNull()
        } else {
            null
        }
        return PairingState(
            paired = paired && url.isNotBlank() && sha.length == 64 && identity != null,
            gatewayUrl = url,
            windowsTlsSha256 = sha,
            identity = identity,
        )
    }

    @Synchronized
    fun clearPairingState(context: Context) {
        val prefs = context.getSharedPreferences(PAIRING_PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putBoolean(PREF_PAIRED_FLAG, false)
            .remove(PREF_PAIRING_GATEWAY_URL)
            .remove(PREF_PAIRING_TLS_SHA256)
            .apply()
    }
}
