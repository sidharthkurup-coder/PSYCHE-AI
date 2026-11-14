package com.psycheai.companion.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
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
        private const val GCM_TAG_BITS = 128
        private const val GCM_IV_LEN = 12
    }

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

    data class EncryptedPayload(val ivB64: String, val ciphertextB64: String)

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

    fun generateEd25519KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("Ed25519")
        return kpg.generateKeyPair()
    }

    fun generateX25519KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519")
        return kpg.generateKeyPair()
    }

    fun deriveX25519SharedSecret(privateKey: PrivateKey, peerPublicKey: java.security.PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privateKey)
        ka.doPhase(peerPublicKey, true)
        return ka.generateSecret()
    }

    fun ed25519SignB64(privateKey: PrivateKey, messageBytes: ByteArray): String {
        val sig = Signature.getInstance("Ed25519")
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

    fun canonicalPresenceHeartbeatBytes(
        deviceId: String,
        timestampUtc: String,
        userPresenceState: String,
        pendingQueueCount: Int,
    ): ByteArray {
        return "$deviceId|$timestampUtc|$userPresenceState|$pendingQueueCount".toByteArray(StandardCharsets.UTF_8)
    }
}
