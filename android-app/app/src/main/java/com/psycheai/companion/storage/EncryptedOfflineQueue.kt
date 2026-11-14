package com.psycheai.companion.storage

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.psycheai.companion.security.FortressKeystoreManager

/**
 * Bounded, AES-256-GCM encrypted SQLite offline queue holding pending notification batches
 * when Wi-Fi/LAN connectivity is unavailable or Windows returns VAULT_LOCKED (HOLD_UNTIL_UNLOCKED).
 * Never stores plaintext message text in SQLite.
 */
class EncryptedOfflineQueue(
    context: Context,
    private val keystoreManager: FortressKeystoreManager = FortressKeystoreManager(),
    private val maxQueueItems: Int = 500,
) : SQLiteOpenHelper(context, "psyche_offline_queue.db", null, 1) {

    data class QueuedBatch(
        val batchId: String,
        val payloadJson: String,
        val state: String,
        val createdAtEpochMs: Long,
    )

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS offline_queue (
                batch_id TEXT PRIMARY KEY,
                iv_b64 TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                sync_state TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun enqueueEncryptedBatch(batchId: String, payloadJson: String, syncState: String = "PENDING") {
        val sealed = keystoreManager.encryptForOfflineQueue(payloadJson, aadUtf8 = batchId)
        val db = writableDatabase
        db.beginTransaction()
        try {
            val values = ContentValues().apply {
                put("batch_id", batchId)
                put("iv_b64", sealed.ivB64)
                put("ciphertext_b64", sealed.ciphertextB64)
                put("sync_state", syncState)
                put("created_at_ms", System.currentTimeMillis())
            }
            db.insertWithOnConflict("offline_queue", null, values, SQLiteDatabase.CONFLICT_REPLACE)

            // Enforce bounded retention (oldest evicted first)
            db.execSQL(
                """
                DELETE FROM offline_queue
                WHERE batch_id IN (
                    SELECT batch_id FROM offline_queue
                    ORDER BY created_at_ms DESC
                    LIMIT -1 OFFSET ?
                )
                """.trimIndent(),
                arrayOf(maxQueueItems.toString()),
            )
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun markAllHoldUntilUnlocked() {
        val values = ContentValues().apply { put("sync_state", "HOLD_UNTIL_UNLOCKED") }
        writableDatabase.update("offline_queue", values, null, null)
    }

    fun peekPendingBatches(): List<QueuedBatch> {
        val results = mutableListOf<QueuedBatch>()
        val cursor = readableDatabase.rawQuery(
            "SELECT batch_id, iv_b64, ciphertext_b64, sync_state, created_at_ms FROM offline_queue ORDER BY created_at_ms ASC",
            null,
        )
        cursor.use {
            while (it.moveToNext()) {
                val batchId = it.getString(0)
                val ivB64 = it.getString(1)
                val ctB64 = it.getString(2)
                val state = it.getString(3)
                val created = it.getLong(4)
                val plaintextJson = keystoreManager.decryptFromOfflineQueue(ivB64, ctB64, aadUtf8 = batchId)
                results += QueuedBatch(batchId, plaintextJson, state, created)
            }
        }
        return results
    }

    fun ackBatch(batchId: String) {
        writableDatabase.delete("offline_queue", "batch_id = ?", arrayOf(batchId))
    }

    fun count(): Int {
        readableDatabase.rawQuery("SELECT COUNT(*) FROM offline_queue", null).use { c ->
            return if (c.moveToFirst()) c.getInt(0) else 0
        }
    }

    fun panicWipeQueue() {
        writableDatabase.delete("offline_queue", null, null)
    }
}
