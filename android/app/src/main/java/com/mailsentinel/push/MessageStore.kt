package com.mailsentinel.push

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.time.Instant

data class LocalMessage(
    val messageId: String,
    val gatewayMessageId: String,
    val envelopeJson: String?,
    val expiresAtEpoch: Long,
    val shown: Boolean,
    val ackResult: String?,
    val acknowledged: Boolean,
)

class MessageStore(context: Context) : SQLiteOpenHelper(context, "encrypted_messages.db", null, 2) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE messages (
                message_id TEXT PRIMARY KEY NOT NULL,
                gateway_message_id TEXT NOT NULL,
                envelope TEXT,
                expires_at INTEGER NOT NULL,
                shown INTEGER NOT NULL DEFAULT 0,
                ack_result TEXT,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                claim_until INTEGER,
                created_at INTEGER NOT NULL
            )""".trimIndent()
        )
        db.execSQL("CREATE INDEX ix_messages_expiry ON messages(expires_at)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE messages ADD COLUMN claim_until INTEGER")
        }
    }

    fun find(messageId: String): LocalMessage? {
        readableDatabase.query(
            "messages", arrayOf("message_id", "gateway_message_id", "envelope", "expires_at", "shown", "ack_result", "acknowledged"),
            "message_id=?", arrayOf(messageId), null, null, null, "1"
        ).use { cursor ->
            if (!cursor.moveToFirst()) return null
            return LocalMessage(
                cursor.getString(0), cursor.getString(1), if (cursor.isNull(2)) null else cursor.getString(2),
                cursor.getLong(3), cursor.getInt(4) == 1, if (cursor.isNull(5)) null else cursor.getString(5), cursor.getInt(6) == 1
            )
        }
    }

    fun insertIfAbsent(gatewayMessageId: String, envelope: Envelope): Boolean {
        val values = ContentValues().apply {
            put("message_id", envelope.messageId)
            put("gateway_message_id", gatewayMessageId)
            put("envelope", envelope.toJson().toString())
            put("expires_at", Instant.parse(envelope.expiresAt).epochSecond)
            put("shown", 0)
            put("created_at", Instant.now().epochSecond)
        }
        return try {
            writableDatabase.insertOrThrow("messages", null, values)
            true
        } catch (_: SQLiteConstraintException) {
            false
        }
    }

    fun claimForProcessing(
        gatewayMessageId: String,
        envelope: Envelope,
        nowEpoch: Long = Instant.now().epochSecond,
        leaseSeconds: Long = 120,
    ): Boolean {
        val leaseUntil = nowEpoch + leaseSeconds
        val values = ContentValues().apply {
            put("message_id", envelope.messageId)
            put("gateway_message_id", gatewayMessageId)
            put("envelope", envelope.toJson().toString())
            put("expires_at", Instant.parse(envelope.expiresAt).epochSecond)
            put("shown", 0)
            put("claim_until", leaseUntil)
            put("created_at", nowEpoch)
        }
        val db = writableDatabase
        if (db.insertWithOnConflict("messages", null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L) {
            return true
        }
        val lease = ContentValues().apply { put("claim_until", leaseUntil) }
        return db.update(
            "messages",
            lease,
            "message_id=? AND ack_result IS NULL AND (claim_until IS NULL OR claim_until<=?)",
            arrayOf(envelope.messageId, nowEpoch.toString()),
        ) == 1
    }

    fun markProcessed(messageId: String, shown: Boolean, result: String) {
        val values = ContentValues().apply {
            put("shown", if (shown) 1 else 0)
            put("ack_result", result)
            putNull("claim_until")
        }
        writableDatabase.update("messages", values, "message_id=?", arrayOf(messageId))
    }

    fun markViewed(messageId: String) {
        val values = ContentValues().apply { putNull("envelope") }
        writableDatabase.update("messages", values, "message_id=?", arrayOf(messageId))
    }

    fun markAcknowledged(messageId: String) {
        val values = ContentValues().apply { put("acknowledged", 1) }
        writableDatabase.update("messages", values, "message_id=?", arrayOf(messageId))
    }

    fun unacknowledged(): List<LocalMessage> {
        val rows = mutableListOf<LocalMessage>()
        readableDatabase.query(
            "messages", arrayOf("message_id", "gateway_message_id", "envelope", "expires_at", "shown", "ack_result", "acknowledged"),
            "ack_result IS NOT NULL AND acknowledged=0", null, null, null, "created_at ASC", "100"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                rows += LocalMessage(
                    cursor.getString(0), cursor.getString(1), if (cursor.isNull(2)) null else cursor.getString(2),
                    cursor.getLong(3), cursor.getInt(4) == 1, cursor.getString(5), cursor.getInt(6) == 1
                )
            }
        }
        return rows
    }

    fun pendingDisplay(): List<LocalMessage> {
        val rows = mutableListOf<LocalMessage>()
        readableDatabase.query(
            "messages", arrayOf("message_id", "gateway_message_id", "envelope", "expires_at", "shown", "ack_result", "acknowledged"),
            "shown=0 AND envelope IS NOT NULL AND expires_at>?", arrayOf(Instant.now().epochSecond.toString()),
            null, null, "created_at ASC", "50"
        ).use { cursor ->
            while (cursor.moveToNext()) {
                rows += LocalMessage(cursor.getString(0), cursor.getString(1), cursor.getString(2), cursor.getLong(3), false, if (cursor.isNull(5)) null else cursor.getString(5), cursor.getInt(6) == 1)
            }
        }
        return rows
    }

    fun cleanup() {
        val now = Instant.now().epochSecond
        val values = ContentValues().apply { putNull("envelope") }
        writableDatabase.update("messages", values, "expires_at<=?", arrayOf(now.toString()))
        writableDatabase.delete("messages", "expires_at<?", arrayOf((now - 7 * 24 * 3600).toString()))
    }

    fun clearAll() {
        writableDatabase.delete("messages", null, null)
    }
}
