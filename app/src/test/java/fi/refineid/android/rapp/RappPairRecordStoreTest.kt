// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.refineid_rapp.RappVaultException
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class RappPairRecordStoreTest {
    private companion object {
        const val PAIR_ID = "00112233445566778899aabbccddeeff"
        const val OTHER_PAIR_ID = "ffeeddccbbaa99887766554433221100"
    }

    @get:Rule
    val folder = TemporaryFolder()

    private val key: SecretKey = newKey()

    private fun newKey(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(AesGcmJournalSealer.KEY_BITS) }.generateKey()

    private fun store(sealingKey: SecretKey = key) =
        RappPairRecordStore(folder.root, AesGcmJournalSealer { sealingKey })

    private val record = "pair record with a private key".encodeToByteArray()

    @Test
    fun aRecordSurvivesARestart() {
        store().insert(PAIR_ID, record)
        assertArrayEquals(record, store().load(PAIR_ID))
    }

    @Test
    fun theRecordIsSealedAtRest() {
        store().insert(PAIR_ID, record)
        val bytes = File(folder.root, "$PAIR_ID.pair").readBytes()
        assertFalse(bytes.decodeToString(throwOnInvalidSequence = false).contains("private key"))
    }

    @Test
    fun anAlteredOrForeignRecordReadsAsAbsent() {
        store().insert(PAIR_ID, record)
        val file = File(folder.root, "$PAIR_ID.pair")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertNull(store().load(PAIR_ID))
        store().insert(OTHER_PAIR_ID, record)
        assertNull(store(newKey()).load(OTHER_PAIR_ID))
    }

    @Test
    fun removeDeletesOnlyThatPairing() {
        store().insert(PAIR_ID, record)
        store().insert(OTHER_PAIR_ID, record)
        store().remove(PAIR_ID)
        assertNull(store().load(PAIR_ID))
        assertArrayEquals(record, store().load(OTHER_PAIR_ID))
    }

    @Test
    fun legacyRecordsMigrateWithoutOverwriting() {
        val newer = "newer".encodeToByteArray()
        store().insert(OTHER_PAIR_ID, newer)
        val migrated = store().migrate(mapOf(PAIR_ID to record, OTHER_PAIR_ID to record, "not-an-id" to record))
        assertEquals(listOf(PAIR_ID, OTHER_PAIR_ID), migrated)
        assertArrayEquals(record, store().load(PAIR_ID))
        assertArrayEquals(newer, store().load(OTHER_PAIR_ID))
    }

    @Test
    fun aPathLikeIdentifierIsRefused() {
        assertThrows(RappVaultException::class.java) { store().insert("../escape", record) }
    }
}
