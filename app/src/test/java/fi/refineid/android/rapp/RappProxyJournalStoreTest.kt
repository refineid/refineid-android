// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.refineid_rapp.RappVaultException
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class RappProxyJournalStoreTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val key: SecretKey =
        KeyGenerator.getInstance("AES").apply { init(AesGcmJournalSealer.KEY_BITS) }.generateKey()

    private fun store(root: File = folder.root) = RappProxyJournalStore(root, AesGcmJournalSealer { key })

    private val pairId = ByteArray(ID_BYTES) { PAIR_FILL }
    private val operationId = ByteArray(ID_BYTES) { OPERATION_FILL }
    private val record = "record".encodeToByteArray()
    private val result = "result".encodeToByteArray()

    @Test
    fun entriesSurviveARestart() {
        store().persistWithResult(pairId, operationId, record, result)

        val reloaded = store().load(pairId).single()

        assertArrayEquals(record, reloaded.record)
        assertArrayEquals(result, reloaded.retainedResult)
    }

    @Test
    fun uncertaintyKeepsTheResultAndAcknowledgmentErasesIt() {
        val journal = store()
        journal.persistWithResult(pairId, operationId, record, result)
        val uncertain = "uncertain".encodeToByteArray()
        journal.retainUncertain(pairId, operationId, uncertain)
        assertArrayEquals(result, store().load(pairId).single().retainedResult)
        assertArrayEquals(uncertain, store().load(pairId).single().record)

        val acknowledged = "acknowledged".encodeToByteArray()
        journal.acknowledge(pairId, operationId, acknowledged)
        val tombstone = store().load(pairId).single()
        assertArrayEquals(acknowledged, tombstone.record)
        assertNull(tombstone.retainedResult)
    }

    @Test
    fun retainingAnUnknownEntryFails() {
        assertThrows(RappVaultException.Unavailable::class.java) {
            store().retainUncertain(pairId, operationId, record)
        }
    }

    @Test
    fun entriesAreSealedAtRest() {
        store().persist(pairId, operationId, record)

        val bytes =
            folder.root
                .walkTopDown()
                .filter { it.isFile }
                .single()
                .readBytes()

        assertFalse(bytes.toString(Charsets.ISO_8859_1).contains("record"))
    }

    @Test
    fun aTamperedEntryFailsClosed() {
        store().persist(pairId, operationId, record)
        val file =
            folder.root
                .walkTopDown()
                .filter { it.isFile }
                .single()
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)

        assertThrows(RappVaultException.Unavailable::class.java) { store().load(pairId) }
    }

    @Test
    fun purgeRemovesOnlyThatPairing() {
        val otherPair = ByteArray(ID_BYTES) { OTHER_PAIR_FILL }
        val journal = store()
        journal.persist(pairId, operationId, record)
        journal.persist(otherPair, operationId, record)

        journal.purge(pairId)

        assertTrue(store().load(pairId).isEmpty())
        assertEquals(1, store().load(otherPair).size)
    }

    private companion object {
        const val ID_BYTES = 16
        const val PAIR_FILL: Byte = 0x11
        const val OTHER_PAIR_FILL: Byte = 0x22
        const val OPERATION_FILL: Byte = 0x33
    }
}
