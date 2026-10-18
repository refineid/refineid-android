// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import javax.crypto.KeyGenerator

/**
 * Revocation retentions are sealed at rest, stored once each, and dropped
 * once the core reports them expired (RAPP v26.10.18 section 4.6 item 4).
 */
class RappRevocationRetentionStoreTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val key = KeyGenerator.getInstance("AES").apply { init(AesGcmJournalSealer.KEY_BITS) }.generateKey()

    private fun store() = RappRevocationRetentionStore(folder.newFolder("revocations"), AesGcmJournalSealer { key })

    @Test
    fun aRetentionIsStoredOnceAndReadBack() {
        val store = store()
        val retention = "retention-one".encodeToByteArray()
        store.retain(retention)
        store.retain(retention)
        val unexpired = store.unexpired(NOW_SECONDS) { _, _ -> false }
        assertEquals(1, unexpired.size)
        assertTrue(unexpired.single().contentEquals(retention))
    }

    @Test
    fun anExpiredRetentionIsDroppedOnTheNextRead() {
        val store = store()
        store.retain("fresh".encodeToByteArray())
        store.retain("stale".encodeToByteArray())
        val first =
            store.unexpired(
                NOW_SECONDS,
            ) { retention, _ -> retention.contentEquals("stale".encodeToByteArray()) }
        assertEquals(listOf("fresh"), first.map { it.decodeToString() })
        val second = store.unexpired(NOW_SECONDS) { _, _ -> false }
        assertEquals(listOf("fresh"), second.map { it.decodeToString() })
    }

    @Test
    fun aRetentionSealedUnderAnotherKeyReadsAsAbsent() {
        val root = folder.newFolder("foreign")
        RappRevocationRetentionStore(root, AesGcmJournalSealer { key }).retain("mine".encodeToByteArray())
        val otherKey = KeyGenerator.getInstance("AES").apply { init(AesGcmJournalSealer.KEY_BITS) }.generateKey()
        val foreign = RappRevocationRetentionStore(root, AesGcmJournalSealer { otherKey })
        assertTrue(foreign.unexpired(NOW_SECONDS) { _, _ -> false }.isEmpty())
    }

    private companion object {
        const val NOW_SECONDS = 1_760_000_000UL
    }
}
