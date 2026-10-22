// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_rapp.RappForgetOutcome
import java.util.concurrent.TimeUnit

/**
 * The served set: the start-up sweep revokes every vault record no catalogue
 * entry names (RAPP v26.10.22 section 4.3 item 4), and every load destroys a
 * forgotten record whose close did not reach its peer within 30 days of the
 * forgetting (section 4.6 item 3).
 */
class RappStoredPairsTest {
    @Test
    fun aRecordWithoutACatalogueEntryIsAnOrphan() {
        val orphans =
            RappStoredPairs.orphanPairIds(
                stored = listOf(CATALOGUED, ORPHAN),
                catalogued = listOf(CATALOGUED),
            )
        assertEquals(listOf(ORPHAN), orphans)
    }

    @Test
    fun catalogueEntriesMatchRecordsWhateverTheirCase() {
        val orphans =
            RappStoredPairs.orphanPairIds(
                stored = listOf(CATALOGUED),
                catalogued = listOf(CATALOGUED.uppercase()),
            )
        assertEquals(emptyList<String>(), orphans)
    }

    @Test
    fun aForgottenRecordIsServedUntilItsNoticeWindowEndsAndDestroyedThen() {
        RappNativeTestLibrary.require()
        val (_, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val vault = RappMemoryVault()
        val catalog = RappPairCatalog(FakeSharedPreferences())
        custodian.persistDeviceOnly(vault)
        val pairing = custodian.pairing()
        catalog.savePair(pairing.id.toWire(), DISPLAY_NAME, PLATFORM, FORGOTTEN_AT_MS.toLong())
        assertEquals(RappForgetOutcome.NOTICE_PENDING, custodian.forget(vault, FORGOTTEN_AT_MS))
        custodian.close()

        val within = RappStoredPairs.served(catalog, vault) { FORGOTTEN_AT_MS + NOTICE_WINDOW_MS - MARGIN_MS }
        assertTrue(within.single().pairing.state is RappPairState.Forgotten)
        within.forEach { it.record.close() }
        assertTrue(catalog.listPairs().isEmpty())

        val after = RappStoredPairs.served(catalog, vault) { FORGOTTEN_AT_MS + NOTICE_WINDOW_MS }
        assertTrue(after.isEmpty())
        assertTrue(catalog.allPairs().isEmpty())
        assertTrue(vault.isRevoked(pairing.id.toWire()))
    }

    private companion object {
        const val CATALOGUED = "00112233445566778899aabbccddeeff"
        const val ORPHAN = "ffeeddccbbaa99887766554433221100"
        const val NOW = 1_000UL
        const val FORGOTTEN_AT_MS = 1_700_000_000_000UL
        const val DISPLAY_NAME = "Laptop"
        const val PLATFORM = "macOS"
        val PROFILES = listOf("fi.refineid.card-status")

        /** Days a forgotten pairing keeps its key for the close (section 4.6 item 3). */
        const val REVOCATION_NOTICE_DAYS = 30L
        val NOTICE_WINDOW_MS = TimeUnit.DAYS.toMillis(REVOCATION_NOTICE_DAYS).toULong()

        /** How long before the window's end the record is still served. */
        const val MARGIN_MINUTES = 1L
        val MARGIN_MS = TimeUnit.MINUTES.toMillis(MARGIN_MINUTES).toULong()
    }
}
