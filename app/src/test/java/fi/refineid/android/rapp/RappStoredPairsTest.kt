// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The start-up sweep revokes every vault record no catalogue entry names
 * (RAPP v26.10.18 section 4.3 item 4).
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

    private companion object {
        const val CATALOGUED = "00112233445566778899aabbccddeeff"
        const val ORPHAN = "ffeeddccbbaa99887766554433221100"
    }
}
