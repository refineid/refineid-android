// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappAnnouncementCandidate
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.rappSessionRecord
import uniffi.refineid_rapp.rappWithdrawnRecord

/**
 * Session and withdrawn records are built and matched by the core from the
 * pairings' static agreements (RAPP v26.10.10 sections 4.3 and 4.5).
 */
class RappDiscoveryRecordTest {
    private companion object {
        const val NOW = 1_000UL
        const val NOW_SECONDS = 1_760_000_000UL
        const val MAX_SESSION_HINTS = 4
        const val WITHDRAWN_ENTRIES = 8
        const val INSTANCE = "refineid-7f2a1c84"
        val PROFILES = listOf("fi.refineid.card-status.v1")
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun resolved(entries: Map<String, String>): Map<String, ByteArray?> =
        entries.mapValues { (_, value) -> value.encodeToByteArray() }

    private fun sessionRecord(custodians: List<RappPairRecord>): Map<String, String> =
        StreamRendezvousName.attributes(
            rappSessionRecord(
                custodians.mapIndexed { index, record ->
                    RappAnnouncementCandidate(record.discoveryHint(NOW_SECONDS), index.toULong())
                },
            ),
        )

    @Test
    fun aSessionRecordNamesItsOwnPairingOnly() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val (otherRequester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val record = resolved(sessionRecord(listOf(custodian)))
        assertTrue(StreamRendezvousName.matches(record, StreamRendezvousName.MODE_SESSION))
        assertTrue(StreamRendezvousName.hasHints(record))
        assertTrue(requester.matchesDiscoveryRecord(StreamRendezvousName.entries(record), NOW_SECONDS))
        assertFalse(otherRequester.matchesDiscoveryRecord(StreamRendezvousName.entries(record), NOW_SECONDS))
    }

    @Test
    fun aSessionRecordWithoutPairingsCarriesNoHints() {
        val record = resolved(StreamRendezvousName.attributes(rappSessionRecord(emptyList())))
        assertTrue(StreamRendezvousName.matches(record, StreamRendezvousName.MODE_SESSION))
        assertFalse(StreamRendezvousName.hasHints(record))
    }

    @Test
    fun aSessionRecordCarriesAtMostFourHints() {
        val custodians = List(MAX_SESSION_HINTS + 1) { RappTestOffers.pairRecords(PROFILES, NOW).second }
        val hints = sessionRecord(custodians).getValue(StreamRendezvousName.ATTRIBUTE_HINTS).split(',')
        assertEquals(MAX_SESSION_HINTS, hints.size)
    }

    @Test
    fun aWithdrawnRecordNamesItsPairingOnItsInstance() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val withdrawn =
            rappWithdrawnRecord(
                listOf(RappAnnouncementCandidate(custodian.withdrawalHint(INSTANCE, NOW_SECONDS), NOW)),
            )
        val entries = StreamRendezvousName.attributes(withdrawn).getValue("withdrawn").split(',')
        assertEquals(WITHDRAWN_ENTRIES, entries.size)
        assertTrue(requester.matchesWithdrawnRecord(INSTANCE, withdrawn, NOW_SECONDS))
        assertFalse(requester.matchesWithdrawnRecord("refineid-00000000", withdrawn, NOW_SECONDS))
    }

    @Test
    fun aWithdrawnRecordWithoutPairingsIsAllFiller() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val withdrawn = rappWithdrawnRecord(emptyList())
        val entries = StreamRendezvousName.attributes(withdrawn).getValue("withdrawn").split(',')
        assertEquals(WITHDRAWN_ENTRIES, entries.size)
        assertFalse(requester.matchesWithdrawnRecord(INSTANCE, withdrawn, NOW_SECONDS))
    }

    @Test
    fun recordKeysMatchWithoutRegardToCase() {
        val record = mapOf("V" to "1".encodeToByteArray(), "Mode" to "session".encodeToByteArray())
        assertTrue(StreamRendezvousName.matches(record, StreamRendezvousName.MODE_SESSION))
        assertFalse(StreamRendezvousName.matches(record, StreamRendezvousName.MODE_PAIRING))
    }
}
