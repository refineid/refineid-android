// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappAnnouncementCandidate
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.rappSessionRecord
import uniffi.refineid_rapp.rappWithdrawnRecord

/**
 * The requester's classification of resolved stream services (RAPP
 * v26.11.2 section 4.5 item 6, section 8.3): appearances put the custodian
 * in sight, and a withdrawn record is honored only on the associated
 * instance.
 */
class RappRequesterSightingsTest {
    private companion object {
        const val NOW = 1_000UL
        const val NOW_SECONDS = 1_760_000_000L
        const val INSTANCE = "refineid-7f2a1c84"
        const val OTHER_INSTANCE = "refineid-00000000"
        const val USE_ORDER = 0UL
        val PROFILES = listOf("fi.refineid.card-status")
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun resolved(entries: Map<String, String>): Map<String, ByteArray?> =
        entries.mapValues { (_, value) -> value.encodeToByteArray() }

    private fun sessionRecord(custodians: List<RappPairRecord>): Map<String, ByteArray?> =
        resolved(
            StreamRendezvousName.attributes(
                rappSessionRecord(
                    custodians.mapIndexed { index, record ->
                        RappAnnouncementCandidate(record.discoveryHint(NOW_SECONDS.toULong()), index.toULong())
                    },
                ),
            ),
        )

    private fun withdrawnRecord(custodians: List<RappPairRecord>): Map<String, ByteArray?> =
        resolved(
            StreamRendezvousName.attributes(
                rappWithdrawnRecord(
                    custodians.map { record ->
                        RappAnnouncementCandidate(record.withdrawalHint(INSTANCE, NOW_SECONDS.toULong()), USE_ORDER)
                    },
                ),
            ),
        )

    @Test
    fun aHintedRecordAppearsOnceUntilLost() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val record = sessionRecord(listOf(custodian))

        assertEquals(
            RappSighting.Appeared(hintMatched = true),
            sightings.resolved(INSTANCE, record, null, requester, NOW_SECONDS),
        )
        assertNull(sightings.resolved(INSTANCE, record, null, requester, NOW_SECONDS))
        sightings.lost(INSTANCE)
        assertEquals(
            RappSighting.Appeared(hintMatched = true),
            sightings.resolved(INSTANCE, record, null, requester, NOW_SECONDS),
        )
    }

    @Test
    fun aFreshInstanceIsAnAppearance() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val record = sessionRecord(listOf(custodian))

        assertEquals(
            RappSighting.Appeared(hintMatched = true),
            sightings.resolved(INSTANCE, record, null, requester, NOW_SECONDS),
        )
        assertEquals(
            RappSighting.Appeared(hintMatched = true),
            sightings.resolved(OTHER_INSTANCE, record, null, requester, NOW_SECONDS),
        )
    }

    @Test
    fun anUnhintedRecordPutsTheCustodianInSight() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val record = sessionRecord(emptyList())

        assertEquals(
            RappSighting.Appeared(hintMatched = false),
            sightings.resolved(INSTANCE, record, null, requester, NOW_SECONDS),
        )
    }

    @Test
    fun aRecordNamingOnlyOtherPairingsMeansNothing() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val (_, stranger) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()

        assertNull(sightings.resolved(INSTANCE, sessionRecord(listOf(stranger)), null, requester, NOW_SECONDS))
    }

    @Test
    fun aWithdrawnRecordMatchesOnlyOnTheAssociatedInstance() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val withdrawn = withdrawnRecord(listOf(custodian))

        assertSame(
            RappSighting.WithdrawnMatched,
            sightings.resolved(INSTANCE, withdrawn, INSTANCE, requester, NOW_SECONDS),
        )
        assertNull(sightings.resolved(INSTANCE, withdrawn, OTHER_INSTANCE, requester, NOW_SECONDS))
        assertNull(sightings.resolved(INSTANCE, withdrawn, null, requester, NOW_SECONDS))
    }

    @Test
    fun aWithdrawnRecordWithoutAMatchMeansNothing() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val withdrawn = withdrawnRecord(emptyList())

        assertNull(sightings.resolved(INSTANCE, withdrawn, INSTANCE, requester, NOW_SECONDS))
    }

    @Test
    fun aPairingRecordMeansNothingToSessionDiscovery() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val sightings = RappRequesterSightings()
        val pairing = resolved(StreamRendezvousName.attributes(StreamRendezvousName.MODE_PAIRING))

        assertNull(sightings.resolved(INSTANCE, pairing, null, requester, NOW_SECONDS))
    }
}
