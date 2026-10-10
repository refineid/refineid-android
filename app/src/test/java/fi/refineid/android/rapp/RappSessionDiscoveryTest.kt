// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.rappStreamPairingPreamble
import uniffi.refineid_rapp.rappStreamSessionPreamble

/**
 * Session discovery publishes nothing derived from a rendezvous token, and
 * a connection is routed only by its preamble (RAPP discovery hierarchy
 * section 4.1-4.3).
 */
class RappSessionDiscoveryTest {
    private companion object {
        const val NOW = 1_000UL
        const val TOKEN_BYTES = 16
        val PROFILES = listOf("fi.refineid.card-status.v1")
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    @Test
    fun instanceNamesAreFreshAndRandom() {
        val first = StreamRendezvousName.ephemeralName()
        val second = StreamRendezvousName.ephemeralName()
        assertTrue(Regex("refineid-[0-9a-f]{8}").matches(first))
        assertNotEquals(first, second)
    }

    @Test
    fun theSessionRecordCarriesOnlyVersionAndMode() {
        assertEquals(
            mapOf("v" to "1", "mode" to "session"),
            StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION),
        )
        val (_, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val token = custodian.metadata().rendezvousToken.joinToString("") { "%02x".format(it) }
        val published =
            StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION).values +
                StreamRendezvousName.ephemeralName()
        assertFalse(published.any { it.contains(token.take(TOKEN_BYTES)) })
    }

    @Test
    fun resolvedAttributesMatchOnlyTheirMode() {
        val session = mapOf("v" to "1".encodeToByteArray(), "mode" to "session".encodeToByteArray())
        assertTrue(StreamRendezvousName.matches(session, StreamRendezvousName.MODE_SESSION))
        assertFalse(StreamRendezvousName.matches(session, StreamRendezvousName.MODE_PAIRING))
        assertFalse(StreamRendezvousName.matches(mapOf("mode" to "session".encodeToByteArray()), "session"))
    }

    @Test
    fun aPreambleRoutesToItsOwnCustodianPairing() {
        val (_, first) = RappTestOffers.pairRecords(PROFILES, NOW)
        val (_, second) = RappTestOffers.pairRecords(PROFILES, NOW)
        val pairs = listOf(first, second)

        fun preambleOf(record: uniffi.refineid_rapp.RappPairRecord) =
            rappStreamSessionPreamble(record.metadata().rendezvousToken)
        assertSame(second, RappSessionRouting.route(preambleOf(second), pairs))
        assertSame(first, RappSessionRouting.route(preambleOf(first), pairs))
    }

    @Test
    fun anUnknownTokenOrAnotherFrameIsRefused() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val pairs = listOf(custodian, requester)
        assertNull(RappSessionRouting.route(rappStreamSessionPreamble(ByteArray(TOKEN_BYTES)), pairs))
        assertNull(RappSessionRouting.route(rappStreamPairingPreamble(), pairs))
        // A requester-role record never serves a session on this phone.
        val requesterPreamble = rappStreamSessionPreamble(requester.metadata().rendezvousToken)
        assertNull(RappSessionRouting.route(requesterPreamble, listOf(requester)))
    }
}
