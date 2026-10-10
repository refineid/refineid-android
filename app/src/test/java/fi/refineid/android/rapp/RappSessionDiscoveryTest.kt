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
import uniffi.refineid_rapp.rappPairingPreamble
import uniffi.refineid_rapp.rappStreamProfileName

/**
 * Session discovery publishes no stable value, and a connection is routed
 * only by the routing tag in its preamble (RAPP v26.10.10 section 2.2.1).
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
    fun theUnhintedSessionRecordCarriesOnlyVersionAndMode() {
        assertEquals(
            mapOf("v" to "1", "mode" to "session"),
            StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION),
        )
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
        val (firstRequester, first) = RappTestOffers.pairRecords(PROFILES, NOW)
        val (secondRequester, second) = RappTestOffers.pairRecords(PROFILES, NOW)
        val pairs = listOf(first, second)
        RappSessionRouting().use { routing ->
            assertSame(second, routing.route(secondRequester.sessionPreamble(rappStreamProfileName()), pairs))
            assertSame(first, routing.route(firstRequester.sessionPreamble(rappStreamProfileName()), pairs))
        }
    }

    @Test
    fun aPreambleIsFreshOnEveryDial() {
        val (requester, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        assertNotEquals(
            requester.sessionPreamble(rappStreamProfileName()).toList(),
            requester.sessionPreamble(rappStreamProfileName()).toList(),
        )
    }

    @Test
    fun aReplayedUnknownOrOtherFrameIsRefused() {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val (stranger, _) = RappTestOffers.pairRecords(PROFILES, NOW)
        val pairs = listOf(custodian, requester)
        RappSessionRouting().use { routing ->
            val preamble = requester.sessionPreamble(rappStreamProfileName())
            assertSame(custodian, routing.route(preamble, pairs))
            assertNull(routing.route(preamble, pairs))
            assertNull(routing.route(stranger.sessionPreamble(rappStreamProfileName()), pairs))
            assertNull(routing.route(rappPairingPreamble(rappStreamProfileName()), pairs))
            // A requester-role record never serves a session on this phone.
            assertNull(routing.route(requester.sessionPreamble(rappStreamProfileName()), listOf(requester)))
        }
    }
}
