// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappRequesterSessionEnd

/**
 * A failed session's dev-log line names the paired device and the transport
 * (RAPP v26.11.2 section 4.3 items 3 and 4): the peer label is the pair
 * record's device label, refreshed every session, and the stream transport
 * reports as the network the requester dials on.
 */
class RappSessionFailureLogTest {
    private companion object {
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication")
        const val EXAMPLE_PEER = "macOS - pk-mac"
        const val NANOS_PER_MILLI = 1_000_000L

        fun monotonicMs(): ULong = (System.nanoTime() / NANOS_PER_MILLI).toULong()
    }

    @Test
    fun lineNamesPeerAndTransport() {
        assertEquals(
            "session closed: handshake protocol failure, macOS - pk-mac, Bluetooth",
            RappSessionFailureLog.line(
                RappSessionFailureLog.HANDSHAKE_PROTOCOL_FAILURE,
                EXAMPLE_PEER,
                RappSessionFailureLog.BLUETOOTH_TRANSPORT,
            ),
        )
    }

    @Test
    fun transportLabelsNameTheCarryingTransport() {
        assertEquals(
            RappSessionFailureLog.NETWORK_TRANSPORT,
            RappSessionFailureLog.transportLabel(RappTransportProfile.STREAM),
        )
        assertEquals(
            RappSessionFailureLog.BLUETOOTH_TRANSPORT,
            RappSessionFailureLog.transportLabel(RappTransportProfile.BLUETOOTH),
        )
    }

    @Test
    fun peerNameReadsThePairRecord() {
        RappNativeTestLibrary.require()
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, monotonicMs())
        try {
            assertEquals(RappTestOffers.COMPUTER_NAME, RappSessionFailureLog.peerName(custodian))
            assertEquals(RappTestOffers.PHONE_NAME, RappSessionFailureLog.peerName(requester))
        } finally {
            requester.close()
            custodian.close()
        }
    }

    @Test
    fun unreadableRecordReportsUnknownPairing() {
        assertEquals(RappSessionFailureLog.UNKNOWN_PAIRING, RappSessionFailureLog.peerName(null))
        RappNativeTestLibrary.require()
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, monotonicMs())
        requester.close()
        custodian.close()
        assertEquals(RappSessionFailureLog.UNKNOWN_PAIRING, RappSessionFailureLog.peerName(custodian))
        assertEquals(
            "session closed: protocol violation, unknown pairing, network",
            RappSessionFailureLog.line(
                RappSessionFailureLog.PROTOCOL_VIOLATION,
                null,
                RappTransportProfile.STREAM,
            ),
        )
    }

    @Test
    fun closesNameTheirReason() {
        assertEquals(
            "peer close: PROTOCOL_VIOLATION",
            RappSessionFailureLog.peerClose(RappCloseReason.PROTOCOL_VIOLATION),
        )
        assertEquals(
            "session end: VIOLATION",
            RappSessionFailureLog.sessionEnd(RappRequesterSessionEnd.VIOLATION),
        )
    }
}
