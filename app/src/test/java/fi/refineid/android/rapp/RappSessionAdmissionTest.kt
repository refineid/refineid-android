// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * One session at a time across the stream and Bluetooth (STPA CC-67): a busy
 * session is never displaced (UCA-66), an idle one goes at once to its own
 * pairing and after the hold to another.
 */
class RappSessionAdmissionTest {
    private companion object {
        const val NOW_MS = 1_000_000L
        val SERVED: RappPairId = checkNotNull(RappPairId.fromWire("served pairing!!".encodeToByteArray()))
        val OTHER: RappPairId = checkNotNull(RappPairId.fromWire("another pairing!".encodeToByteArray()))
    }

    private fun decide(
        incoming: RappPairId,
        serving: RappPairId?,
        idleForMs: Long?,
    ): RappSessionAdmission =
        RappSessionAdmission.decide(
            incoming = incoming,
            serving = serving,
            idleSinceMs = idleForMs?.let { NOW_MS - it },
            nowMs = NOW_MS,
        )

    @Test
    fun aDialIsAdmittedWhileNoSessionIsOpen() {
        assertEquals(RappSessionAdmission.ADMIT, decide(SERVED, serving = null, idleForMs = null))
    }

    @Test
    fun aBusySessionIsNeverDisplacedWhateverDials() {
        assertEquals(RappSessionAdmission.REFUSE_BUSY, decide(SERVED, SERVED, idleForMs = null))
        assertEquals(RappSessionAdmission.REFUSE_BUSY, decide(OTHER, SERVED, idleForMs = null))
    }

    @Test
    fun anIdleSessionGoesAtOnceToItsOwnPairing() {
        assertEquals(RappSessionAdmission.ADMIT, decide(SERVED, SERVED, idleForMs = 0L))
    }

    @Test
    fun anIdleSessionGoesToAnotherPairingOnlyAfterTheHold() {
        val justShort = RappSessionAdmission.CROSS_PEER_HOLD_MS - 1
        assertEquals(RappSessionAdmission.REFUSE_HELD, decide(OTHER, SERVED, idleForMs = justShort))
        assertEquals(
            RappSessionAdmission.ADMIT,
            decide(OTHER, SERVED, idleForMs = RappSessionAdmission.CROSS_PEER_HOLD_MS),
        )
    }

    @Test
    fun onlyAdmitAdmits() {
        assertTrue(RappSessionAdmission.ADMIT.admits)
        assertFalse(RappSessionAdmission.REFUSE_BUSY.admits)
        assertFalse(RappSessionAdmission.REFUSE_HELD.admits)
    }

    @Test
    fun eachTransportBindsItsRegisteredProfile() {
        assertEquals(RappTransportProfile.STREAM, RappServedTransport.Stream.profile)
        assertEquals(RappTransportProfile.BLUETOOTH, RappServedTransport.Bluetooth(RappBleLink(serial = 1L)).profile)
        assertEquals(RappBleGattProfile.PROFILE_NAME, RappTransportProfile.BLUETOOTH.profileName)
    }
}
