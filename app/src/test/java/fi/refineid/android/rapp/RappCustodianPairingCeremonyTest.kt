// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappTransportCandidate
import java.security.SecureRandom

/**
 * Drives [RappCustodianPairingCeremony] against a requester bridge in the
 * order RAPP v26.10.1 section 6.1.3 fixes, as the Apple and Windows
 * requesters send it.
 */
class RappCustodianPairingCeremonyTest {
    private companion object {
        const val STREAM_CANDIDATE_ID = "stream-1"
        const val STREAM_PROFILE = "fi.refineid.stream.v1"
        const val CPACE_RANDOM_BYTES = 64
        const val EMPTY_CBOR_MAP_BYTE = 0xa0
        const val OFFER_STARTED_AT_MS = 1_000UL
        const val WALL_CLOCK_MS = 1_700_000_000_000UL
        val OFFERED_PROFILES =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )
    }

    private val candidates =
        listOf(
            RappTransportCandidate(
                profile = STREAM_PROFILE,
                candidateId = STREAM_CANDIDATE_ID,
                parametersCbor = byteArrayOf(EMPTY_CBOR_MAP_BYTE.toByte()),
            ),
        )

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun bridge(
        code: String,
        custodian: Boolean,
    ): RappPairingBridge {
        val ttl = RappPairingCode.DEFAULT_LIFETIME_MS.toULong()
        val bridge =
            if (custodian) {
                RappPairingBridge.fromProxyCodeOffer(code, OFFERED_PROFILES, candidates, ttl, OFFER_STARTED_AT_MS)
            } else {
                RappPairingBridge.createRequesterCodeOffer(code, OFFERED_PROFILES, candidates, ttl, OFFER_STARTED_AT_MS)
            }
        val random = ByteArray(CPACE_RANDOM_BYTES).also { SecureRandom().nextBytes(it) }
        try {
            bridge.beginCpace(STREAM_CANDIDATE_ID, code, random, OFFER_STARTED_AT_MS)
        } finally {
            random.fill(0)
        }
        return bridge
    }

    private fun ceremony(bridge: RappPairingBridge) =
        RappCustodianPairingCeremony(
            bridge = bridge,
            offeredProfiles = OFFERED_PROFILES,
            displayName = "Phone",
            platform = "Android",
            monotonicMs = { OFFER_STARTED_AT_MS },
            wallMs = { WALL_CLOCK_MS },
        )

    private fun RappCustodianPairingCeremony.Outcome.frames(): List<ByteArray> =
        (this as RappCustodianPairingCeremony.Outcome.Send).frames

    @Test
    fun custodianCompletesTheThreeMessageCpaceAndNoiseOrder() {
        val code = RappPairingCode.generate()
        val requester = bridge(code, custodian = false)
        val custodianBridge = bridge(code, custodian = true)
        val custodian = ceremony(custodianBridge)
        val now = OFFER_STARTED_AT_MS

        val stepTwo = custodian.receive(requester.writeCpaceFrame(now)).frames().single()
        requester.readCpaceFrame(stepTwo, now)
        assertEquals(RappCustodianPairingCeremony.Step.AWAITING_STEP_THREE, custodian.step)

        assertTrue(custodian.receive(requester.writeCpaceFrame(now)).frames().isEmpty())
        val handshakeTwo = custodian.receive(requester.writeHandshakeFrame(now)).frames().single()
        requester.readHandshakeFrame(handshakeTwo, now)
        assertTrue(custodian.receive(requester.writeHandshakeFrame(now)).frames().isEmpty())
        assertTrue(requester.handshakeComplete(now))
        requester.enterConfirmation(now)

        val (custodianHello, grant) =
            custodian.receive(requester.sendHello(displayName = "Workstation", platform = "Windows")).frames()
        assertEquals("Phone", requester.receiveHello(custodianHello, WALL_CLOCK_MS).displayName)
        val granted = requester.receiveConfirmation(grant, WALL_CLOCK_MS)
        assertEquals(OFFERED_PROFILES.sorted(), granted.sorted())

        val outcome = custodian.receive(requester.sendConfirmation(granted))
        val paired = outcome as RappCustodianPairingCeremony.Outcome.Paired
        assertEquals("Workstation", paired.peer.displayName)
        assertArrayEquals(
            requester.finishPairing(WALL_CLOCK_MS).metadata().pairId,
            paired.record.metadata().pairId,
        )
        assertEquals(RappCustodianPairingCeremony.Step.COMPLETED, custodian.step)
    }

    @Test
    fun aWrongCodeFailsAtTagBOnTheRequesterAndEndsTheCustodianAttempt() {
        val code = RappPairingCode.generate()
        var wrongCode = RappPairingCode.generate()
        while (wrongCode == code) {
            wrongCode = RappPairingCode.generate()
        }
        val requester = bridge(wrongCode, custodian = false)
        val custodian = ceremony(bridge(code, custodian = true))
        val now = OFFER_STARTED_AT_MS

        val stepTwo = custodian.receive(requester.writeCpaceFrame(now)).frames().single()
        assertThrows(RappBindingException::class.java) { requester.readCpaceFrame(stepTwo, now) }

        // The requester never sends T_A. A forged one fails the custodian's tag
        // check, and the failed attempt leaves nothing to retry on this offer.
        val forgedTagA = ByteArray(stepTwo.size / 2)
        assertThrows(RappBindingException::class.java) { custodian.receive(forgedTagA) }
        assertThrows(RappBindingException::class.java) { custodian.receive(forgedTagA) }
    }

    @Test
    fun aFrameOutOfOrderIsRefused() {
        val code = RappPairingCode.generate()
        val requester = bridge(code, custodian = false)
        val custodian = ceremony(bridge(code, custodian = true))
        val now = OFFER_STARTED_AT_MS

        val stepOne = requester.writeCpaceFrame(now)
        custodian.receive(stepOne)
        assertThrows(RappBindingException::class.java) { custodian.receive(stepOne) }
    }
}
