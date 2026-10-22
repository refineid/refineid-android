// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBridge
import java.security.SecureRandom

/**
 * Drives [RappCustodianPairingCeremony] against a requester bridge in the
 * order RAPP v26.10.21 section 6.1.3 fixes, after the requester decoded the
 * custodian's offer bootstrap (section 4.2).
 */
class RappCustodianPairingCeremonyTest {
    private companion object {
        const val STREAM_CANDIDATE_ID = RappTestOffers.STREAM_CANDIDATE_ID
        const val CPACE_RANDOM_BYTES = 64
        const val OFFER_STARTED_AT_MS = 1_000UL
        const val ATTEMPT_SPACING_MS = 1_000UL
        const val ATTEMPTS_PER_OFFER = 3
        const val WALL_CLOCK_MS = 1_700_000_000_000UL
        val OFFERED_PROFILES =
            listOf(
                "fi.refineid.card-status",
                "fi.refineid.authentication",
                "fi.refineid.document-signing",
            )
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun begin(
        bridge: RappPairingBridge,
        code: String,
        now: ULong,
    ) {
        val random = ByteArray(CPACE_RANDOM_BYTES).also { SecureRandom().nextBytes(it) }
        try {
            bridge.beginCpace(STREAM_CANDIDATE_ID, code, random, now)
        } finally {
            random.fill(0)
        }
    }

    /** The custodian and requester bridges of one offer, CPace begun with the given codes. */
    private fun bridges(
        custodianCode: String,
        requesterCode: String = custodianCode,
    ): Pair<RappPairingBridge, RappPairingBridge> {
        val (custodian, requester) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        begin(custodian, custodianCode, OFFER_STARTED_AT_MS)
        begin(requester, requesterCode, OFFER_STARTED_AT_MS)
        return custodian to requester
    }

    private fun otherCode(code: String): String {
        var other = RappPairingCode.generate()
        while (other == code) {
            other = RappPairingCode.generate()
        }
        return other
    }

    /** The unconfirmed records the ceremony asked to persist, in order. */
    private val persisted = mutableListOf<uniffi.refineid_rapp.RappPairRecord>()

    private fun ceremony(bridge: RappPairingBridge) =
        RappCustodianPairingCeremony(
            bridge = bridge,
            offeredProfiles = OFFERED_PROFILES,
            displayName = "Phone",
            platform = "Android",
            monotonicMs = { OFFER_STARTED_AT_MS },
            wallMs = { WALL_CLOCK_MS },
            persistUnconfirmed = { record -> persisted.add(record) },
        )

    private fun RappCustodianPairingCeremony.Outcome.frames(): List<ByteArray> =
        (this as RappCustodianPairingCeremony.Outcome.Send).frames

    @Test
    fun custodianCompletesTheThreeMessageCpaceAndNoiseOrder() {
        val (custodianBridge, requester) = bridges(RappPairingCode.generate())
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
            custodian.receive(requester.sendHello("Workstation", "Windows", now)).frames()
        assertEquals("Phone", requester.receiveHello(custodianHello, now).displayName)
        val granted = requester.receiveConfirmation(grant, now)
        assertEquals(OFFERED_PROFILES.sorted(), granted.sorted())

        // The custodian stores its unconfirmed record and announces it;
        // the pairing is not active until the requester confirms (section
        // 4.3 item 4).
        val custodianStored = custodian.receive(requester.sendConfirmation(granted, now)).frames().single()
        assertEquals(RappCustodianPairingCeremony.Step.AWAITING_STORED, custodian.step)
        assertEquals(1, persisted.size)
        assertTrue(!persisted.single().metadata().storageConfirmed)
        assertNotNull(custodian.storedRecord)

        requester.buildPairRecord(WALL_CLOCK_MS, now).close()
        val requesterStored = requester.sendStored(now)
        requester.receiveStored(custodianStored, now)
        val outcome = custodian.receive(requesterStored)
        val paired = outcome as RappCustodianPairingCeremony.Outcome.Paired
        assertEquals("Workstation", paired.peer.displayName)
        assertTrue(paired.record.metadata().storageConfirmed)
        assertNull(custodian.storedRecord)
        // The unconfirmed handle is closed once the confirmed record replaces it.
        assertThrows(IllegalStateException::class.java) { persisted.single().metadata() }
        assertArrayEquals(
            checkNotNull(requester.activatePairing(now)).metadata().pairId,
            paired.record.metadata().pairId,
        )
        assertEquals(RappCustodianPairingCeremony.Step.COMPLETED, custodian.step)
    }

    @Test
    fun aCeremonyAbandonedAfterStoringLeavesTheRecordToRevoke() {
        val (custodianBridge, requester) = bridges(RappPairingCode.generate())
        val custodian = ceremony(custodianBridge)
        val now = OFFER_STARTED_AT_MS

        requester.readCpaceFrame(custodian.receive(requester.writeCpaceFrame(now)).frames().single(), now)
        custodian.receive(requester.writeCpaceFrame(now))
        requester.readHandshakeFrame(custodian.receive(requester.writeHandshakeFrame(now)).frames().single(), now)
        custodian.receive(requester.writeHandshakeFrame(now))
        requester.enterConfirmation(now)
        val (custodianHello, grant) = custodian.receive(requester.sendHello("Workstation", "Windows", now)).frames()
        requester.receiveHello(custodianHello, now)
        val granted = requester.receiveConfirmation(grant, now)
        custodian.receive(requester.sendConfirmation(granted, now))

        // The requester never confirms: the stored record is the caller's to
        // revoke, and the bridge activates nothing.
        val stored = checkNotNull(custodian.storedRecord)
        assertTrue(!stored.metadata().storageConfirmed)
        assertNull(custodianBridge.activatePairing(now))
    }

    @Test
    fun aWrongCodeFailsAtTagBOnTheRequesterAndSpendsOneCustodianAttempt() {
        val code = RappPairingCode.generate()
        val (custodianBridge, requester) = bridges(code, requesterCode = otherCode(code))
        val custodian = ceremony(custodianBridge)
        val now = OFFER_STARTED_AT_MS

        val stepTwo = custodian.receive(requester.writeCpaceFrame(now)).frames().single()
        assertThrows(RappBindingException::class.java) { requester.readCpaceFrame(stepTwo, now) }

        // The requester never sends T_A and disconnects; the attempt is spent
        // and the offer stays for another connection (section 3.3).
        assertTrue(custodianBridge.candidateFailed(now))
    }

    @Test
    fun threeWrongCodesExhaustTheOffer() {
        val code = RappPairingCode.generate()
        val (custodianBridge, _) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        var now = OFFER_STARTED_AT_MS
        repeat(ATTEMPTS_PER_OFFER) { attempt ->
            val requester =
                RappPairingBridge.fromBootstrap(
                    custodianBridge.bootstrapBytes(now),
                    RappTestOffers.STREAM_PROFILE,
                    now,
                )
            begin(custodianBridge, code, now)
            begin(requester, otherCode(code), now)
            custodianBridge.readCpaceFrame(requester.writeCpaceFrame(now), now)
            custodianBridge.writeCpaceFrame(now)
            val kept =
                try {
                    custodianBridge.candidateFailed(now)
                } catch (_: RappBindingException.AttemptsExhausted) {
                    false
                }
            assertEquals(attempt < ATTEMPTS_PER_OFFER - 1, kept)
            now += ATTEMPT_SPACING_MS
        }
        assertThrows(RappBindingException::class.java) { begin(custodianBridge, code, now) }
    }

    @Test
    fun aFrameOutOfOrderIsRefused() {
        val (custodianBridge, requester) = bridges(RappPairingCode.generate())
        val custodian = ceremony(custodianBridge)
        val now = OFFER_STARTED_AT_MS

        val stepOne = requester.writeCpaceFrame(now)
        custodian.receive(stepOne)
        assertThrows(RappBindingException::class.java) { custodian.receive(stepOne) }
    }
}
