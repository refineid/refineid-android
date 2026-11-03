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
 * Drives [RappRequesterPairingCeremony] against a custodian bridge in the
 * order RAPP v26.11.2 sections 4.3 and 6.1.3 fix, after the requester
 * decoded the custodian's offer bootstrap (section 4.2).
 */
class RappRequesterPairingCeremonyTest {
    private companion object {
        const val STREAM_CANDIDATE_ID = RappTestOffers.STREAM_CANDIDATE_ID
        const val CPACE_RANDOM_BYTES = 64
        const val OFFER_STARTED_AT_MS = 1_000UL
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

    /** The unconfirmed records the ceremony asked to persist, in order. */
    private val persisted = mutableListOf<uniffi.refineid_rapp.RappPairRecord>()

    private fun ceremony(
        bridge: RappPairingBridge,
        code: String,
    ) = RappRequesterPairingCeremony(
        bridge = bridge,
        pairingCode = code,
        candidateId = STREAM_CANDIDATE_ID,
        displayName = checkNotNull(RappDisplayName.parse(RappTestOffers.COMPUTER_NAME)),
        platform = RappTestOffers.COMPUTER_PLATFORM,
        monotonicMs = { OFFER_STARTED_AT_MS },
        wallMs = { WALL_CLOCK_MS },
        random64 = { ByteArray(CPACE_RANDOM_BYTES).also { SecureRandom().nextBytes(it) } },
        persistUnconfirmed = { record -> persisted.add(record) },
    )

    private fun RappRequesterPairingCeremony.Outcome.frames(): List<ByteArray> =
        (this as RappRequesterPairingCeremony.Outcome.Send).frames

    private fun beginCustodian(
        custodian: RappPairingBridge,
        code: String,
    ) {
        val random = ByteArray(CPACE_RANDOM_BYTES).also { SecureRandom().nextBytes(it) }
        try {
            custodian.beginCpace(STREAM_CANDIDATE_ID, code, random, OFFER_STARTED_AT_MS)
        } finally {
            random.fill(0)
        }
    }

    @Test
    fun requesterCompletesTheCpaceNoiseAndConfirmationOrder() {
        val code = RappPairingCode.generate()
        val (custodian, requesterBridge) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        beginCustodian(custodian, code)
        val requester = ceremony(requesterBridge, code)
        val now = OFFER_STARTED_AT_MS

        custodian.readCpaceFrame(requester.start(), now)
        val (stepThree, handshakeOne) = requester.receive(custodian.writeCpaceFrame(now)).frames()
        assertEquals(RappRequesterPairingCeremony.Step.AWAITING_HANDSHAKE_TWO, requester.step)
        custodian.readCpaceFrame(stepThree, now)
        custodian.readHandshakeFrame(handshakeOne, now)

        val (handshakeThree, ownHello) = requester.receive(custodian.writeHandshakeFrame(now)).frames()
        assertEquals(RappRequesterPairingCeremony.Step.AWAITING_PEER_HELLO, requester.step)
        custodian.readHandshakeFrame(handshakeThree, now)
        assertTrue(custodian.handshakeComplete(now))
        custodian.enterConfirmation(now)

        val custodianHello = custodian.sendHello(RappTestOffers.PHONE_NAME, RappTestOffers.PHONE_PLATFORM, now)
        assertTrue(requester.receive(custodianHello).frames().isEmpty())
        assertEquals(RappRequesterPairingCeremony.Step.AWAITING_CONFIRMATION, requester.step)
        custodian.receiveHello(ownHello, now)

        val grant = custodian.sendConfirmation(OFFERED_PROFILES, now)
        val (echo, stored) = requester.receive(grant).frames()
        assertEquals(RappRequesterPairingCeremony.Step.AWAITING_STORED, requester.step)
        assertEquals(1, persisted.size)
        assertTrue(!persisted.single().metadata().storageConfirmed)
        assertNotNull(requester.storedRecord)
        custodian.receiveConfirmation(echo, now)
        custodian.buildPairRecord(WALL_CLOCK_MS, now).close()
        val custodianStored = custodian.sendStored(now)
        custodian.receiveStored(stored, now)

        val outcome = requester.receive(custodianStored)
        val paired = outcome as RappRequesterPairingCeremony.Outcome.Paired
        assertEquals(RappTestOffers.PHONE_NAME, paired.peer.displayName)
        assertTrue(paired.record.metadata().storageConfirmed)
        assertNull(requester.storedRecord)
        // The unconfirmed handle is closed once the confirmed record replaces it.
        assertThrows(IllegalStateException::class.java) { persisted.single().metadata() }
        assertArrayEquals(
            checkNotNull(custodian.activatePairing(now)).metadata().pairId,
            paired.record.metadata().pairId,
        )
        assertEquals(RappRequesterPairingCeremony.Step.COMPLETED, requester.step)
    }

    @Test
    fun aCeremonyAbandonedAfterStoringLeavesTheRecordToRevoke() {
        val code = RappPairingCode.generate()
        val (custodian, requesterBridge) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        beginCustodian(custodian, code)
        val requester = ceremony(requesterBridge, code)
        val now = OFFER_STARTED_AT_MS

        custodian.readCpaceFrame(requester.start(), now)
        val (stepThree, handshakeOne) = requester.receive(custodian.writeCpaceFrame(now)).frames()
        custodian.readCpaceFrame(stepThree, now)
        custodian.readHandshakeFrame(handshakeOne, now)
        val (handshakeThree, ownHello) = requester.receive(custodian.writeHandshakeFrame(now)).frames()
        custodian.readHandshakeFrame(handshakeThree, now)
        custodian.enterConfirmation(now)
        requester.receive(custodian.sendHello(RappTestOffers.PHONE_NAME, RappTestOffers.PHONE_PLATFORM, now))
        custodian.receiveHello(ownHello, now)
        requester.receive(custodian.sendConfirmation(OFFERED_PROFILES, now))

        // The custodian never confirms: the stored record is the caller's to
        // revoke, and the bridge activates nothing.
        val stored = checkNotNull(requester.storedRecord)
        assertTrue(!stored.metadata().storageConfirmed)
        assertNull(requesterBridge.activatePairing(now))
    }

    @Test
    fun aWrongCodeFailsAtTagBAndTriesNothingElse() {
        val code = RappPairingCode.generate()
        var wrong = RappPairingCode.generate()
        while (wrong == code) {
            wrong = RappPairingCode.generate()
        }
        val (custodian, requesterBridge) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        beginCustodian(custodian, code)
        val requester = ceremony(requesterBridge, wrong)
        val now = OFFER_STARTED_AT_MS

        custodian.readCpaceFrame(requester.start(), now)
        assertThrows(RappBindingException::class.java) { requester.receive(custodian.writeCpaceFrame(now)) }
        assertEquals(RappRequesterPairingCeremony.Step.AWAITING_STEP_TWO, requester.step)
        assertNull(requester.storedRecord)
    }

    @Test
    fun aBusyFrameIsNotACpaceStep() {
        val (custodian, _) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        val busy = custodian.busyBytes(OFFER_STARTED_AT_MS, 0UL)
        assertTrue(isPairingBusy(busy))
    }

    @Test
    fun aFrameOutOfOrderIsRefused() {
        val code = RappPairingCode.generate()
        val (custodian, requesterBridge) = RappTestOffers.custodianAndRequester(OFFERED_PROFILES, OFFER_STARTED_AT_MS)
        beginCustodian(custodian, code)
        val requester = ceremony(requesterBridge, code)
        val now = OFFER_STARTED_AT_MS

        custodian.readCpaceFrame(requester.start(), now)
        val stepTwo = custodian.writeCpaceFrame(now)
        requester.receive(stepTwo)
        assertThrows(RappBindingException::class.java) { requester.receive(stepTwo) }
    }
}
