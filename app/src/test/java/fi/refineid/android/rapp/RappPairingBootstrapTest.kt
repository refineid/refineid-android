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
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.rappPairingBusyRetryAfterMs
import uniffi.refineid_rapp.rappPairingPreamble
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.SecureRandom

/**
 * The custodian answers a pairing connection it cannot admit with
 * `pairing-busy` carrying the time until it can, and serves its offer again
 * once it can (RAPP v26.10.29 section 3.3 item 6; section 4.2, "Bootstrap
 * Read Flow" and "Busy Refusal").
 */
class RappPairingBootstrapTest {
    private companion object {
        const val STREAM_PROFILE = RappTestOffers.STREAM_PROFILE
        const val STREAM_CANDIDATE_ID = RappTestOffers.STREAM_CANDIDATE_ID
        val CPACE_RANDOM_BYTES = rappRandomByteCounts().cpaceRandom.toInt()
        val PROFILES = listOf("fi.refineid.card-status")

        /** When the offer was created. */
        const val OFFER_STARTED_AT_MS = 1_000UL

        /** The spacing between admitted pre-authentication attempts (section 3.3 item 6). */
        const val ADMISSION_SPACING_MS = 500UL

        /** How long an admitted attempt may run (section 3.3 item 3). */
        const val ATTEMPT_WINDOW_MS = 5_000UL

        /** How long the offer is served (section 3.3 item 7). */
        const val OFFER_TTL_MS = 300_000UL

        /** How far into the limiter's spacing a refused connection arrives. */
        const val INSIDE_SPACING_MS = 200UL

        /** When the requester's step 1 arrives, after the offer was served. */
        const val STEP_ONE_AFTER_MS = 10UL

        /** A first frame that is no routing preamble. */
        val NOT_A_PREAMBLE = "not a routing preamble".encodeToByteArray()
    }

    private val preamble by lazy { rappPairingPreamble(STREAM_PROFILE) }

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

    private fun offer(answer: RappPairingBootstrap.Answer): ByteArray {
        assertTrue("expected the offer, got $answer", answer is RappPairingBootstrap.Answer.Offer)
        return (answer as RappPairingBootstrap.Answer.Offer).frame
    }

    private fun busyWait(answer: RappPairingBootstrap.Answer): ULong {
        assertTrue("expected a busy answer, got $answer", answer is RappPairingBootstrap.Answer.Busy)
        return rappPairingBusyRetryAfterMs((answer as RappPairingBootstrap.Answer.Busy).frame)
    }

    /** A requester that decoded [offer] and sent its CPace step 1 with [code]. */
    private fun requesterAtStepOne(
        offer: ByteArray,
        code: String,
        now: ULong,
    ): Pair<RappPairingBridge, ByteArray> {
        val requester = RappPairingBridge.fromBootstrap(offer, STREAM_PROFILE, now)
        begin(requester, code, now)
        return requester to requester.writeCpaceFrame(now)
    }

    /**
     * A custodian whose offer was served at [OFFER_STARTED_AT_MS] and whose
     * attempt was admitted [STEP_ONE_AFTER_MS] later; its bootstrap and the
     * offer it served.
     */
    private fun custodianWithActiveAttempt(): Triple<RappPairingBridge, RappPairingBootstrap, ByteArray> {
        val code = RappPairingCode.generate()
        val (custodian, _) = RappTestOffers.custodianAndRequester(PROFILES, OFFER_STARTED_AT_MS)
        val bootstrap = RappPairingBootstrap(custodian, RappPreAuthenticationLimiter(), STREAM_PROFILE)
        val offer = offer(bootstrap.answer(preamble, OFFER_STARTED_AT_MS))
        begin(custodian, code, OFFER_STARTED_AT_MS)
        val (_, stepOne) = requesterAtStepOne(offer, code, OFFER_STARTED_AT_MS)
        custodian.readCpaceFrame(stepOne, OFFER_STARTED_AT_MS + STEP_ONE_AFTER_MS)
        return Triple(custodian, bootstrap, offer)
    }

    @Test
    fun anActiveAttemptAnswersBusyAtBootstrapWithItsRemainingTime() {
        val (_, bootstrap, _) = custodianWithActiveAttempt()
        val admittedAt = OFFER_STARTED_AT_MS + STEP_ONE_AFTER_MS
        val later = admittedAt + ADMISSION_SPACING_MS

        val answer = bootstrap.answer(preamble, later)

        assertEquals(ATTEMPT_WINDOW_MS - ADMISSION_SPACING_MS, busyWait(answer))
        val busy = (answer as RappPairingBootstrap.Answer.Busy).frame
        assertThrows(RappBindingException.CustodianBusy::class.java) {
            RappPairingBridge.fromBootstrap(busy, STREAM_PROFILE, later)
        }
    }

    @Test
    fun theOfferIsServedAgainOnceTheAttemptEnded() {
        val (custodian, bootstrap, offer) = custodianWithActiveAttempt()
        val ended = OFFER_STARTED_AT_MS + STEP_ONE_AFTER_MS + ADMISSION_SPACING_MS
        busyWait(bootstrap.answer(preamble, ended))
        assertTrue(custodian.candidateFailed(ended))

        val again = bootstrap.answer(preamble, ended + ADMISSION_SPACING_MS)

        assertArrayEquals(offer, offer(again))
    }

    @Test
    fun aConnectionTheLimiterRefusesIsAnsweredWithTheLimitersWait() {
        val (custodian, _) = RappTestOffers.custodianAndRequester(PROFILES, OFFER_STARTED_AT_MS)
        val bootstrap = RappPairingBootstrap(custodian, RappPreAuthenticationLimiter(), STREAM_PROFILE)
        val offer = offer(bootstrap.answer(preamble, OFFER_STARTED_AT_MS))

        val refused = bootstrap.answer(preamble, OFFER_STARTED_AT_MS + INSIDE_SPACING_MS)

        assertEquals(ADMISSION_SPACING_MS - INSIDE_SPACING_MS, busyWait(refused))
        val again = offer(bootstrap.answer(preamble, OFFER_STARTED_AT_MS + ADMISSION_SPACING_MS))
        assertArrayEquals(offer, again)
        RappPairingBridge.fromBootstrap(again, STREAM_PROFILE, OFFER_STARTED_AT_MS + ADMISSION_SPACING_MS).close()
    }

    @Test
    fun aConnectionWhileAnotherHoldsTheTransportIsAnsweredBusyWithoutUsingTheLimiter() {
        val (custodian, _) = RappTestOffers.custodianAndRequester(PROFILES, OFFER_STARTED_AT_MS)
        val bootstrap = RappPairingBootstrap(custodian, RappPreAuthenticationLimiter(), STREAM_PROFILE)
        offer(bootstrap.answer(preamble, OFFER_STARTED_AT_MS))

        val held = bootstrap.answerWhileHeld(preamble, OFFER_STARTED_AT_MS + INSIDE_SPACING_MS)

        assertEquals(ADMISSION_SPACING_MS - INSIDE_SPACING_MS, busyWait(held))
        offer(bootstrap.answer(preamble, OFFER_STARTED_AT_MS + ADMISSION_SPACING_MS))
        assertEquals(
            RappPairingBootstrap.Answer.Close,
            bootstrap.answerWhileHeld(NOT_A_PREAMBLE, OFFER_STARTED_AT_MS),
        )
    }

    @Test
    fun aStepOneTheOfferCannotAdmitIsAnsweredBusyInPlaceOfStepTwo() {
        val (custodian, bootstrap, offer) = custodianWithActiveAttempt()
        val now = OFFER_STARTED_AT_MS + ADMISSION_SPACING_MS
        val (second, _) = requesterAtStepOne(offer, RappPairingCode.generate(), now)
        assertThrows(RappBindingException.WrongPhase::class.java) {
            begin(custodian, RappPairingCode.generate(), now)
        }

        val answer = bootstrap.answerInPlaceOfStepTwo(now)

        assertEquals(ATTEMPT_WINDOW_MS + STEP_ONE_AFTER_MS - ADMISSION_SPACING_MS, busyWait(answer))
        assertThrows(RappBindingException.CustodianBusy::class.java) {
            second.readCpaceFrame((answer as RappPairingBootstrap.Answer.Busy).frame, now)
        }
    }

    @Test
    fun anythingButAPairingPreambleOrAnExpiredOfferIsClosedUnanswered() {
        val (custodian, _) = RappTestOffers.custodianAndRequester(PROFILES, OFFER_STARTED_AT_MS)
        val bootstrap = RappPairingBootstrap(custodian, RappPreAuthenticationLimiter(), STREAM_PROFILE)

        assertEquals(RappPairingBootstrap.Answer.Close, bootstrap.answer(NOT_A_PREAMBLE, OFFER_STARTED_AT_MS))
        val expired = OFFER_STARTED_AT_MS + OFFER_TTL_MS
        assertEquals(RappPairingBootstrap.Answer.Close, bootstrap.answer(preamble, expired))
        assertEquals(RappPairingBootstrap.Answer.Close, bootstrap.answerWhileHeld(preamble, expired))
        assertEquals(RappPairingBootstrap.Answer.Close, bootstrap.answerInPlaceOfStepTwo(expired))
    }
}
