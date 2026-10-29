// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.PIN1_MINIMUM_LENGTH
import fi.refineid.android.core.Pin1Retention
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.attemptsLeft
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderCardPresenceWatch
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The custodian's PIN 1 across browser authentications, step by step as
 * the proxy dispatcher takes it: asked once, then spent with no prompt
 * until the card leaves or refuses it (RAPP v26.10.29 section 11 item 2).
 */
class RappPin1CustodyTest {
    @Test
    fun theFirstAuthenticationAsksAndTheSecondAsksNothing() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)

        assertNull("nothing is held before the first authentication", custody.held(CARD_A))
        acceptEntered(custody, syntheticPin(), NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT))

        // The card stays in the reader, so its status reads verified.
        repeat(LATER_AUTHENTICATIONS) {
            val held = checkNotNull(custody.held(CARD_A)) { "a held PIN is spent with no prompt" }
            held.use { pin ->
                val retention = Pin1Retention.of(CARD_A, NativePin1State.Verified.attemptsLeft())
                assertTrue(custody.admits(CARD_A, heldFor = CARD_A, retention = retention))
                assertTrue("a held PIN needs no separate VERIFY", custody.holds(pin, CARD_A))
                assertTrue(custody.hold(pin, checkNotNull(retention), custody.generation))
            }
        }
        assertTrue(cache.holds(CARD_A))
    }

    @Test
    fun aPinTheCardRefusedEndsTheHold() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)
        acceptEntered(custody, syntheticPin(), NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT))

        syntheticPin().use(custody::refuse)

        assertNull(custody.held(CARD_A))
        syntheticPin().use { assertTrue(custody.refused(it)) }
    }

    @Test
    fun theCardLeavingTheReaderEndsTheHold() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)
        val watch = ReaderCardPresenceWatch()
        watch.presenceEnded(UsbReaderSnapshot(ReaderConnectionStatus.READY, CardPresence.PRESENT))
        acceptEntered(custody, syntheticPin(), NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT))

        // The application clears the cache when the watch reports the end.
        if (watch.presenceEnded(UsbReaderSnapshot(ReaderConnectionStatus.READY, CardPresence.NOT_PRESENT))) {
            cache.clear()
        }

        assertNull(custody.held(CARD_A))
    }

    @Test
    fun anotherCardGetsNothingAndEndsTheHold() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)
        acceptEntered(custody, syntheticPin(), NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT))

        assertNull(custody.held(CARD_B))
        assertNull(custody.held(CARD_A))
    }

    @Test
    fun aHeldPinGoesNowhereOnceItsCardCounterFalls() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)
        acceptEntered(custody, syntheticPin(), NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT))

        val fallen = Pin1Retention.of(CARD_A, NativePin1State.Remaining(ONE_ATTEMPT_SPENT).attemptsLeft())
        assertFalse(custody.admits(CARD_A, heldFor = CARD_A, retention = fallen))
        assertNull(custody.held(CARD_A))
    }

    @Test
    fun aPinEnteredBelowTheTryLimitServesOnlyItsOperation() {
        val cache = AuthenticationPinCache()
        val custody = RappPin1Custody(cache)
        val retention = Pin1Retention.of(CARD_A, NativePin1State.Remaining(ONE_ATTEMPT_SPENT).attemptsLeft())

        assertTrue(
            "an entered PIN still goes to its card",
            custody.admits(CARD_A, heldFor = null, retention = retention),
        )
        assertNull(retention)
        assertNull(custody.held(CARD_A))
    }

    /** The first authentication: the holder enters [pin], the card accepts it, and custody holds it. */
    private fun acceptEntered(
        custody: RappPin1Custody,
        pin: Pin1Submission,
        before: NativePin1State,
    ) {
        pin.use {
            val retention = Pin1Retention.of(CARD_A, before.attemptsLeft())
            assertTrue(custody.admits(CARD_A, heldFor = null, retention = retention))
            assertFalse("an entered PIN is verified on the card", custody.holds(it, CARD_A))
            assertTrue(custody.hold(it, checkNotNull(retention), custody.generation))
        }
    }

    private companion object {
        const val LATER_AUTHENTICATIONS = 3
        const val ONE_ATTEMPT_SPENT = FINEID_PIN_TRY_LIMIT - 1
        val CARD_A =
            checkNotNull(AuthenticationCardIdentity.of("synthetic authentication certificate A".encodeToByteArray()))
        val CARD_B =
            checkNotNull(AuthenticationCardIdentity.of("synthetic authentication certificate B".encodeToByteArray()))

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())
    }
}
