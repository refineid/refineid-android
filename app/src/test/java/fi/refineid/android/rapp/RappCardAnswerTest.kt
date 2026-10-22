// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.QualifiedSignFailure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * A wrong PIN is the holder's to correct while the card allows at least the
 * floor; every other refusal ends the operation with its registered error
 * (RAPP v26.10.21 sections 10.2 and 10.3).
 */
class RappCardAnswerTest {
    private companion object {
        const val FLOOR = RappCardAnswer.MINIMUM_REMAINING_ATTEMPTS

        /** The attempts a wrong PIN at the floor leaves, below it. */
        const val BELOW_FLOOR = 2

        /** A blocked PIN's count. */
        const val BLOCKED = 0
    }

    private fun ends(answer: RappCardAnswer): RappCardFailure = (answer as RappCardAnswer.Ends).failure

    @Test
    fun aWrongPinAtTheFloorAsksAgainWithTheCount() {
        val answer = RappCardAnswer.of(AuthenticationSignFailure.WRONG_PIN, FLOOR) as RappCardAnswer.WrongPin
        assertEquals(FLOOR, answer.attemptsLeft)
        val qualified = RappCardAnswer.of(QualifiedSignFailure.WRONG_PIN, FLOOR) as RappCardAnswer.WrongPin
        assertEquals(FLOOR, qualified.attemptsLeft)
    }

    @Test
    fun aWrongPinBelowTheFloorOrWithoutACountEndsAtTheFloor() {
        for (remaining in listOf(BELOW_FLOOR, BLOCKED, null)) {
            assertEquals(
                RappCardFailure.RETRY_FLOOR,
                ends(RappCardAnswer.of(AuthenticationSignFailure.WRONG_PIN, remaining)),
            )
            assertEquals(
                RappCardFailure.RETRY_FLOOR,
                ends(RappCardAnswer.of(QualifiedSignFailure.WRONG_PIN, remaining)),
            )
        }
        assertNull(RappCardAnswer.WrongPin.after(BELOW_FLOOR))
    }

    @Test
    fun aRefusalBeforeAnyVerificationAndABlockedPinEndAtTheFloor() {
        for (failure in listOf(AuthenticationSignFailure.SAFETY_REFUSED, AuthenticationSignFailure.PIN_LOCKED)) {
            assertEquals(RappCardFailure.RETRY_FLOOR, ends(RappCardAnswer.of(failure, null)))
        }
        for (failure in listOf(QualifiedSignFailure.SAFETY_REFUSED, QualifiedSignFailure.PIN_LOCKED)) {
            assertEquals(RappCardFailure.RETRY_FLOOR, ends(RappCardAnswer.of(failure, null)))
        }
    }

    @Test
    fun aCardThatDidNotAnswerIsACardError() {
        for (failure in listOf(
            AuthenticationSignFailure.CARD_UNAVAILABLE,
            AuthenticationSignFailure.TRANSPORT_ERROR,
            AuthenticationSignFailure.BRIDGE_ERROR,
        )) {
            assertEquals(RappCardFailure.CARD_ERROR, ends(RappCardAnswer.of(failure, null)))
        }
        assertEquals(
            RappCardFailure.CARD_ERROR,
            ends(RappCardAnswer.of(QualifiedSignFailure.CERTIFICATE_MISMATCH, null)),
        )
    }

    @Test
    fun aKeyTheCardDoesNotHoldIsUnsupportedAndAnythingElseFails() {
        assertEquals(
            RappCardFailure.UNSUPPORTED,
            ends(RappCardAnswer.of(AuthenticationSignFailure.KEY_PROFILE_MISMATCH, null)),
        )
        assertEquals(
            RappCardFailure.UNSUPPORTED,
            ends(RappCardAnswer.of(QualifiedSignFailure.KEY_PROFILE_MISMATCH, null)),
        )
        assertEquals(
            RappCardFailure.OPERATION_FAILED,
            ends(RappCardAnswer.of(AuthenticationSignFailure.SIGNING_REJECTED, null)),
        )
        assertEquals(
            RappCardFailure.OPERATION_FAILED,
            ends(RappCardAnswer.of(QualifiedSignFailure.VERIFICATION_REJECTED, null)),
        )
    }

    @Test
    fun aPinThePhoneAlreadyKnewWrongIsAskedAgainWithoutACount() {
        assertNull(RappCardAnswer.WrongPin.ALREADY_REJECTED.attemptsLeft)
    }
}
