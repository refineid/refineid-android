// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CardHealthReadingTest {
    @Test
    fun noTitleIsDecidedBeforeTheCardAnswers() {
        assertNull(cardManagementTitle(health = null))
    }

    @Test
    fun anOrganizationCardIsTitledByItsAnswer() {
        assertEquals(
            CardManagementTitle.ORGANISATION_CARD_ACTIVATION,
            cardManagementTitle(awaitingActivation(NativePinReferenceScheme.ORGANIZATIONAL)),
        )
    }

    @Test
    fun aCitizenCardIsTitledByItsAnswer() {
        assertEquals(
            CardManagementTitle.IDENTITY_CARD_ACTIVATION,
            cardManagementTitle(awaitingActivation(NativePinReferenceScheme.CITIZEN)),
        )
    }

    @Test
    fun anActivatedCardManagesPins() {
        assertEquals(CardManagementTitle.CARD_PINS, cardManagementTitle(activated()))
    }

    @Test
    fun theScreenWaitsForAReadableCardUntilItAnswers() {
        val service = HeldService()
        val reading = CardHealthReading()

        assertTrue(cardManagementAwaitsReading(cardReadable = true, reading = reading))
        assertFalse(cardManagementAwaitsReading(cardReadable = false, reading = reading))

        reading.probe(service)
        assertTrue(reading.isProbing)
        assertTrue(cardManagementAwaitsReading(cardReadable = true, reading = reading))

        service.answer(CardManagementResult.Success(awaitingActivation(NativePinReferenceScheme.ORGANIZATIONAL)))
        assertFalse(reading.isProbing)
        assertFalse(cardManagementAwaitsReading(cardReadable = true, reading = reading))
        assertEquals(NativePinReferenceScheme.ORGANIZATIONAL, reading.health?.scheme)
    }

    @Test
    fun aFailedProbeIsAnAnswer() {
        val service = HeldService()
        val reading = CardHealthReading()

        reading.probe(service)
        service.answer(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        assertNull(reading.health)
        assertEquals(CardManagementFailure.CARD_UNAVAILABLE, reading.failure)
        assertFalse(cardManagementAwaitsReading(cardReadable = true, reading = reading))
    }

    @Test
    fun anAnswerArrivingAfterForgetIsDropped() {
        val service = HeldService()
        val reading = CardHealthReading()
        var answered = false

        reading.probe(service) { answered = true }
        reading.forget()
        service.answer(CardManagementResult.Success(awaitingActivation(NativePinReferenceScheme.CITIZEN)))

        assertNull(reading.health)
        assertFalse(reading.isProbing)
        assertFalse(answered)
        assertTrue(cardManagementAwaitsReading(cardReadable = true, reading = reading))
    }

    private fun awaitingActivation(scheme: NativePinReferenceScheme) =
        CredentialHealth(
            pin1State = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
            pin2State = NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT),
            pukState = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
            scheme = scheme,
            activationScheme = CardManagementScheme.PUK,
            activationNeeds = CardActivationNeeds(pin1 = true, pin2 = true),
        )

    private fun activated() =
        awaitingActivation(NativePinReferenceScheme.CITIZEN)
            .copy(activationNeeds = CardActivationNeeds(pin1 = false, pin2 = false))

    /** Holds each credential probe until the test answers it. */
    private class HeldService : CardManagementService {
        private var pending: ((CardManagementResult<CredentialHealth>) -> Unit)? = null

        fun answer(result: CardManagementResult<CredentialHealth>) {
            pending?.invoke(result)
            pending = null
        }

        override fun probeCredentialHealth(onResult: (CardManagementResult<CredentialHealth>) -> Unit) {
            pending = onResult
        }

        override fun changePin1(
            currentPin: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun changePin2(
            currentPin: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun unblockPin1(
            puk: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun unblockPin2(
            puk: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun activateCard(
            scheme: CardManagementScheme,
            code: ByteArray,
            newPin1: ByteArray?,
            newPin2: ByteArray?,
            onResult: (CardManagementResult<ActivationReport>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
    }
}
