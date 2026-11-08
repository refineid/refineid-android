// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import org.junit.Assert.assertEquals
import org.junit.Test

class PinChangeTaskTest {
    @Test
    fun anOrganisationCardKeepsTheSignaturePin2ChangeChosen() {
        assertEquals(
            ManagementTask.CHANGE_PIN2,
            taskAfterAnswer(organisationCard(), ManagementTask.CHANGE_PIN2),
        )
    }

    @Test
    fun aWrongCurrentSignaturePin2KeepsTheChangeWithTheCardsCount() {
        val counted = organisationCard(NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT - 1))
        assertEquals(ManagementTask.CHANGE_PIN2, taskAfterAnswer(counted, ManagementTask.CHANGE_PIN2))
        assertEquals(
            R.string.error,
            changeRefusalNotice(ManageOutcome.WrongCredential(FINEID_PIN_TRY_LIMIT - 1), ManagementTask.CHANGE_PIN2),
        )
    }

    @Test
    fun aBlockedSignaturePin2OffersThePukReset() {
        assertEquals(
            R.string.pin2_blocked,
            changeRefusalNotice(ManageOutcome.Locked, ManagementTask.CHANGE_PIN2),
        )
        assertEquals(
            ManagementTask.RESET_PIN2,
            taskAfterAnswer(organisationCard(NativePin2State.Locked), ManagementTask.CHANGE_PIN2),
        )
    }

    @Test
    fun aBlockedBasicPin1NamesItsOwnReset() {
        assertEquals(
            R.string.pin1_blocked,
            changeRefusalNotice(ManageOutcome.Locked, ManagementTask.CHANGE_PIN1),
        )
    }

    private fun organisationCard(pin2State: NativePin2State = NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT)) =
        CredentialHealth(
            pin1State = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
            pin2State = pin2State,
            pukState = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
            scheme = NativePinReferenceScheme.ORGANIZATIONAL,
            activationScheme = CardManagementScheme.PUK,
            activationNeeds = CardActivationNeeds(pin1 = false, pin2 = false),
        )
}
