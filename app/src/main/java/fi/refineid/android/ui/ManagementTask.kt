// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State

internal enum class ManagementTask {
    CHANGE_PIN1,
    CHANGE_PIN2,
    RESET_PIN1,
    RESET_PIN2,
    ACTIVATE_CARD,
}

/**
 * The notice a PIN change the card answered but did not take shows: a blocked
 * PIN names the PUK reset, anything else is an error whose count the next
 * reading of the card puts in the banner.
 */
internal fun changeRefusalNotice(
    outcome: ManageOutcome,
    task: ManagementTask,
): Int =
    when {
        outcome !is ManageOutcome.Locked -> R.string.error
        task == ManagementTask.CHANGE_PIN1 -> R.string.pin1_blocked
        else -> R.string.pin2_blocked
    }

/**
 * The task a card's answer selects: activation while it awaits activation,
 * the reset of a locked PIN, otherwise the task already chosen.
 */
internal fun taskAfterAnswer(
    health: CredentialHealth?,
    current: ManagementTask,
): ManagementTask =
    when {
        health == null -> current
        health.activationNeeds.any -> ManagementTask.ACTIVATE_CARD
        health.pin1State is NativePin1State.Locked -> ManagementTask.RESET_PIN1
        health.pin2State is NativePin2State.Locked -> ManagementTask.RESET_PIN2
        current == ManagementTask.ACTIVATE_CARD -> ManagementTask.CHANGE_PIN1
        else -> current
    }
