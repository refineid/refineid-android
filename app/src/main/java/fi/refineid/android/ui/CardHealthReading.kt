// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.NativePinReferenceScheme

/**
 * The credential probe's answer for the card the phone holds: its kind,
 * activation scheme, activation needs and counters. The card management
 * screen's title and form read this one answer; the screen opens before it
 * and fills in what the card says as it arrives.
 */
@Stable
internal class CardHealthReading {
    var health by mutableStateOf<CredentialHealth?>(null)
        private set
    var failure by mutableStateOf<CardManagementFailure?>(null)
        private set
    var isProbing by mutableStateOf(false)
        private set
    private var generation = 0

    val hasAnswered: Boolean get() = health != null || failure != null

    /** Asks the card for its credential health; [onAnswer] sees the result after this reading holds it. */
    fun probe(
        service: CardManagementService,
        onAnswer: (CardManagementResult<CredentialHealth>) -> Unit = {},
    ) {
        val asked = generation
        isProbing = true
        service.probeCredentialHealth { result ->
            if (asked != generation) return@probeCredentialHealth
            isProbing = false
            when (result) {
                is CardManagementResult.Success -> {
                    health = result.value
                    failure = null
                }

                is CardManagementResult.Failure -> {
                    failure = result.kind
                }
            }
            onAnswer(result)
        }
    }

    /** Drops the answer and any answer still on its way, so the next view asks the card again. */
    fun forget() {
        generation++
        health = null
        failure = null
        isProbing = false
    }
}

/** The card management screen's title, one per kind of screen. */
internal enum class CardManagementTitle {
    CARD_PINS,
    IDENTITY_CARD_ACTIVATION,
    ORGANISATION_CARD_ACTIVATION,
}

/**
 * The title the card's answer decides. Before any answer a card that
 * awaits no activation is shown its PINs; one awaiting activation has no
 * title until it has said whether it is an identity or an organisation
 * card.
 */
internal fun cardManagementTitle(
    health: CredentialHealth?,
    activationRequired: Boolean,
): CardManagementTitle? =
    when {
        health == null -> if (activationRequired) null else CardManagementTitle.CARD_PINS
        !health.activationNeeds.any -> CardManagementTitle.CARD_PINS
        health.scheme == NativePinReferenceScheme.ORGANIZATIONAL -> CardManagementTitle.ORGANISATION_CARD_ACTIVATION
        else -> CardManagementTitle.IDENTITY_CARD_ACTIVATION
    }
