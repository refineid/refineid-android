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
 * activation scheme, activation needs and counters. The main screen's
 * routing and the card management screen's title and form all read this one
 * answer, so a view that depends on what the card is appears only once the
 * card has said it.
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
 * The title the card's answer decides, or null while no card has answered:
 * the screen draws no title before the card has said what it is.
 */
internal fun cardManagementTitle(health: CredentialHealth?): CardManagementTitle? =
    when {
        health == null -> null
        !health.activationNeeds.any -> CardManagementTitle.CARD_PINS
        health.scheme == NativePinReferenceScheme.ORGANIZATIONAL -> CardManagementTitle.ORGANISATION_CARD_ACTIVATION
        else -> CardManagementTitle.IDENTITY_CARD_ACTIVATION
    }

/**
 * Whether the card management screen waits before it is first drawn: a
 * readable card has not answered the probe yet, so the screen the holder
 * already sees stays until the card has said what it is.
 */
internal fun cardManagementAwaitsReading(
    cardReadable: Boolean,
    reading: CardHealthReading,
): Boolean = cardReadable && !reading.hasAnswered
