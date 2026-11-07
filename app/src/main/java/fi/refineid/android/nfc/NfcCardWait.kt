// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import fi.refineid.android.core.NfcCardKind

/**
 * Timing and session-opening rules for one wait on a contactless card.
 *
 * A wait ends after [IDLE_MILLISECONDS] without any change in the reader's
 * state, and never later than [LIMIT_MILLISECONDS] after it began. NFC
 * access always needs the card access number; while none is known the wait
 * is on the holder typing it, so only the limit applies then. The same holds
 * while RefineID is not in front: Android reads NFC only for the foreground
 * app, so the wait is on the holder opening it.
 */
internal object NfcCardWait {
    const val IDLE_MILLISECONDS = 30_000L
    const val LIMIT_MILLISECONDS = 90_000L

    /** Whether the holder must give the access number before NFC can open the card. */
    fun needsAccessNumber(
        status: NfcReaderStatus,
        accessNumberKnown: Boolean,
    ): Boolean =
        status == NfcReaderStatus.WRONG_CAN ||
            (!accessNumberKnown && status in AWAITING_ACCESS_NUMBER)

    /**
     * Whether a prompt asks for the access number now: the card in the field
     * named itself a citizen card and none is known, or it refused the one
     * given. An organization card has none to ask for, and until a card has
     * answered its kind is not known.
     */
    fun asksForAccessNumber(
        status: NfcReaderStatus,
        accessNumberKnown: Boolean,
        cardKind: NfcCardKind?,
    ): Boolean =
        status == NfcReaderStatus.WRONG_CAN ||
            (!accessNumberKnown && status == NfcReaderStatus.CARD_RECOGNIZED && cardKind == NfcCardKind.PERSONAL)

    /** Whether a prompt asks for Basic PIN 1: an organization card is in the field and not yet read. */
    fun asksForOrganizationPin1(
        status: NfcReaderStatus,
        cardKind: NfcCardKind?,
    ): Boolean = status == NfcReaderStatus.CARD_RECOGNIZED && cardKind == NfcCardKind.ORGANIZATION

    private val AWAITING_ACCESS_NUMBER =
        setOf(
            NfcReaderStatus.WAITING_FOR_CARD,
            NfcReaderStatus.CHECKING,
            NfcReaderStatus.CARD_RECOGNIZED,
        )

    /** Whether the wait is on the holder rather than on the reader. */
    fun waitsOnHolder(
        status: NfcReaderStatus,
        accessNumberKnown: Boolean,
        readerInFront: Boolean,
    ): Boolean = !readerInFront || needsAccessNumber(status, accessNumberKnown)

    /** The instant a wait begun at [startedAt] gives up. */
    fun deadline(
        startedAt: Long,
        lastChangeAt: Long,
        waitingOnHolder: Boolean,
    ): Long {
        val limit = startedAt + LIMIT_MILLISECONDS
        return if (waitingOnHolder) limit else minOf(lastChangeAt + IDLE_MILLISECONDS, limit)
    }

    /**
     * Whether a wait should open a session on the card now: it is recognized
     * and still in the field, its access number is known, and no opening is
     * already under way.
     */
    fun shouldOpenSession(
        status: NfcReaderStatus,
        cardInField: Boolean,
        accessNumberKnown: Boolean,
        opening: Boolean,
    ): Boolean =
        status == NfcReaderStatus.CARD_RECOGNIZED &&
            cardInField &&
            accessNumberKnown &&
            !opening
}
