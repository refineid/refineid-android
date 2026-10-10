// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

/**
 * Timing and session-opening rules for one wait on a contactless card.
 *
 * A wait ends after [IDLE_MILLISECONDS] without any change in the reader's
 * state, and never later than [LIMIT_MILLISECONDS] after it began. NFC
 * access always needs the card access number; while none is known the wait
 * is on the holder typing it, so only the limit applies then.
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

    private val AWAITING_ACCESS_NUMBER =
        setOf(
            NfcReaderStatus.WAITING_FOR_CARD,
            NfcReaderStatus.CHECKING,
            NfcReaderStatus.CARD_RECOGNIZED,
        )

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
