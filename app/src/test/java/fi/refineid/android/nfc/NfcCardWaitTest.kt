// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NfcCardWaitTest {
    @Test
    fun aQuietWaitEndsAfterTheIdleAllowance() {
        assertEquals(
            STARTED + NfcCardWait.IDLE_MILLISECONDS,
            NfcCardWait.deadline(startedAt = STARTED, lastChangeAt = STARTED, waitingOnHolder = false),
        )
    }

    @Test
    fun eachReaderChangeExtendsTheWait() {
        val changed = STARTED + CHANGE_AFTER
        assertEquals(
            changed + NfcCardWait.IDLE_MILLISECONDS,
            NfcCardWait.deadline(startedAt = STARTED, lastChangeAt = changed, waitingOnHolder = false),
        )
    }

    @Test
    fun noWaitOutlastsTheLimit() {
        val late = STARTED + NfcCardWait.LIMIT_MILLISECONDS
        assertEquals(
            STARTED + NfcCardWait.LIMIT_MILLISECONDS,
            NfcCardWait.deadline(startedAt = STARTED, lastChangeAt = late, waitingOnHolder = false),
        )
    }

    @Test
    fun aBackgroundedReaderWaitsOnTheHolder() {
        assertTrue(
            NfcCardWait.waitsOnHolder(
                status = NfcReaderStatus.NOT_AVAILABLE,
                accessNumberKnown = true,
                readerInFront = false,
            ),
        )
    }

    @Test
    fun aReaderInFrontWithAKnownAccessNumberWaitsOnTheCard() {
        assertFalse(
            NfcCardWait.waitsOnHolder(
                status = NfcReaderStatus.WAITING_FOR_CARD,
                accessNumberKnown = true,
                readerInFront = true,
            ),
        )
    }

    @Test
    fun typingTheAccessNumberRunsToTheLimit() {
        assertEquals(
            STARTED + NfcCardWait.LIMIT_MILLISECONDS,
            NfcCardWait.deadline(startedAt = STARTED, lastChangeAt = STARTED, waitingOnHolder = true),
        )
    }

    @Test
    fun nfcWithoutAKnownAccessNumberAsksForIt() {
        assertTrue(NfcCardWait.needsAccessNumber(NfcReaderStatus.WAITING_FOR_CARD, accessNumberKnown = false))
        assertTrue(NfcCardWait.needsAccessNumber(NfcReaderStatus.CARD_RECOGNIZED, accessNumberKnown = false))
        assertTrue(NfcCardWait.needsAccessNumber(NfcReaderStatus.WRONG_CAN, accessNumberKnown = true))
        assertFalse(NfcCardWait.needsAccessNumber(NfcReaderStatus.CARD_RECOGNIZED, accessNumberKnown = true))
        assertFalse(NfcCardWait.needsAccessNumber(NfcReaderStatus.CONNECTING, accessNumberKnown = false))
    }

    @Test
    fun aRecognizedCardWithAKnownAccessNumberIsOpened() {
        assertTrue(
            NfcCardWait.shouldOpenSession(
                NfcReaderStatus.CARD_RECOGNIZED,
                cardInField = true,
                accessNumberKnown = true,
                opening = false,
            ),
        )
    }

    @Test
    fun aSecondOpeningNeverStartsBesideTheFirst() {
        assertFalse(
            NfcCardWait.shouldOpenSession(
                NfcReaderStatus.CARD_RECOGNIZED,
                cardInField = true,
                accessNumberKnown = true,
                opening = true,
            ),
        )
    }

    @Test
    fun nothingOpensWithoutTheCardOrItsAccessNumber() {
        assertFalse(
            NfcCardWait.shouldOpenSession(
                NfcReaderStatus.CARD_RECOGNIZED,
                cardInField = false,
                accessNumberKnown = true,
                opening = false,
            ),
        )
        assertFalse(
            NfcCardWait.shouldOpenSession(
                NfcReaderStatus.CARD_RECOGNIZED,
                cardInField = true,
                accessNumberKnown = false,
                opening = false,
            ),
        )
        assertFalse(
            NfcCardWait.shouldOpenSession(
                NfcReaderStatus.CHECKING,
                cardInField = true,
                accessNumberKnown = true,
                opening = false,
            ),
        )
    }

    private companion object {
        const val STARTED = 1_000L
        const val CHANGE_AFTER = 12_000L
    }
}
