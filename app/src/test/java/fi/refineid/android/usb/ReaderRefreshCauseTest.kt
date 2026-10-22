// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.usb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReaderRefreshCauseTest {
    @Test
    fun anAttachLeavesThePromptToTheSystemsAssociationDialog() {
        assertFalse(
            shouldRequestReaderPermission(ReaderRefreshCause.DEVICE_ATTACHED, requestOutstanding = false),
        )
        assertFalse(
            shouldRequestReaderPermission(ReaderRefreshCause.ACTIVITY_INTENT, requestOutstanding = false),
        )
    }

    @Test
    fun theHoldersAnswerIsNeverFollowedByAnotherRequest() {
        assertFalse(
            shouldRequestReaderPermission(ReaderRefreshCause.PERMISSION_ANSWERED, requestOutstanding = false),
        )
    }

    @Test
    fun aStartInTheBackgroundOrADetachAsksNothing() {
        assertFalse(
            shouldRequestReaderPermission(ReaderRefreshCause.CONTROLLER_STARTED, requestOutstanding = false),
        )
        assertFalse(
            shouldRequestReaderPermission(ReaderRefreshCause.DEVICE_DETACHED, requestOutstanding = false),
        )
    }

    @Test
    fun theHolderBringingTheAppAReaderAsksOnce() {
        for (cause in HOLDER_CAUSES) {
            assertTrue("$cause asks", shouldRequestReaderPermission(cause, requestOutstanding = false))
            assertFalse("$cause asks again", shouldRequestReaderPermission(cause, requestOutstanding = true))
        }
    }

    @Test
    fun onlyTheHoldersMomentsMayAsk() {
        assertEquals(
            HOLDER_CAUSES,
            ReaderRefreshCause.entries.filter { it.mayAskHolder }.toSet(),
        )
    }

    private companion object {
        val HOLDER_CAUSES =
            setOf(
                ReaderRefreshCause.APP_FOREGROUND,
                ReaderRefreshCause.READER_SELECTED,
                ReaderRefreshCause.CARD_WANTED,
            )
    }
}
