// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CanRejectionTest {
    @Before
    fun setUp() {
        CanSessionStore.clearForTesting()
    }

    @Test
    fun rejectionDropsTheCanWithoutATrace() {
        CanSessionStore.remember(FIRST_CAN)
        assertTrue(CanSessionStore.hasCan)

        CanSessionStore.drop()

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
    }

    @Test
    fun theSameCanIsAcceptedAgainRightAfterADrop() {
        CanSessionStore.remember(FIRST_CAN)
        CanSessionStore.drop()

        CanSessionStore.remember(FIRST_CAN)

        assertEquals(FIRST_CAN, CanSessionStore.currentCan)
    }

    @Test
    fun aSubmissionAfterADropIsRememberedAtOnce() {
        CanSessionStore.remember(FIRST_CAN)
        CanSessionStore.drop()

        CanSessionStore.remember(CanSubmission.from(SECOND_CAN))

        assertEquals(SECOND_CAN, CanSessionStore.currentCan)
    }
}

private const val FIRST_CAN = "123456"
private const val SECOND_CAN = "654321"
