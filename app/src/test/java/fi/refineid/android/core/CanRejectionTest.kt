@file:Suppress("MagicNumber")
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
        CanSessionStore.remember("123456")
        assertTrue(CanSessionStore.hasCan)

        CanSessionStore.drop()

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
    }

    @Test
    fun theSameCanIsAcceptedAgainRightAfterADrop() {
        CanSessionStore.remember("123456")
        CanSessionStore.drop()

        CanSessionStore.remember("123456")

        assertEquals("123456", CanSessionStore.currentCan)
    }

    @Test
    fun aSubmissionAfterADropIsRememberedAtOnce() {
        CanSessionStore.remember("123456")
        CanSessionStore.drop()

        CanSessionStore.remember(CanSubmission.from("654321"))

        assertEquals("654321", CanSessionStore.currentCan)
    }
}
