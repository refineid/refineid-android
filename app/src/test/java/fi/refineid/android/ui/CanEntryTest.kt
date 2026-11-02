// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import fi.refineid.android.core.CanSessionStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CanEntryTest {
    @Before
    fun setUp() {
        CanSessionStore.clearForTesting()
    }

    @Test
    fun emptyFieldWithoutRememberedCanIsNotReady() {
        assertFalse(canEntryReady(""))
        assertNull(canEntrySubmission(""))
    }

    @Test
    fun emptyFieldSubmitsRememberedCan() {
        CanSessionStore.remember(REMEMBERED_CAN)
        assertTrue(canEntryReady(""))
        assertArrayEquals(REMEMBERED_CAN.toByteArray(Charsets.US_ASCII), canEntrySubmission("")?.transfer())
    }

    @Test
    fun typedDigitsWinOverRememberedCan() {
        CanSessionStore.remember(REMEMBERED_CAN)
        assertArrayEquals(
            TYPED_CAN.toByteArray(Charsets.US_ASCII),
            canEntrySubmission(TYPED_CAN)?.transfer(),
        )
    }

    @Test
    fun partialEntryIsNotReadyEvenWithRememberedCan() {
        CanSessionStore.remember(REMEMBERED_CAN)
        assertFalse(canEntryReady(PARTIAL_CAN))
        assertNull(canEntrySubmission(PARTIAL_CAN))
    }

    private companion object {
        const val REMEMBERED_CAN = "123456"
        const val TYPED_CAN = "654321"
        const val PARTIAL_CAN = "123"
    }
}
