@file:Suppress("MagicNumber")

// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import fi.refineid.android.nfc.NfcReaderStatus
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
    fun remembersValidCanAndDropsOnRejection() {
        CanSessionStore.remember("123456")
        assertTrue(CanSessionStore.hasCan)
        assertEquals("123456", CanSessionStore.currentCan)

        // Simulate wrong CAN rejection event
        val status = NfcReaderStatus.WRONG_CAN
        if (status == NfcReaderStatus.WRONG_CAN) {
            CanSessionStore.recordRejected("123456")
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertNull(CanSessionStore.canBytes())
        assertTrue(CanSessionStore.isBlocked("123456"))
    }

    @Test
    fun dropsOnWrongAccessNumberInUsbReader() {
        CanSessionStore.remember("654321")
        assertTrue(CanSessionStore.hasCan)

        val status = fi.refineid.android.usb.ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        if (status == fi.refineid.android.usb.ReaderConnectionStatus.WRONG_ACCESS_NUMBER) {
            CanSessionStore.recordRejected("654321")
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertTrue(CanSessionStore.isBlocked("654321"))
    }

    @Test
    fun dropsOnPaceRejectedCertificateReadFailure() {
        CanSessionStore.remember("112233")
        assertTrue(CanSessionStore.hasCan)

        val failure = NativeCertificateReadFailure.PACE_REJECTED
        if (failure == NativeCertificateReadFailure.PACE_REJECTED) {
            CanSessionStore.recordRejected("112233")
        }

        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertTrue(CanSessionStore.isBlocked("112233"))
    }

    @Test
    fun blocklistCooldownBlocksRejectedCanForCooldownDuration() {
        val baseTime = 1_000_000L
        CanSessionStore.remember("987654", now = baseTime)
        CanSessionStore.recordRejected("987654", now = baseTime)

        assertFalse(CanSessionStore.hasCan)
        assertTrue(CanSessionStore.isBlocked("987654", now = baseTime))
        assertEquals(5, CanSessionStore.remainingCooldownSeconds("987654", now = baseTime))

        // After 2 seconds, remaining cooldown is 3
        assertEquals(3, CanSessionStore.remainingCooldownSeconds("987654", now = baseTime + 2_000L))
        assertTrue(CanSessionStore.isBlocked("987654", now = baseTime + 2_000L))

        // Attempting to remember blocked CAN while cooldown is active is ignored
        CanSessionStore.remember("987654", now = baseTime)
        assertFalse(CanSessionStore.hasCan)

        // Remembering a different (non-blocked) CAN is permitted immediately
        CanSessionStore.remember("654321", now = baseTime)
        assertTrue(CanSessionStore.hasCan)
        assertEquals("654321", CanSessionStore.currentCan)

        // After 5 seconds, cooldown has expired
        val expiryTime = baseTime + CanSessionStore.BLOCKLIST_DURATION_MS
        assertFalse(CanSessionStore.isBlocked("987654", now = expiryTime))
        assertEquals(0, CanSessionStore.remainingCooldownSeconds("987654", now = expiryTime))
        CanSessionStore.remember("987654", now = expiryTime)
        assertTrue(CanSessionStore.hasCan)
        assertEquals("987654", CanSessionStore.currentCan)
    }

    @Test
    fun clearsCanOnReaderDetachedAndPreservesBlocklist() {
        val baseTime = 2_000_000L
        CanSessionStore.remember("987654", now = baseTime)
        CanSessionStore.recordRejected("987654", now = baseTime)
        CanSessionStore.remember("123456", now = baseTime)
        assertTrue(CanSessionStore.hasCan)
        assertEquals("123456", CanSessionStore.currentCan)

        // Detaching reader clears the active CAN cache, but blocklist cooldown remains intact
        CanSessionStore.drop()
        assertFalse(CanSessionStore.hasCan)
        assertNull(CanSessionStore.currentCan)
        assertTrue(CanSessionStore.isBlocked("987654", now = baseTime))
    }

    @Test
    fun explicitSubmissionUnblocksAndRemembersCan() {
        val baseTime = 3_000_000L
        CanSessionStore.remember("123456", now = baseTime)
        CanSessionStore.recordRejected("123456", now = baseTime)
        assertTrue(CanSessionStore.isBlocked("123456", now = baseTime))
        assertFalse(CanSessionStore.hasCan)

        val submission = CanSubmission.from("123456")
        CanSessionStore.remember(submission)
        assertFalse(CanSessionStore.isBlocked("123456", now = baseTime))
        assertTrue(CanSessionStore.hasCan)
        assertEquals("123456", CanSessionStore.currentCan)
    }
}
