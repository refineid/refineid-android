package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class Pin1VerificationOutcomeTest {
    @Test
    fun onlyFirstRejectionRecordsAndInvalidates() {
        val cache = AuthenticationPinCache()
        var invalidations = 0
        Pin1VerificationOutcome(syntheticDigits(), cache) { invalidations++ }.use { outcome ->
            outcome.report(Pin1VerificationResult.WRONG_PIN)
            outcome.report(Pin1VerificationResult.WRONG_PIN)
            outcome.report(Pin1VerificationResult.PIN_LOCKED)
        }
        assertEquals(1, invalidations)
        assertTrue(cache.isRejected(syntheticDigits()))
    }

    @Test
    fun lockedCardInvalidatesWithoutRecordingUntestedDigits() {
        val cache = AuthenticationPinCache()
        val digits = syntheticDigits()
        var invalidations = 0
        Pin1VerificationOutcome(digits, cache) { invalidations++ }.use { outcome ->
            outcome.report(Pin1VerificationResult.PIN_LOCKED)
        }
        assertEquals(1, invalidations)
        assertFalse(cache.isRejected(syntheticDigits()))
        assertTrue(digits.all { it == CLEARED_BYTE })
    }

    @Test
    fun nonRejectionAnswersLeaveCustodyAndCloseZeroesCopy() {
        val cache = AuthenticationPinCache()
        val digits = syntheticDigits()
        var invalidations = 0
        Pin1VerificationOutcome(digits, cache) { invalidations++ }.use { outcome ->
            outcome.report(Pin1VerificationResult.VERIFIED)
            outcome.report(Pin1VerificationResult.TRANSPORT_ERROR)
            outcome.report(Pin1VerificationResult.CARD_UNAVAILABLE)
        }
        assertEquals(0, invalidations)
        assertFalse(cache.isRejected(syntheticDigits()))
        assertTrue(digits.all { it == CLEARED_BYTE })
    }

    private companion object {
        const val CLEARED_BYTE: Byte = 0
        const val DIGIT_ZERO = '0'.code.toByte()

        fun syntheticDigits(): ByteArray = ByteArray(PIN1_MINIMUM_LENGTH) { DIGIT_ZERO }
    }
}
