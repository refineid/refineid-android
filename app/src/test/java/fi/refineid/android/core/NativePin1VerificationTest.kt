package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

internal class NativePin1VerificationTest {
    @Test
    fun decodesVerificationAndRejectionWithoutAcceptingSigningPayloads() {
        val success = byteArrayOf(VERIFIED_TAG)
        assertEquals(Pin1Verification(Pin1VerificationResult.VERIFIED), NativePin1Verification.decode(success))
        assertTrue(success.all { it == CLEARED_BYTE })
        val wrongPin = byteArrayOf(WRONG_PIN_TAG, SYNTHETIC_RETRIES_LEFT)
        assertEquals(
            Pin1Verification(Pin1VerificationResult.WRONG_PIN, SYNTHETIC_RETRIES_LEFT.toInt()),
            NativePin1Verification.decode(wrongPin),
        )
        assertTrue(wrongPin.all { it == CLEARED_BYTE })
        val malformed =
            listOf(
                byteArrayOf(),
                byteArrayOf(VERIFIED_TAG, VERIFIED_TAG),
                byteArrayOf(UNKNOWN_TAG),
                byteArrayOf(WRONG_PIN_TAG),
                byteArrayOf(WRONG_PIN_TAG, CLEARED_BYTE),
                byteArrayOf(WRONG_PIN_TAG, OUT_OF_RANGE_RETRIES),
            )
        malformed.forEach { reply ->
            assertEquals(Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR), NativePin1Verification.decode(reply))
            assertTrue(reply.all { it == CLEARED_BYTE })
        }
    }

    private companion object {
        const val VERIFIED_TAG: Byte = 1
        const val WRONG_PIN_TAG: Byte = 7
        const val UNKNOWN_TAG: Byte = 127
        const val SYNTHETIC_RETRIES_LEFT: Byte = 2
        const val OUT_OF_RANGE_RETRIES: Byte = 16
        const val CLEARED_BYTE: Byte = 0
    }
}
