package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

internal class NativePin1VerificationTest {
    @Test
    fun decodesVerificationAndRejectionWithoutAcceptingSigningPayloads() {
        val success = byteArrayOf(VERIFIED_TAG)
        assertEquals(Pin1VerificationResult.VERIFIED, NativePin1Verification.decode(success))
        assertTrue(success.all { it == CLEARED_BYTE })
        assertEquals(Pin1VerificationResult.WRONG_PIN, NativePin1Verification.decode(byteArrayOf(WRONG_PIN_TAG)))
        val malformed = listOf(byteArrayOf(), byteArrayOf(VERIFIED_TAG, VERIFIED_TAG), byteArrayOf(UNKNOWN_TAG))
        malformed.forEach { reply ->
            assertEquals(Pin1VerificationResult.BRIDGE_ERROR, NativePin1Verification.decode(reply))
            assertTrue(reply.all { it == CLEARED_BYTE })
        }
    }

    private companion object {
        const val VERIFIED_TAG: Byte = 1
        const val WRONG_PIN_TAG: Byte = 7
        const val UNKNOWN_TAG: Byte = 127
        const val CLEARED_BYTE: Byte = 0
    }
}
