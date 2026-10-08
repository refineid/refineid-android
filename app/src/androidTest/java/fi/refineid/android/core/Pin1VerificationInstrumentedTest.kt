package fi.refineid.android.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises the shipped JNI boundary with a synthetic card, without touching hardware. */
@RunWith(AndroidJUnit4::class)
internal class Pin1VerificationInstrumentedTest {
    @Test
    fun standaloneVerificationUsesCredentialVerifyWithoutSigning() {
        assertTrue(NativeCore.isLoaded)
        val exchange = SyntheticCard()
        val candidate = Pin1Submission.fromOwnedBytes(ByteArray(PIN1_MINIMUM_LENGTH) { DIGIT_ZERO_BYTE })
        val result = NativePin1Verification.verify(candidate, exchange)
        assertEquals(2, exchange.publicCalls)
        assertEquals(Pin1VerificationResult.VERIFIED, result)
        assertEquals(1, exchange.credentialCalls)
        assertTrue(runCatching { candidate.copyBytes() }.isFailure)
    }

    @Test
    fun malformedPreflightNeverPresentsCredential() {
        val exchange = SyntheticCard(malformed = true)
        val candidate = Pin1Submission.fromOwnedBytes(ByteArray(PIN1_MINIMUM_LENGTH) { DIGIT_ZERO_BYTE })
        assertEquals(Pin1VerificationResult.TRANSPORT_ERROR, NativePin1Verification.verify(candidate, exchange))
        assertEquals(0, exchange.credentialCalls)
    }

    private class SyntheticCard(
        private val malformed: Boolean = false,
    ) : NativeBlockExchange {
        var credentialCalls = 0
        var publicCalls = 0

        override fun exchangePublic(block: ByteArray): ByteArray {
            publicCalls++
            return when (block[INSTRUCTION_OFFSET]) {
                SELECT -> {
                    reply(SUCCESS_SW1, SUCCESS_SW2)
                }

                VERIFY -> {
                    if (malformed) {
                        byteArrayOf(
                            NativeExchangeReplyTag.RESPONSE.wireValue,
                        )
                    } else {
                        reply(RETRIES_SW1, PRISTINE_SW2)
                    }
                }

                else -> {
                    error("unexpected public operation")
                }
            }
        }

        override fun exchangeCredential(block: ByteArray): ByteArray {
            assertEquals(VERIFY, block[INSTRUCTION_OFFSET])
            credentialCalls++
            return reply(SUCCESS_SW1, SUCCESS_SW2)
        }
    }

    private companion object {
        const val INSTRUCTION_OFFSET = 1
        const val SELECT: Byte = 0xA4.toByte()
        const val VERIFY: Byte = 0x20
        const val SUCCESS_SW1: Byte = 0x90.toByte()
        const val SUCCESS_SW2: Byte = 0x00
        const val RETRIES_SW1: Byte = 0x63
        const val PRISTINE_SW2: Byte = 0xC5.toByte()

        fun reply(
            sw1: Byte,
            sw2: Byte,
        ): ByteArray = byteArrayOf(NativeExchangeReplyTag.RESPONSE.wireValue, sw1, sw2)
    }
}
