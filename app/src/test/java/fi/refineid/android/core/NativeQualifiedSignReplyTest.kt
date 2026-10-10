package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeQualifiedSignReplyTest {
    @Test
    fun acceptsOnlyBoundedSignedAttributeContent() {
        for (algorithm in QualifiedSigningAlgorithm.entries) {
            assertTrue(
                algorithm.acceptsContentLength(MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH),
            )
            assertFalse(
                algorithm.acceptsContentLength(
                    MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH + SINGLE_EXCESS_BYTE_COUNT,
                ),
            )
        }
    }

    @Test
    fun decodesEveryFixedSuccessShapeAndClearsTheBridgeReply() {
        for (algorithm in QualifiedSigningAlgorithm.entries) {
            val signature = ByteArray(algorithm.signatureLength) { SYNTHETIC_SIGNATURE_BYTE }
            val reply =
                byteArrayOf(
                    NativeQualifiedSignWire.SUCCESS_TAG.toByte(),
                    algorithm.wireValue.toByte(),
                ) + signature

            val result = NativeQualifiedSignReply.decode(reply)

            val success = result as NativeQualifiedSignResult.Success
            assertEquals(algorithm, success.signature.algorithm)
            assertArrayEquals(signature, success.signature.copyBytes())
            assertTrue(reply.all { it == ZERO_BYTE })
            success.signature.close()
        }
    }

    @Test
    fun rejectsMalformedSuccessAndPayloadBearingFailure() {
        val malformedSuccess =
            byteArrayOf(
                NativeQualifiedSignWire.SUCCESS_TAG.toByte(),
                NativeQualifiedSignWire.ALGORITHM_RSA_PKCS1_SHA384.toByte(),
                SYNTHETIC_SIGNATURE_BYTE,
            )
        val malformedFailure =
            byteArrayOf(
                NativeQualifiedSignWire.WRONG_PIN_TAG.toByte(),
                SYNTHETIC_SIGNATURE_BYTE,
            )

        for (reply in listOf(malformedSuccess, malformedFailure)) {
            val result = NativeQualifiedSignReply.decode(reply)

            assertEquals(
                NativeQualifiedSignFailure.BRIDGE_ERROR,
                (result as NativeQualifiedSignResult.Failure).kind,
            )
            assertTrue(reply.all { it == ZERO_BYTE })
        }
    }

    @Test
    fun decodesAWrongPinWithTheCardsRemainingCount() {
        val reply =
            byteArrayOf(
                NativeQualifiedSignWire.WRONG_PIN_TAG.toByte(),
                SYNTHETIC_RETRIES_LEFT.toByte(),
            )

        val result = NativeQualifiedSignReply.decode(reply)

        assertEquals(
            NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.WRONG_PIN, SYNTHETIC_RETRIES_LEFT),
            result,
        )
        assertTrue(reply.all { it == ZERO_BYTE })
    }

    @Test
    fun refusesAWrongPinWithoutAPositiveCount() {
        val replies =
            listOf(
                byteArrayOf(NativeQualifiedSignWire.WRONG_PIN_TAG.toByte()),
                byteArrayOf(NativeQualifiedSignWire.WRONG_PIN_TAG.toByte(), ZERO_BYTE),
                byteArrayOf(
                    NativeQualifiedSignWire.WRONG_PIN_TAG.toByte(),
                    (NativeQualifiedSignWire.MAXIMUM_RETRIES + 1).toByte(),
                ),
            )
        for (reply in replies) {
            assertEquals(
                NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR),
                NativeQualifiedSignReply.decode(reply),
            )
        }
    }

    @Test
    fun mapsEveryCoarseFailure() {
        val cases =
            listOf(
                NativeQualifiedSignWire.BRIDGE_ERROR_TAG to
                    NativeQualifiedSignFailure.BRIDGE_ERROR,
                NativeQualifiedSignWire.CARD_UNAVAILABLE_TAG to
                    NativeQualifiedSignFailure.CARD_UNAVAILABLE,
                NativeQualifiedSignWire.TRANSPORT_ERROR_TAG to
                    NativeQualifiedSignFailure.TRANSPORT_ERROR,
                NativeQualifiedSignWire.INVALID_PIN_TAG to
                    NativeQualifiedSignFailure.INVALID_PIN,
                NativeQualifiedSignWire.SAFETY_REFUSED_TAG to
                    NativeQualifiedSignFailure.SAFETY_REFUSED,
                NativeQualifiedSignWire.PIN_LOCKED_TAG to
                    NativeQualifiedSignFailure.PIN_LOCKED,
                NativeQualifiedSignWire.VERIFICATION_REJECTED_TAG to
                    NativeQualifiedSignFailure.VERIFICATION_REJECTED,
                NativeQualifiedSignWire.CERTIFICATE_REJECTED_TAG to
                    NativeQualifiedSignFailure.CERTIFICATE_REJECTED,
                NativeQualifiedSignWire.INVALID_CERTIFICATE_TAG to
                    NativeQualifiedSignFailure.INVALID_CERTIFICATE,
                NativeQualifiedSignWire.CERTIFICATE_MISMATCH_TAG to
                    NativeQualifiedSignFailure.CERTIFICATE_MISMATCH,
                NativeQualifiedSignWire.KEY_PROFILE_MISMATCH_TAG to
                    NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH,
                NativeQualifiedSignWire.SIGNING_REJECTED_TAG to
                    NativeQualifiedSignFailure.SIGNING_REJECTED,
            )

        for ((tag, expected) in cases) {
            val result = NativeQualifiedSignReply.decode(byteArrayOf(tag.toByte()))
            assertEquals(expected, (result as NativeQualifiedSignResult.Failure).kind)
        }
    }

    @Test
    fun pin2SubmissionAvoidsStringMaterializationAndIsConsumedOnce() {
        val input =
            object : CharSequence {
                private val characters = SYNTHETIC_PIN2_TEXT.toCharArray()

                override val length: Int = characters.size

                override fun get(index: Int): Char = characters[index]

                override fun subSequence(
                    startIndex: Int,
                    endIndex: Int,
                ): CharSequence = throw AssertionError("not needed")

                override fun toString(): String = throw AssertionError("must not materialize")
            }
        val submission = Pin2Submission.from(input)
        lateinit var consumedBytes: ByteArray

        submission.consume { bytes ->
            consumedBytes = bytes
            assertArrayEquals(SYNTHETIC_PIN2_TEXT.encodeToByteArray(), bytes)
        }

        assertTrue(consumedBytes.all { it == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) {
            submission.consume { _ -> }
        }
    }

    @Test
    fun pin2PredicatesEnforceTheSixThroughTwelveDigitRange() {
        assertTrue(Pin2Submission.acceptsEntry(TOO_SHORT_PIN2_TEXT))
        assertFalse(Pin2Submission.isComplete(TOO_SHORT_PIN2_TEXT))
        assertTrue(Pin2Submission.isComplete(SYNTHETIC_PIN2_TEXT))
        assertFalse(Pin2Submission.acceptsEntry(NON_DIGIT_PIN2_TEXT))
        assertFalse(Pin2Submission.acceptsEntry(OVERLENGTH_PIN2_TEXT))
        assertThrows(IllegalArgumentException::class.java) {
            Pin2Submission.from(TOO_SHORT_PIN2_TEXT)
        }
        assertEquals(
            "Pin2Submission([redacted])",
            Pin2Submission.from(SYNTHETIC_PIN2_TEXT).toString(),
        )
    }

    @Test
    fun signatureOwnerClearsItsBackingArrayOnClose() {
        val ownedBytes =
            ByteArray(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.signatureLength) {
                SYNTHETIC_SIGNATURE_BYTE
            }
        val signature =
            NativeQualifiedSignature(
                algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                ownedBytes = ownedBytes,
            )

        signature.close()

        assertTrue(ownedBytes.all { it == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) {
            signature.copyBytes()
        }
    }

    private companion object {
        const val SYNTHETIC_PIN2_TEXT = "135790"
        const val TOO_SHORT_PIN2_TEXT = "12345"
        const val NON_DIGIT_PIN2_TEXT = "12345a"
        const val OVERLENGTH_PIN2_TEXT = "0123456789012"
        const val SYNTHETIC_SIGNATURE_BYTE: Byte = 0x5A
        const val SYNTHETIC_RETRIES_LEFT = 2
        const val SINGLE_EXCESS_BYTE_COUNT = 1
        const val ZERO_BYTE: Byte = 0
    }
}
