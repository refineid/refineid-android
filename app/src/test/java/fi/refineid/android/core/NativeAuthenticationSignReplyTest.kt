package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeAuthenticationSignReplyTest {
    @Test
    fun mapsEveryMessageAndPrehashedRequestToItsStableWireCode() {
        val expectedPrehashedRequests =
            mapOf(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA256,
                AuthenticationSigningAlgorithm.RSA_PSS_SHA256 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA256,
                AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_ECDSA_P384_SHA256,
                AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_ECDSA_P384_SHA384,
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA384,
                AuthenticationSigningAlgorithm.RSA_PSS_SHA384 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA384,
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA512,
                AuthenticationSigningAlgorithm.RSA_PSS_SHA512 to
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA512,
            )

        for (algorithm in AuthenticationSigningAlgorithm.entries) {
            assertEquals(
                algorithm.wireValue,
                algorithm.requestWireValue(AuthenticationSigningInputMode.MESSAGE),
            )
            assertEquals(
                expectedPrehashedRequests.getValue(algorithm),
                algorithm.requestWireValue(AuthenticationSigningInputMode.PREHASHED),
            )
        }
    }

    @Test
    fun acceptsOnlyBoundedMessagesAndExactAlgorithmDigests() {
        for (algorithm in AuthenticationSigningAlgorithm.entries) {
            assertTrue(
                algorithm.acceptsInputLength(
                    AuthenticationSigningInputMode.MESSAGE,
                    MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH,
                ),
            )
            assertFalse(
                algorithm.acceptsInputLength(
                    AuthenticationSigningInputMode.MESSAGE,
                    MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH + SINGLE_EXCESS_BYTE_COUNT,
                ),
            )
            assertTrue(
                algorithm.acceptsInputLength(
                    AuthenticationSigningInputMode.PREHASHED,
                    algorithm.digestLength,
                ),
            )
            assertFalse(
                algorithm.acceptsInputLength(
                    AuthenticationSigningInputMode.PREHASHED,
                    algorithm.digestLength - SINGLE_MISSING_BYTE_COUNT,
                ),
            )
        }
    }

    @Test
    fun decodesEveryFixedSuccessShapeAndClearsTheBridgeReply() {
        for (algorithm in AuthenticationSigningAlgorithm.entries) {
            val signature = ByteArray(algorithm.signatureLength) { SYNTHETIC_SIGNATURE_BYTE }
            val reply =
                byteArrayOf(
                    NativeAuthenticationSignWire.SUCCESS_TAG.toByte(),
                    algorithm.wireValue.toByte(),
                ) + signature

            val result = NativeAuthenticationSignReply.decode(reply)

            assertTrue(result is NativeAuthenticationSignResult.Success)
            val success = result as NativeAuthenticationSignResult.Success
            assertEquals(algorithm, success.signature.algorithm)
            assertArrayEquals(signature, success.signature.copyBytes())
            assertTrue(reply.all { it == 0.toByte() })
            success.signature.close()
        }
    }

    @Test
    fun rejectsMalformedSuccessAndClearsIt() {
        val reply =
            byteArrayOf(
                NativeAuthenticationSignWire.SUCCESS_TAG.toByte(),
                NativeAuthenticationSignWire.ALGORITHM_RSA_PKCS1_SHA256.toByte(),
                SYNTHETIC_SIGNATURE_BYTE,
            )

        val result = NativeAuthenticationSignReply.decode(reply)

        assertEquals(
            NativeAuthenticationSignFailure.BRIDGE_ERROR,
            (result as NativeAuthenticationSignResult.Failure).kind,
        )
        assertTrue(reply.all { it == 0.toByte() })
    }

    @Test
    fun rejectsPayloadBearingFailure() {
        val reply =
            byteArrayOf(
                NativeAuthenticationSignWire.WRONG_PIN_TAG.toByte(),
                SYNTHETIC_SIGNATURE_BYTE,
            )

        val result = NativeAuthenticationSignReply.decode(reply)

        assertEquals(
            NativeAuthenticationSignFailure.BRIDGE_ERROR,
            (result as NativeAuthenticationSignResult.Failure).kind,
        )
        assertTrue(reply.all { it == 0.toByte() })
    }

    @Test
    fun decodesAWrongPinWithTheCardsRemainingCount() {
        val reply =
            byteArrayOf(
                NativeAuthenticationSignWire.WRONG_PIN_TAG.toByte(),
                SYNTHETIC_RETRIES_LEFT.toByte(),
            )

        val result = NativeAuthenticationSignReply.decode(reply)

        assertEquals(
            NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.WRONG_PIN, SYNTHETIC_RETRIES_LEFT),
            result,
        )
        assertTrue(reply.all { it == 0.toByte() })
    }

    @Test
    fun refusesAWrongPinWithoutAPositiveCount() {
        val replies =
            listOf(
                byteArrayOf(NativeAuthenticationSignWire.WRONG_PIN_TAG.toByte()),
                byteArrayOf(NativeAuthenticationSignWire.WRONG_PIN_TAG.toByte(), 0),
                byteArrayOf(
                    NativeAuthenticationSignWire.WRONG_PIN_TAG.toByte(),
                    (NativeAuthenticationSignWire.MAXIMUM_RETRIES + 1).toByte(),
                ),
            )
        for (reply in replies) {
            val result = NativeAuthenticationSignReply.decode(reply)
            assertEquals(
                NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR),
                result,
            )
        }
    }

    @Test
    fun mapsEveryCoarseFailure() {
        val expected =
            listOf(
                NativeAuthenticationSignFailure.BRIDGE_ERROR,
                NativeAuthenticationSignFailure.CARD_UNAVAILABLE,
                NativeAuthenticationSignFailure.TRANSPORT_ERROR,
                NativeAuthenticationSignFailure.INVALID_PIN,
                NativeAuthenticationSignFailure.SAFETY_REFUSED,
                NativeAuthenticationSignFailure.PIN_LOCKED,
                NativeAuthenticationSignFailure.VERIFICATION_REJECTED,
                NativeAuthenticationSignFailure.SIGNING_REJECTED,
                NativeAuthenticationSignFailure.PACE_REJECTED,
            )
        val tags =
            listOf(
                NativeAuthenticationSignWire.BRIDGE_ERROR_TAG,
                NativeAuthenticationSignWire.CARD_UNAVAILABLE_TAG,
                NativeAuthenticationSignWire.TRANSPORT_ERROR_TAG,
                NativeAuthenticationSignWire.INVALID_PIN_TAG,
                NativeAuthenticationSignWire.SAFETY_REFUSED_TAG,
                NativeAuthenticationSignWire.PIN_LOCKED_TAG,
                NativeAuthenticationSignWire.VERIFICATION_REJECTED_TAG,
                NativeAuthenticationSignWire.SIGNING_REJECTED_TAG,
                NativeAuthenticationSignWire.PACE_REJECTED_TAG,
            )
        for ((tag, failure) in tags.zip(expected)) {
            val result = NativeAuthenticationSignReply.decode(byteArrayOf(tag.toByte()))
            assertEquals(failure, (result as NativeAuthenticationSignResult.Failure).kind)
        }
    }

    @Test
    fun pinSubmissionDoesNotCreateAStringAndIsConsumedOnce() {
        val input =
            object : CharSequence {
                private val characters = SYNTHETIC_PIN_TEXT.toCharArray()

                override val length: Int = characters.size

                override fun get(index: Int): Char = characters[index]

                override fun subSequence(
                    startIndex: Int,
                    endIndex: Int,
                ): CharSequence = throw AssertionError("not needed")

                override fun toString(): String = throw AssertionError("must not materialize")
            }
        val submission = Pin1Submission.from(input)
        lateinit var consumedBytes: ByteArray

        submission.consume { bytes ->
            consumedBytes = bytes
            assertArrayEquals(SYNTHETIC_PIN_TEXT.encodeToByteArray(), bytes)
        }

        assertTrue(consumedBytes.all { it == 0.toByte() })
        assertThrows(IllegalStateException::class.java) {
            submission.consume { _ -> }
        }
    }

    @Test
    fun pinSubmissionRejectsInvalidShapesWithoutEchoingThem() {
        assertThrows(IllegalArgumentException::class.java) {
            Pin1Submission.from(TOO_SHORT_PIN_TEXT)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Pin1Submission.from(NON_DIGIT_PIN_TEXT)
        }
        assertEquals(
            "Pin1Submission([redacted])",
            Pin1Submission.from(SYNTHETIC_PIN_TEXT).toString(),
        )
    }

    @Test
    fun pinEntryPredicatesAllowOnlyACompleteDecimalPin() {
        assertTrue(Pin1Submission.acceptsEntry(TOO_SHORT_PIN_TEXT))
        assertFalse(Pin1Submission.isComplete(TOO_SHORT_PIN_TEXT))
        assertTrue(Pin1Submission.isComplete(SYNTHETIC_PIN_TEXT))
        assertFalse(Pin1Submission.acceptsEntry(NON_DIGIT_PIN_TEXT))
        assertFalse(Pin1Submission.acceptsEntry(TOO_LONG_PIN_TEXT))
    }

    @Test
    fun signatureOwnerClearsItsBackingArrayOnClose() {
        val ownedBytes =
            ByteArray(AuthenticationSigningAlgorithm.ECDSA_P384_SHA256.signatureLength) {
                SYNTHETIC_SIGNATURE_BYTE
            }
        val signature =
            NativeAuthenticationSignature(
                algorithm = AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
                ownedBytes = ownedBytes,
            )

        signature.close()

        assertTrue(ownedBytes.all { it == 0.toByte() })
        assertThrows(IllegalStateException::class.java) {
            signature.copyBytes()
        }
    }

    private companion object {
        const val SYNTHETIC_PIN_TEXT = "1357"
        const val TOO_SHORT_PIN_TEXT = "123"
        const val NON_DIGIT_PIN_TEXT = "123a"
        const val TOO_LONG_PIN_TEXT = "1234567890123"
        const val SYNTHETIC_SIGNATURE_BYTE: Byte = 0x5A
        const val SYNTHETIC_RETRIES_LEFT = 2
        const val SINGLE_EXCESS_BYTE_COUNT = 1
        const val SINGLE_MISSING_BYTE_COUNT = 1
    }
}
