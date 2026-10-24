package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeContactlessOpenReplyTest {
    @Test
    fun decodesNestedPreflightAndCertificate() {
        val reply = successReply()

        val result = NativeContactlessOpenReply.decode(reply) as NativeContactlessOpenResult.Success

        assertEquals(
            NativePin1Preflight(
                referenceScheme = NativePinReferenceScheme.CITIZEN,
                state = NativePin1State.Remaining(SYNTHETIC_RETRY_COUNT.toInt()),
                retryFloorPermits = true,
            ),
            result.preflight,
        )
        assertEquals(NativeCardKeyProfile.RSA_3072, result.certificate.keyProfile)
        assertArrayEquals(SYNTHETIC_DER, result.certificate.copyDer())
        assertTrue(reply.all { it == ZERO_BYTE })
        result.certificate.close()
    }

    @Test
    fun decodesActivationRequiredWithCertificate() {
        val reply =
            byteArrayOf(
                CERTIFICATE_ACTIVATION_REQUIRED,
                KEY_PROFILE_RSA_3072,
                *SYNTHETIC_DER,
            )
        val result = NativeContactlessOpenReply.decode(reply) as NativeContactlessOpenResult.ActivationRequired
        assertEquals(NativeCardKeyProfile.RSA_3072, result.certificate.keyProfile)
        assertArrayEquals(SYNTHETIC_DER, result.certificate.copyDer())
        result.certificate.close()
    }

    @Test
    fun decodesEveryCertificateVocabularyFailure() {
        val expected =
            mapOf(
                CERTIFICATE_CARD_UNAVAILABLE to NativeCertificateReadFailure.CARD_UNAVAILABLE,
                CERTIFICATE_REJECTED to NativeCertificateReadFailure.REJECTED,
                CERTIFICATE_TRANSPORT_ERROR to NativeCertificateReadFailure.TRANSPORT_ERROR,
                CERTIFICATE_INVALID to NativeCertificateReadFailure.INVALID_CERTIFICATE,
                CERTIFICATE_PACE_REJECTED to NativeCertificateReadFailure.PACE_REJECTED,
                CERTIFICATE_BRIDGE_ERROR to NativeCertificateReadFailure.BRIDGE_ERROR,
                CERTIFICATE_ACTIVATION_REQUIRED to NativeCertificateReadFailure.ACTIVATION_REQUIRED,
            )
        expected.forEach { (tag, kind) ->
            assertEquals(
                NativeContactlessOpenResult.Failure(kind),
                NativeContactlessOpenReply.decode(byteArrayOf(tag)),
            )
        }
    }

    @Test
    fun rejectsMalformedNestedShapes() {
        val truncatedAtPreflight = successReply().copyOfRange(0, WRAPPER_HEADER_LENGTH + 2)
        val wrongPreflightLength =
            successReply().also { it[PREFLIGHT_LENGTH_OFFSET] = WRONG_PREFLIGHT_LENGTH }
        val failureTaggedPreflight =
            successReply().also { it[WRAPPER_HEADER_LENGTH] = CERTIFICATE_CARD_UNAVAILABLE }
        val failureTaggedCertificate =
            successReply().also {
                it[WRAPPER_HEADER_LENGTH + PREFLIGHT_REPLY_LENGTH] = CERTIFICATE_TRANSPORT_ERROR
            }
        val malformed =
            listOf(
                byteArrayOf(),
                byteArrayOf(OPEN_SUCCEEDED),
                truncatedAtPreflight,
                wrongPreflightLength,
                failureTaggedPreflight,
                failureTaggedCertificate,
                byteArrayOf(CERTIFICATE_TRANSPORT_ERROR, TRAILING_GARBAGE),
                byteArrayOf(UNKNOWN_TAG),
            )
        malformed.forEach { reply ->
            assertEquals(
                NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR),
                NativeContactlessOpenReply.decode(reply),
            )
        }
    }

    private fun successReply(): ByteArray =
        byteArrayOf(
            OPEN_SUCCEEDED,
            PREFLIGHT_REPLY_LENGTH,
            PREFLIGHT_SUCCEEDED,
            PIN_REFERENCE_CITIZEN,
            PIN1_STATE_REMAINING,
            SYNTHETIC_RETRY_COUNT,
            POLICY_PERMITTED,
            CERTIFICATE_SUCCEEDED,
            KEY_PROFILE_RSA_3072,
            *SYNTHETIC_DER,
        )

    private companion object {
        const val OPEN_SUCCEEDED: Byte = 1
        const val CERTIFICATE_BRIDGE_ERROR: Byte = 0
        const val CERTIFICATE_SUCCEEDED: Byte = 1
        const val CERTIFICATE_CARD_UNAVAILABLE: Byte = 2
        const val CERTIFICATE_REJECTED: Byte = 3
        const val CERTIFICATE_TRANSPORT_ERROR: Byte = 4
        const val CERTIFICATE_INVALID: Byte = 5
        const val CERTIFICATE_PACE_REJECTED: Byte = 6
        const val CERTIFICATE_ACTIVATION_REQUIRED: Byte = 7
        const val PREFLIGHT_SUCCEEDED: Byte = 1
        const val PIN_REFERENCE_CITIZEN: Byte = 0
        const val PIN1_STATE_REMAINING: Byte = 1
        const val POLICY_PERMITTED: Byte = 1
        const val KEY_PROFILE_RSA_3072: Byte = 1
        const val PREFLIGHT_REPLY_LENGTH: Byte = 5
        const val WRONG_PREFLIGHT_LENGTH: Byte = 4
        const val PREFLIGHT_LENGTH_OFFSET = 1
        const val WRAPPER_HEADER_LENGTH = 2
        const val SYNTHETIC_RETRY_COUNT: Byte = 3
        const val UNKNOWN_TAG: Byte = 8
        const val TRAILING_GARBAGE: Byte = 0x7F
        const val ZERO_BYTE: Byte = 0
        val SYNTHETIC_DER = byteArrayOf(0x30, 0x00)
    }
}
