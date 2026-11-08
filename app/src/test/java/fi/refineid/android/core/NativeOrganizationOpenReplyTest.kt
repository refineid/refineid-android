// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeOrganizationOpenReplyTest {
    @Test
    fun aWrongPinCarriesTheCardsCount() {
        val result =
            NativeOrganizationOpenReply.decode(
                byteArrayOf(OPEN_REFUSED, ANSWER_WRONG_PIN, SYNTHETIC_RETRIES),
            )
        assertEquals(
            NativeOrganizationOpenResult.Refused(
                Pin1Verification(Pin1VerificationResult.WRONG_PIN, SYNTHETIC_RETRIES.toInt()),
            ),
            result,
        )
    }

    @Test
    fun theFloorsRefusalIsTheCardsNotTheHolders() {
        assertEquals(
            NativeOrganizationOpenResult.Refused(Pin1Verification(Pin1VerificationResult.SAFETY_REFUSED)),
            NativeOrganizationOpenReply.decode(byteArrayOf(OPEN_REFUSED, ANSWER_SAFETY_REFUSED)),
        )
    }

    @Test
    fun aCardThatIsNotAnOrganizationCardIsNamedByItsAnswer() {
        assertEquals(
            NativeOrganizationOpenResult.Refused(Pin1Verification(Pin1VerificationResult.PACE_REJECTED)),
            NativeOrganizationOpenReply.decode(byteArrayOf(OPEN_REFUSED, ANSWER_PACE_REJECTED)),
        )
    }

    @Test
    fun anAuthenticationCertificateThatDidNotReadIsUnreadable() {
        assertEquals(
            NativeOrganizationOpenResult.Unreadable(NativeCertificateReadFailure.REJECTED),
            NativeOrganizationOpenReply.decode(
                byteArrayOf(
                    OPEN_ANSWERED,
                    ZERO,
                    ZERO,
                    ZERO,
                    ONE_OCTET,
                    CERTIFICATE_REJECTED,
                    CERTIFICATE_REJECTED,
                ),
            ),
        )
    }

    @Test
    fun malformedRepliesAreBridgeFaults() {
        val bridge = NativeOrganizationOpenResult.Refused(Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR))
        listOf(
            byteArrayOf(),
            byteArrayOf(UNKNOWN_TAG),
            byteArrayOf(OPEN_ANSWERED),
            byteArrayOf(OPEN_ANSWERED, ZERO, ZERO, ZERO, ZERO, CERTIFICATE_REJECTED),
            byteArrayOf(OPEN_ANSWERED, ZERO, ZERO, ZERO, ONE_OCTET),
            byteArrayOf(OPEN_ANSWERED, MAXIMUM_OCTET, MAXIMUM_OCTET, MAXIMUM_OCTET, MAXIMUM_OCTET, ZERO),
        ).forEach { reply ->
            assertEquals(bridge, NativeOrganizationOpenReply.decode(reply))
        }
    }

    @Test
    fun clearsTheReplyBufferAfterDecoding() {
        val reply = byteArrayOf(OPEN_REFUSED, ANSWER_WRONG_PIN, SYNTHETIC_RETRIES)
        NativeOrganizationOpenReply.decode(reply)
        assertArrayEquals(ByteArray(reply.size), reply)
    }

    @Test
    fun pin1IsNotOfferedAtTheLastTwoTriesOrBlocked() {
        assertTrue(organizationPin1Refused(BLOCKED_TRIES))
        assertTrue(organizationPin1Refused(LAST_TRY))
        assertTrue(organizationPin1Refused(TWO_TRIES))
        assertFalse(organizationPin1Refused(LOWEST_SERVED_TRIES))
        assertFalse(organizationPin1Refused(FINEID_PIN_TRY_LIMIT))
        assertFalse(organizationPin1Refused(null))
    }

    private companion object {
        const val OPEN_ANSWERED: Byte = 0
        const val OPEN_REFUSED: Byte = 1
        const val ANSWER_SAFETY_REFUSED: Byte = 5
        const val ANSWER_WRONG_PIN: Byte = 7
        const val ANSWER_PACE_REJECTED: Byte = 10
        const val CERTIFICATE_REJECTED: Byte = 3
        const val SYNTHETIC_RETRIES: Byte = 3
        const val UNKNOWN_TAG: Byte = 9
        const val ZERO: Byte = 0
        const val ONE_OCTET: Byte = 1
        const val MAXIMUM_OCTET: Byte = -1
        const val BLOCKED_TRIES = 0
        const val LAST_TRY = 1
        const val TWO_TRIES = 2
        const val LOWEST_SERVED_TRIES = 3
    }
}
