package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class NativePin1PreflightReplyTest {
    @Test
    fun decodesEveryReviewedStateAndClearsNativeReplies() {
        val cases =
            listOf(
                Case(
                    wire = success(PIN_REFERENCE_CITIZEN, PIN1_STATE_VERIFIED, NO_RETRY_COUNT, true),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.Verified,
                    permitted = true,
                ),
                Case(
                    wire =
                        success(
                            PIN_REFERENCE_ORGANIZATIONAL,
                            PIN1_STATE_REMAINING,
                            TYPICAL_RETRY_COUNT,
                            true,
                        ),
                    scheme = NativePinReferenceScheme.ORGANIZATIONAL,
                    state = NativePin1State.Remaining(TYPICAL_RETRY_COUNT),
                    permitted = true,
                ),
                Case(
                    wire = success(PIN_REFERENCE_CITIZEN, PIN1_STATE_REMAINING, LOW_RETRY_COUNT, false),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.Remaining(LOW_RETRY_COUNT),
                    permitted = false,
                ),
                Case(
                    wire = success(PIN_REFERENCE_CITIZEN, PIN1_STATE_REMAINING, EXHAUSTED_RETRY_COUNT, false),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.Remaining(EXHAUSTED_RETRY_COUNT),
                    permitted = false,
                ),
                Case(
                    wire = success(PIN_REFERENCE_CITIZEN, PIN1_STATE_LOCKED, NO_RETRY_COUNT, false),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.Locked,
                    permitted = false,
                ),
                Case(
                    wire =
                        success(
                            PIN_REFERENCE_CITIZEN,
                            PIN1_STATE_NO_INFORMATION,
                            NO_RETRY_COUNT,
                            false,
                        ),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.NoInformation,
                    permitted = false,
                ),
                Case(
                    wire =
                        success(
                            PIN_REFERENCE_CITIZEN,
                            PIN1_STATE_UNRECOGNIZED,
                            NO_RETRY_COUNT,
                            false,
                        ),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    state = NativePin1State.Unrecognized,
                    permitted = false,
                ),
            )

        for (case in cases) {
            val reply = case.wire.copyOf()
            val result =
                NativePin1PreflightReply.decode(reply) as NativePin1PreflightResult.Success

            assertEquals(case.scheme, result.preflight.referenceScheme)
            assertEquals(case.state, result.preflight.state)
            assertEquals(case.permitted, result.preflight.retryFloorPermits)
            assertTrue(reply.all { byte -> byte == 0.toByte() })
        }
    }

    @Test
    fun decodesTypedFailuresAndClearsNativeReplies() {
        val cases =
            listOf(
                PREFLIGHT_CARD_UNAVAILABLE to NativePin1PreflightFailure.CARD_UNAVAILABLE,
                PREFLIGHT_TRANSPORT_ERROR to NativePin1PreflightFailure.TRANSPORT_ERROR,
                PREFLIGHT_BRIDGE_ERROR to NativePin1PreflightFailure.BRIDGE_ERROR,
            )

        for ((tag, expected) in cases) {
            val reply = byteArrayOf(tag.toByte())
            val result =
                NativePin1PreflightReply.decode(reply) as NativePin1PreflightResult.Failure

            assertEquals(expected, result.kind)
            assertTrue(reply.all { byte -> byte == 0.toByte() })
        }
    }

    @Test
    fun rejectsMalformedShapesAndPolicyContradictions() {
        val malformed =
            listOf(
                byteArrayOf(),
                byteArrayOf(PREFLIGHT_SUCCEEDED.toByte()),
                success(UNKNOWN_VALUE, PIN1_STATE_VERIFIED, NO_RETRY_COUNT, true),
                success(PIN_REFERENCE_CITIZEN, UNKNOWN_VALUE, NO_RETRY_COUNT, false),
                success(PIN_REFERENCE_CITIZEN, PIN1_STATE_VERIFIED, TYPICAL_RETRY_COUNT, true),
                success(PIN_REFERENCE_CITIZEN, PIN1_STATE_REMAINING, NO_RETRY_COUNT, false),
                success(PIN_REFERENCE_CITIZEN, PIN1_STATE_REMAINING, LAST_RETRY_COUNT, true),
                success(PIN_REFERENCE_CITIZEN, PIN1_STATE_REMAINING, ABOVE_POLICY_RETRY_COUNT, true),
                success(PIN_REFERENCE_CITIZEN, PIN1_STATE_LOCKED, NO_RETRY_COUNT, true),
                byteArrayOf(PREFLIGHT_CARD_UNAVAILABLE.toByte(), UNKNOWN_VALUE.toByte()),
            )

        for (reply in malformed) {
            val result =
                NativePin1PreflightReply.decode(reply) as NativePin1PreflightResult.Failure

            assertEquals(NativePin1PreflightFailure.BRIDGE_ERROR, result.kind)
            assertTrue(reply.all { byte -> byte == 0.toByte() })
        }
    }

    @Test
    fun retryStateRejectsValuesOutsideTheWireNibble() {
        assertThrows(IllegalArgumentException::class.java) {
            NativePin1State.Remaining(FIRST_RETRY_COUNT_OUTSIDE_WIRE_NIBBLE)
        }
    }

    private fun success(
        scheme: Int,
        state: Int,
        retries: Int,
        permitted: Boolean,
    ): ByteArray =
        byteArrayOf(
            PREFLIGHT_SUCCEEDED.toByte(),
            scheme.toByte(),
            state.toByte(),
            retries.toByte(),
            if (permitted) POLICY_PERMITTED.toByte() else POLICY_REFUSED.toByte(),
        )

    private data class Case(
        val wire: ByteArray,
        val scheme: NativePinReferenceScheme,
        val state: NativePin1State,
        val permitted: Boolean,
    )

    private companion object {
        const val PREFLIGHT_BRIDGE_ERROR = 0
        const val PREFLIGHT_SUCCEEDED = 1
        const val PREFLIGHT_CARD_UNAVAILABLE = 2
        const val PREFLIGHT_TRANSPORT_ERROR = 3
        const val PIN_REFERENCE_CITIZEN = 0
        const val PIN_REFERENCE_ORGANIZATIONAL = 1
        const val PIN1_STATE_VERIFIED = 0
        const val PIN1_STATE_REMAINING = 1
        const val PIN1_STATE_LOCKED = 2
        const val PIN1_STATE_NO_INFORMATION = 3
        const val PIN1_STATE_UNRECOGNIZED = 4
        const val POLICY_REFUSED = 0
        const val POLICY_PERMITTED = 1
        const val NO_RETRY_COUNT = 0xFF
        const val UNKNOWN_VALUE = 0x7F
        const val EXHAUSTED_RETRY_COUNT = 0
        const val LAST_RETRY_COUNT = 1
        const val LOW_RETRY_COUNT = 2
        const val TYPICAL_RETRY_COUNT = 3
        const val ABOVE_POLICY_RETRY_COUNT = 6
        const val FIRST_RETRY_COUNT_OUTSIDE_WIRE_NIBBLE = 16
    }
}
