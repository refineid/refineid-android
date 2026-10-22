package fi.refineid.android.core

private const val MAXIMUM_PIN2_RETRY_NIBBLE = 0x0F

internal sealed interface NativePin2State {
    data object Verified : NativePin2State

    data class Remaining(
        val attempts: Int,
    ) : NativePin2State {
        init {
            require(attempts in 0..MAXIMUM_PIN2_RETRY_NIBBLE) {
                "PIN2 retry count does not fit the status-word nibble"
            }
        }
    }

    data object Locked : NativePin2State

    data object NoInformation : NativePin2State

    data object Unrecognized : NativePin2State
}

internal data class NativePin2Preflight(
    val referenceScheme: NativePinReferenceScheme,
    val state: NativePin2State,
    val qualifiedSignaturePermitted: Boolean,
)

internal enum class NativePin2PreflightFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    BRIDGE_ERROR,
}

internal sealed interface NativePin2PreflightResult {
    data class Success(
        val preflight: NativePin2Preflight,
    ) : NativePin2PreflightResult

    data class Failure(
        val kind: NativePin2PreflightFailure,
    ) : NativePin2PreflightResult
}

/** Strict decoder for the bounded native PIN2 status vocabulary. */
internal object NativePin2PreflightReply {
    fun decode(reply: ByteArray): NativePin2PreflightResult =
        try {
            if (reply.isEmpty()) {
                return bridgeFailure()
            }
            when (reply[TAG_OFFSET].toUnsignedInt()) {
                PREFLIGHT_SUCCEEDED -> {
                    decodeSuccess(reply)
                }

                PREFLIGHT_CARD_UNAVAILABLE -> {
                    decodeFailure(reply, NativePin2PreflightFailure.CARD_UNAVAILABLE)
                }

                PREFLIGHT_TRANSPORT_ERROR -> {
                    decodeFailure(reply, NativePin2PreflightFailure.TRANSPORT_ERROR)
                }

                PREFLIGHT_BRIDGE_ERROR -> {
                    decodeFailure(reply, NativePin2PreflightFailure.BRIDGE_ERROR)
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(ZERO_BYTE)
        }

    private fun decodeSuccess(reply: ByteArray): NativePin2PreflightResult {
        if (reply.size != SUCCESS_REPLY_LENGTH) {
            return bridgeFailure()
        }
        val scheme =
            when (reply[SCHEME_OFFSET].toUnsignedInt()) {
                PIN_REFERENCE_CITIZEN -> NativePinReferenceScheme.CITIZEN
                PIN_REFERENCE_ORGANIZATIONAL -> NativePinReferenceScheme.ORGANIZATIONAL
                else -> return bridgeFailure()
            }
        val retryCount = reply[RETRY_COUNT_OFFSET].toUnsignedInt()
        val state =
            when (reply[STATE_OFFSET].toUnsignedInt()) {
                PIN2_STATE_VERIFIED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin2State.Verified
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN2_STATE_REMAINING -> {
                    if (retryCount <= MAXIMUM_PIN2_RETRY_NIBBLE) {
                        NativePin2State.Remaining(retryCount)
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN2_STATE_LOCKED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin2State.Locked
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN2_STATE_NO_INFORMATION -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin2State.NoInformation
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN2_STATE_UNRECOGNIZED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin2State.Unrecognized
                    } else {
                        return bridgeFailure()
                    }
                }

                else -> {
                    return bridgeFailure()
                }
            }
        val permitted =
            when (reply[POLICY_OFFSET].toUnsignedInt()) {
                POLICY_REFUSED -> false
                POLICY_PERMITTED -> true
                else -> return bridgeFailure()
            }
        if (permitted != expectedQualifiedSignaturePolicy(state)) {
            return bridgeFailure()
        }
        return NativePin2PreflightResult.Success(
            NativePin2Preflight(
                referenceScheme = scheme,
                state = state,
                qualifiedSignaturePermitted = permitted,
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativePin2PreflightFailure,
    ): NativePin2PreflightResult =
        if (reply.size == FAILURE_REPLY_LENGTH) {
            NativePin2PreflightResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun expectedQualifiedSignaturePolicy(state: NativePin2State): Boolean =
        when (state) {
            NativePin2State.Verified -> {
                true
            }

            is NativePin2State.Remaining -> {
                state.attempts == EXHAUSTED_RETRY_COUNT ||
                    state.attempts in MINIMUM_SAFE_RETRY_COUNT..FINEID_PIN_TRY_LIMIT
            }

            NativePin2State.Locked,
            NativePin2State.NoInformation,
            NativePin2State.Unrecognized,
            -> {
                false
            }
        }

    private fun bridgeFailure(): NativePin2PreflightResult.Failure =
        NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()

    private const val PREFLIGHT_BRIDGE_ERROR = 0
    private const val PREFLIGHT_SUCCEEDED = 1
    private const val PREFLIGHT_CARD_UNAVAILABLE = 2
    private const val PREFLIGHT_TRANSPORT_ERROR = 3

    private const val PIN_REFERENCE_CITIZEN = 0
    private const val PIN_REFERENCE_ORGANIZATIONAL = 1

    private const val PIN2_STATE_VERIFIED = 0
    private const val PIN2_STATE_REMAINING = 1
    private const val PIN2_STATE_LOCKED = 2
    private const val PIN2_STATE_NO_INFORMATION = 3
    private const val PIN2_STATE_UNRECOGNIZED = 4

    private const val POLICY_REFUSED = 0
    private const val POLICY_PERMITTED = 1

    private const val TAG_OFFSET = 0
    private const val SCHEME_OFFSET = 1
    private const val STATE_OFFSET = 2
    private const val RETRY_COUNT_OFFSET = 3
    private const val POLICY_OFFSET = 4

    private const val FAILURE_REPLY_LENGTH = 1
    private const val SUCCESS_REPLY_LENGTH = 5
    private const val NO_RETRY_COUNT = 0xFF
    private const val EXHAUSTED_RETRY_COUNT = 0
    private const val MINIMUM_SAFE_RETRY_COUNT = 3
    private const val ZERO_BYTE: Byte = 0
}
