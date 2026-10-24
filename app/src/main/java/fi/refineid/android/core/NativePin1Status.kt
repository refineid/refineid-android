package fi.refineid.android.core

private const val MAXIMUM_PIN_RETRY_NIBBLE = 0x0F

internal enum class NativePinReferenceScheme {
    CITIZEN,
    ORGANIZATIONAL,
}

/**
 * The PIN Try Limit FINEID cards are issued with: the attempts a PIN allows
 * before any wrong entry, to which RESET RETRY COUNTER sets the try counter
 * (FINEID S1 v4.2 section 3.12); refineid-auth names the same count its
 * pristine retry state.
 */
internal const val FINEID_PIN_TRY_LIMIT = 5

internal sealed interface NativePin1State {
    data object Verified : NativePin1State

    data class Remaining(
        val attempts: Int,
    ) : NativePin1State {
        init {
            require(attempts in 0..MAXIMUM_PIN_RETRY_NIBBLE) {
                "PIN retry count does not fit the status-word nibble"
            }
        }
    }

    data object Locked : NativePin1State

    data object NoInformation : NativePin1State

    data object Unrecognized : NativePin1State
}

/**
 * The attempts the card still allows, or null when the card did not say.
 *
 * A PIN 1 the card holds as verified allows its PIN Try Limit: a
 * successful VERIFY sets the try counter to the limit, and every command
 * that lowers the counter also clears the verified flag (FINEID S1 v4.2
 * sections 3.5 and 3.11). A card in a contact reader keeps the flag from
 * one operation to the next, so its status reads verified rather than as
 * a count.
 */
internal fun NativePin1State.attemptsLeft(): Int? =
    when (this) {
        is NativePin1State.Remaining -> attempts
        NativePin1State.Verified -> FINEID_PIN_TRY_LIMIT
        NativePin1State.Locked -> 0
        NativePin1State.NoInformation, NativePin1State.Unrecognized -> null
    }

internal data class NativePin1Preflight(
    val referenceScheme: NativePinReferenceScheme,
    val state: NativePin1State,
    val retryFloorPermits: Boolean,
)

internal enum class NativePin1PreflightFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    BRIDGE_ERROR,
}

internal sealed interface NativePin1PreflightResult {
    data class Success(
        val preflight: NativePin1Preflight,
    ) : NativePin1PreflightResult

    data class Failure(
        val kind: NativePin1PreflightFailure,
    ) : NativePin1PreflightResult
}

/** Strict decoder for the bounded native PIN1 status vocabulary. */
internal object NativePin1PreflightReply {
    fun decode(reply: ByteArray): NativePin1PreflightResult =
        try {
            if (reply.isEmpty()) {
                return bridgeFailure()
            }
            when (reply[TAG_OFFSET].toUnsignedInt()) {
                PREFLIGHT_SUCCEEDED -> {
                    decodeSuccess(reply)
                }

                PREFLIGHT_CARD_UNAVAILABLE -> {
                    decodeFailure(reply, NativePin1PreflightFailure.CARD_UNAVAILABLE)
                }

                PREFLIGHT_TRANSPORT_ERROR -> {
                    decodeFailure(reply, NativePin1PreflightFailure.TRANSPORT_ERROR)
                }

                PREFLIGHT_BRIDGE_ERROR -> {
                    decodeFailure(reply, NativePin1PreflightFailure.BRIDGE_ERROR)
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeSuccess(reply: ByteArray): NativePin1PreflightResult {
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
                PIN1_STATE_VERIFIED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin1State.Verified
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN1_STATE_REMAINING -> {
                    if (retryCount <= MAXIMUM_PIN_RETRY_NIBBLE) {
                        NativePin1State.Remaining(retryCount)
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN1_STATE_LOCKED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin1State.Locked
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN1_STATE_NO_INFORMATION -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin1State.NoInformation
                    } else {
                        return bridgeFailure()
                    }
                }

                PIN1_STATE_UNRECOGNIZED -> {
                    if (retryCount == NO_RETRY_COUNT) {
                        NativePin1State.Unrecognized
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
        if (permitted != expectedRetryFloor(state)) {
            return bridgeFailure()
        }
        return NativePin1PreflightResult.Success(
            NativePin1Preflight(
                referenceScheme = scheme,
                state = state,
                retryFloorPermits = permitted,
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativePin1PreflightFailure,
    ): NativePin1PreflightResult =
        if (reply.size == FAILURE_REPLY_LENGTH) {
            NativePin1PreflightResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun expectedRetryFloor(state: NativePin1State): Boolean =
        when (state) {
            NativePin1State.Verified -> {
                true
            }

            is NativePin1State.Remaining -> {
                state.attempts in MINIMUM_SAFE_RETRY_COUNT..FINEID_PIN_TRY_LIMIT
            }

            NativePin1State.Locked,
            NativePin1State.NoInformation,
            NativePin1State.Unrecognized,
            -> {
                false
            }
        }

    private fun bridgeFailure(): NativePin1PreflightResult.Failure =
        NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toInt() and UNSIGNED_BYTE_MASK

    private const val PREFLIGHT_BRIDGE_ERROR = 0
    private const val PREFLIGHT_SUCCEEDED = 1
    private const val PREFLIGHT_CARD_UNAVAILABLE = 2
    private const val PREFLIGHT_TRANSPORT_ERROR = 3

    private const val PIN_REFERENCE_CITIZEN = 0
    private const val PIN_REFERENCE_ORGANIZATIONAL = 1

    private const val PIN1_STATE_VERIFIED = 0
    private const val PIN1_STATE_REMAINING = 1
    private const val PIN1_STATE_LOCKED = 2
    private const val PIN1_STATE_NO_INFORMATION = 3
    private const val PIN1_STATE_UNRECOGNIZED = 4

    private const val POLICY_REFUSED = 0
    private const val POLICY_PERMITTED = 1

    private const val TAG_OFFSET = 0
    private const val SCHEME_OFFSET = 1
    private const val STATE_OFFSET = 2
    private const val RETRY_COUNT_OFFSET = 3
    private const val POLICY_OFFSET = 4

    private const val FAILURE_REPLY_LENGTH = 1
    private const val SUCCESS_REPLY_LENGTH = 5
    private const val UNSIGNED_BYTE_MASK = 0xFF
    private const val NO_RETRY_COUNT = 0xFF
    private const val MINIMUM_SAFE_RETRY_COUNT = 3
}
