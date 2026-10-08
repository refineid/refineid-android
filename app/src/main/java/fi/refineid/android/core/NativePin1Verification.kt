package fi.refineid.android.core

internal enum class Pin1VerificationResult {
    VERIFIED,
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    INVALID_PIN,
    SAFETY_REFUSED,
    PIN_LOCKED,
    WRONG_PIN,
    VERIFICATION_REJECTED,
    PACE_REJECTED,
    BRIDGE_ERROR,
}

/** Standalone credential verification. A success proves the submitted digits. */
internal object NativePin1Verification {
    fun verify(
        pin1: Pin1Submission,
        exchange: NativeBlockExchange,
        exchangeLevel: NativeCardExchangeLevel = NativeCardExchangeLevel.APDU,
        heldSession: Boolean = false,
    ): Pin1VerificationResult =
        try {
            pin1.consume { bytes ->
                if (!NativeCore.isLoaded) {
                    Pin1VerificationResult.BRIDGE_ERROR
                } else {
                    decode(verifyPin1Native(exchangeLevel.wireValue, heldSession, bytes, exchange))
                }
            }
        } catch (_: LinkageError) {
            Pin1VerificationResult.BRIDGE_ERROR
        } catch (_: RuntimeException) {
            Pin1VerificationResult.BRIDGE_ERROR
        } finally {
            pin1.close()
        }

    fun decode(reply: ByteArray): Pin1VerificationResult =
        try {
            if (reply.size != REPLY_SIZE) {
                Pin1VerificationResult.BRIDGE_ERROR
            } else {
                when (reply.single().toInt()) {
                    VERIFIED -> Pin1VerificationResult.VERIFIED
                    CARD_UNAVAILABLE -> Pin1VerificationResult.CARD_UNAVAILABLE
                    TRANSPORT_ERROR -> Pin1VerificationResult.TRANSPORT_ERROR
                    INVALID_PIN -> Pin1VerificationResult.INVALID_PIN
                    SAFETY_REFUSED -> Pin1VerificationResult.SAFETY_REFUSED
                    PIN_LOCKED -> Pin1VerificationResult.PIN_LOCKED
                    WRONG_PIN -> Pin1VerificationResult.WRONG_PIN
                    VERIFICATION_REJECTED -> Pin1VerificationResult.VERIFICATION_REJECTED
                    PACE_REJECTED -> Pin1VerificationResult.PACE_REJECTED
                    else -> Pin1VerificationResult.BRIDGE_ERROR
                }
            }
        } finally {
            reply.fill(0)
        }

    @JvmStatic
    private external fun verifyPin1Native(
        exchangeLevel: Int,
        heldSession: Boolean,
        pin: ByteArray,
        callback: Any,
    ): ByteArray

    private const val REPLY_SIZE = 1
    private const val VERIFIED = 1
    private const val CARD_UNAVAILABLE = 2
    private const val TRANSPORT_ERROR = 3
    private const val INVALID_PIN = 4
    private const val SAFETY_REFUSED = 5
    private const val PIN_LOCKED = 6
    private const val WRONG_PIN = 7
    private const val VERIFICATION_REJECTED = 8
    private const val PACE_REJECTED = 10
}

internal fun Pin1VerificationResult.authenticationFailure(): AuthenticationSignFailure? =
    when (this) {
        Pin1VerificationResult.VERIFIED -> {
            null
        }

        Pin1VerificationResult.CARD_UNAVAILABLE -> {
            AuthenticationSignFailure.CARD_UNAVAILABLE
        }

        Pin1VerificationResult.TRANSPORT_ERROR, Pin1VerificationResult.PACE_REJECTED -> {
            AuthenticationSignFailure.TRANSPORT_ERROR
        }

        Pin1VerificationResult.INVALID_PIN -> {
            AuthenticationSignFailure.INVALID_PIN
        }

        Pin1VerificationResult.SAFETY_REFUSED -> {
            AuthenticationSignFailure.SAFETY_REFUSED
        }

        Pin1VerificationResult.PIN_LOCKED -> {
            AuthenticationSignFailure.PIN_LOCKED
        }

        Pin1VerificationResult.WRONG_PIN -> {
            AuthenticationSignFailure.WRONG_PIN
        }

        Pin1VerificationResult.VERIFICATION_REJECTED -> {
            AuthenticationSignFailure.VERIFICATION_REJECTED
        }

        Pin1VerificationResult.BRIDGE_ERROR -> {
            AuthenticationSignFailure.BRIDGE_ERROR
        }
    }
