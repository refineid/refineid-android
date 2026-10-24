@file:Suppress("TooManyFunctions")

package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/**
 * How a citizen card is activated (FINEID S4-1 section 4.6), and the exact
 * digit count the card accepts for the activation entry: the card enforces
 * the length itself and a wrong length spends a try. An unknown scheme has
 * no length and gets no activation attempt.
 */
internal enum class CardManagementScheme(
    val activationEntryDigitCount: Int?,
) {
    UNKNOWN(null),
    PUK(ACTIVATION_CODE_DIGIT_COUNT),
    PRESET_PIN(PRESET_ACTIVATION_PIN_DIGIT_COUNT),
}

/** Digits of the activation code, the PUK, under section 4.6.1. */
private const val ACTIVATION_CODE_DIGIT_COUNT = 8

/** Digits of the preset activation PIN under section 4.6.2. */
private const val PRESET_ACTIVATION_PIN_DIGIT_COUNT = 7

/** The activation scheme a native reply byte names. */
internal fun decodeActivationScheme(byte: Int): CardManagementScheme =
    when (byte) {
        ACTIVATION_SCHEME_PUK -> CardManagementScheme.PUK
        ACTIVATION_SCHEME_PRESET -> CardManagementScheme.PRESET_PIN
        else -> CardManagementScheme.UNKNOWN
    }

/** Which PINs a native reply byte says still await activation. */
internal fun decodeActivationNeeds(byte: Int): CardActivationNeeds =
    when (byte) {
        ACTIVATION_NEEDS_PIN1_ONLY -> CardActivationNeeds(pin1 = true, pin2 = false)
        ACTIVATION_NEEDS_PIN2_ONLY -> CardActivationNeeds(pin1 = false, pin2 = true)
        ACTIVATION_NEEDS_BOTH -> CardActivationNeeds(pin1 = true, pin2 = true)
        else -> CardActivationNeeds(pin1 = false, pin2 = false)
    }

internal data class CardActivationNeeds(
    val pin1: Boolean,
    val pin2: Boolean,
) {
    val any: Boolean get() = pin1 || pin2
}

internal data class CredentialHealth(
    val pin1State: NativePin1State,
    val pin2State: NativePin2State,
    val pukState: NativePin1State,
    val scheme: NativePinReferenceScheme,
    val activationScheme: CardManagementScheme,
    val activationNeeds: CardActivationNeeds,
)

internal sealed interface ManageOutcome {
    data object Succeeded : ManageOutcome

    data class WrongCredential(
        val attemptsRemaining: Int,
    ) : ManageOutcome

    data object Locked : ManageOutcome

    data class Other(
        val sw1: Int,
        val sw2: Int,
    ) : ManageOutcome
}

internal data class ActivationReport(
    val scheme: CardManagementScheme,
    val pin1Outcome: ManageOutcome?,
    val pin2Outcome: ManageOutcome?,
)

internal enum class CardManagementFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    BRIDGE_ERROR,
    INVALID_CREDENTIAL,
    SAFETY_REFUSED,
    PACE_REJECTED,
}

internal sealed interface CardManagementResult<out T> {
    data class Success<out T>(
        val value: T,
    ) : CardManagementResult<T>

    data class Failure(
        val kind: CardManagementFailure,
    ) : CardManagementResult<Nothing>
}

private const val MANAGEMENT_TAG_BRIDGE_ERROR = 0
private const val MANAGEMENT_TAG_SUCCEEDED = 1
private const val MANAGEMENT_TAG_CARD_UNAVAILABLE = 2
private const val MANAGEMENT_TAG_TRANSPORT_ERROR = 3
private const val MANAGEMENT_TAG_INVALID_CREDENTIAL = 4
private const val MANAGEMENT_TAG_SAFETY_REFUSED = 5
private const val MANAGEMENT_TAG_PACE_REJECTED = 6
private const val MANAGEMENT_TAG_WRONG_CREDENTIAL = 7
private const val MANAGEMENT_TAG_LOCKED = 8
private const val MANAGEMENT_TAG_OTHER = 9

private const val PIN_STATE_VERIFIED = 1
private const val PIN_STATE_REMAINING = 2
private const val PIN_STATE_LOCKED = 3
private const val PIN_STATE_NO_INFO = 4

private const val SCHEME_CITIZEN = 1
private const val SCHEME_ORGANIZATIONAL = 2

private const val ACTIVATION_SCHEME_UNKNOWN = 0
private const val ACTIVATION_SCHEME_PUK = 1
private const val ACTIVATION_SCHEME_PRESET = 2

private const val ACTIVATION_NEEDS_NONE = 0
private const val ACTIVATION_NEEDS_PIN1_ONLY = 1
private const val ACTIVATION_NEEDS_PIN2_ONLY = 2
private const val ACTIVATION_NEEDS_BOTH = 3

private const val HEALTH_REPLY_LENGTH = 10
private const val OUTCOME_REPLY_LENGTH = 4
private const val ACTIVATION_REPLY_LENGTH = 6

internal object NativeCardManagement {
    /**
     * The credential health under the activation scheme the card's answer
     * to reset names, so a card awaiting activation has nothing read beyond
     * its counters; an answer that names none has the scheme read from the
     * certificate, as an activated card's may be.
     */
    fun probeCredentialHealth(
        exchangeLevel: NativeCardExchangeLevel,
        cardAnswer: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = probeCredentialHealthNative(exchangeLevel.wireValue, cardAnswer, exchange)
            decodeCredentialHealth(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun changePin1(
        exchangeLevel: NativeCardExchangeLevel,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = changePin1Native(exchangeLevel.wireValue, currentPin, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun changePin2(
        exchangeLevel: NativeCardExchangeLevel,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = changePin2Native(exchangeLevel.wireValue, currentPin, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun unblockPin1(
        exchangeLevel: NativeCardExchangeLevel,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = unblockPin1Native(exchangeLevel.wireValue, puk, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun unblockPin2(
        exchangeLevel: NativeCardExchangeLevel,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = unblockPin2Native(exchangeLevel.wireValue, puk, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun activateCard(
        exchangeLevel: NativeCardExchangeLevel,
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        val schemeByte =
            when (scheme) {
                CardManagementScheme.PUK -> ACTIVATION_SCHEME_PUK
                CardManagementScheme.PRESET_PIN -> ACTIVATION_SCHEME_PRESET
                CardManagementScheme.UNKNOWN -> ACTIVATION_SCHEME_UNKNOWN
            }
        return try {
            val reply =
                activateCardNative(
                    exchangeLevel.wireValue,
                    schemeByte,
                    code,
                    newPin1 ?: ByteArray(0),
                    newPin2 ?: ByteArray(0),
                    exchange,
                )
            decodeActivationReport(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    // Contactless operations
    fun contactlessProbeCredentialHealth(
        can: ByteArray,
        cardAnswer: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = contactlessProbeCredentialHealthNative(can, cardAnswer, exchange)
            decodeCredentialHealth(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun contactlessChangePin1(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = contactlessChangePin1Native(can, currentPin, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun contactlessChangePin2(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = contactlessChangePin2Native(can, currentPin, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun contactlessUnblockPin1(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = contactlessUnblockPin1Native(can, puk, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun contactlessUnblockPin2(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            val reply = contactlessUnblockPin2Native(can, puk, newPin, exchange)
            decodeManageOutcome(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    fun contactlessActivateCard(
        can: ByteArray,
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        val schemeByte =
            when (scheme) {
                CardManagementScheme.PUK -> ACTIVATION_SCHEME_PUK
                CardManagementScheme.PRESET_PIN -> ACTIVATION_SCHEME_PRESET
                CardManagementScheme.UNKNOWN -> ACTIVATION_SCHEME_UNKNOWN
            }
        return try {
            val reply =
                contactlessActivateCardNative(
                    can,
                    schemeByte,
                    code,
                    newPin1 ?: ByteArray(0),
                    newPin2 ?: ByteArray(0),
                    exchange,
                )
            decodeActivationReport(reply)
        } catch (_: Throwable) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    private fun decodeCredentialHealth(reply: ByteArray): CardManagementResult<CredentialHealth> {
        if (reply.isEmpty()) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return when (val tag = reply[0].toInt()) {
            MANAGEMENT_TAG_SUCCEEDED -> {
                if (reply.size != HEALTH_REPLY_LENGTH) {
                    CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                } else {
                    val p1State = parsePin1State(reply[1].toInt(), reply[2].toInt())
                    val p2State = parsePin2State(reply[3].toInt(), reply[4].toInt())
                    val pukState = parsePin1State(reply[5].toInt(), reply[6].toInt())
                    val scheme =
                        if (reply[7].toInt() == SCHEME_ORGANIZATIONAL) {
                            NativePinReferenceScheme.ORGANIZATIONAL
                        } else {
                            NativePinReferenceScheme.CITIZEN
                        }
                    val actScheme = decodeActivationScheme(reply[8].toInt())
                    val needs = decodeActivationNeeds(reply[9].toInt())
                    CardManagementResult.Success(
                        CredentialHealth(
                            pin1State = p1State,
                            pin2State = p2State,
                            pukState = pukState,
                            scheme = scheme,
                            activationScheme = actScheme,
                            activationNeeds = needs,
                        ),
                    )
                }
            }

            else -> {
                CardManagementResult.Failure(mapFailureTag(tag))
            }
        }
    }

    private fun decodeManageOutcome(reply: ByteArray): CardManagementResult<ManageOutcome> {
        if (reply.isEmpty()) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return when (val tag = reply[0].toInt()) {
            MANAGEMENT_TAG_SUCCEEDED -> {
                CardManagementResult.Success(ManageOutcome.Succeeded)
            }

            MANAGEMENT_TAG_WRONG_CREDENTIAL -> {
                val attempts = if (reply.size >= 2) reply[1].toInt() else 0
                CardManagementResult.Success(ManageOutcome.WrongCredential(attempts))
            }

            MANAGEMENT_TAG_LOCKED -> {
                CardManagementResult.Success(ManageOutcome.Locked)
            }

            MANAGEMENT_TAG_OTHER -> {
                val sw1 = if (reply.size >= 3) reply[2].toInt() and 0xFF else 0
                val sw2 = if (reply.size >= 4) reply[3].toInt() and 0xFF else 0
                CardManagementResult.Success(ManageOutcome.Other(sw1, sw2))
            }

            else -> {
                CardManagementResult.Failure(mapFailureTag(tag))
            }
        }
    }

    private fun decodeActivationReport(reply: ByteArray): CardManagementResult<ActivationReport> {
        if (reply.isEmpty()) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return when (val tag = reply[0].toInt()) {
            MANAGEMENT_TAG_SUCCEEDED -> {
                if (reply.size != ACTIVATION_REPLY_LENGTH) {
                    CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                } else {
                    val scheme =
                        when (reply[1].toInt()) {
                            ACTIVATION_SCHEME_PUK -> CardManagementScheme.PUK
                            ACTIVATION_SCHEME_PRESET -> CardManagementScheme.PRESET_PIN
                            else -> CardManagementScheme.UNKNOWN
                        }
                    val p1Outcome = parseOutcomeTag(reply[2].toInt(), reply[3].toInt())
                    val p2Outcome = parseOutcomeTag(reply[4].toInt(), reply[5].toInt())
                    CardManagementResult.Success(
                        ActivationReport(
                            scheme = scheme,
                            pin1Outcome = p1Outcome,
                            pin2Outcome = p2Outcome,
                        ),
                    )
                }
            }

            else -> {
                CardManagementResult.Failure(mapFailureTag(tag))
            }
        }
    }

    private fun parseOutcomeTag(
        tag: Int,
        retries: Int,
    ): ManageOutcome? {
        return when (tag) {
            MANAGEMENT_TAG_SUCCEEDED -> ManageOutcome.Succeeded
            MANAGEMENT_TAG_WRONG_CREDENTIAL -> ManageOutcome.WrongCredential(retries)
            MANAGEMENT_TAG_LOCKED -> ManageOutcome.Locked
            MANAGEMENT_TAG_OTHER -> ManageOutcome.Other(0, 0)
            else -> null
        }
    }

    private fun parsePin1State(
        stateByte: Int,
        retryByte: Int,
    ): NativePin1State {
        return when (stateByte) {
            PIN_STATE_VERIFIED -> NativePin1State.Verified
            PIN_STATE_REMAINING -> NativePin1State.Remaining(retryByte)
            PIN_STATE_LOCKED -> NativePin1State.Locked
            PIN_STATE_NO_INFO -> NativePin1State.NoInformation
            else -> NativePin1State.Unrecognized
        }
    }

    private fun parsePin2State(
        stateByte: Int,
        retryByte: Int,
    ): NativePin2State {
        return when (stateByte) {
            PIN_STATE_VERIFIED -> NativePin2State.Verified
            PIN_STATE_REMAINING -> NativePin2State.Remaining(retryByte)
            PIN_STATE_LOCKED -> NativePin2State.Locked
            PIN_STATE_NO_INFO -> NativePin2State.NoInformation
            else -> NativePin2State.Unrecognized
        }
    }

    private fun mapFailureTag(tag: Int): CardManagementFailure {
        return when (tag) {
            MANAGEMENT_TAG_CARD_UNAVAILABLE -> CardManagementFailure.CARD_UNAVAILABLE
            MANAGEMENT_TAG_TRANSPORT_ERROR -> CardManagementFailure.TRANSPORT_ERROR
            MANAGEMENT_TAG_INVALID_CREDENTIAL -> CardManagementFailure.INVALID_CREDENTIAL
            MANAGEMENT_TAG_SAFETY_REFUSED -> CardManagementFailure.SAFETY_REFUSED
            MANAGEMENT_TAG_PACE_REJECTED -> CardManagementFailure.PACE_REJECTED
            else -> CardManagementFailure.BRIDGE_ERROR
        }
    }

    @JvmStatic
    private external fun probeCredentialHealthNative(
        exchangeLevel: Int,
        cardAnswer: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun changePin1Native(
        exchangeLevel: Int,
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun changePin2Native(
        exchangeLevel: Int,
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun unblockPin1Native(
        exchangeLevel: Int,
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun unblockPin2Native(
        exchangeLevel: Int,
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun activateCardNative(
        exchangeLevel: Int,
        scheme: Int,
        code: ByteArray,
        newPin1: ByteArray,
        newPin2: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessProbeCredentialHealthNative(
        can: ByteArray,
        cardAnswer: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessChangePin1Native(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessChangePin2Native(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessUnblockPin1Native(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessUnblockPin2Native(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessActivateCardNative(
        can: ByteArray,
        scheme: Int,
        code: ByteArray,
        newPin1: ByteArray,
        newPin2: ByteArray,
        callback: Any,
    ): ByteArray
}
