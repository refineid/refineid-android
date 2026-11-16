@file:Suppress("TooManyFunctions")

package fi.refineid.android.core

/**
 * How a card is activated (FINEID S4-1 section 4.6), as the native core
 * decides it from the card's credential numbering and its authentication
 * certificate's validity start, and the exact digit count the card accepts
 * for the activation entry: the card enforces the length itself and a
 * wrong length spends a try. An unknown scheme has no length and gets no
 * activation attempt.
 */
internal enum class CardManagementScheme(
    val activationEntryDigitCount: Int?,
) {
    UNKNOWN(null),
    PUK(ACTIVATION_CODE_DIGIT_COUNT),
    PRESET_PIN(PRESET_ACTIVATION_PIN_DIGIT_COUNT),
}

/** Digits of the activation PIN, the PUK, under section 4.6.1. */
private const val ACTIVATION_CODE_DIGIT_COUNT = 8

/** Digits of the preset activation PIN under section 4.6.2. */
private const val PRESET_ACTIVATION_PIN_DIGIT_COUNT = 7

/** The activation scheme a native reply byte names. */
internal fun decodeActivationScheme(byte: Int): CardManagementScheme =
    when (byte) {
        NativeCardManagementWire.ACTIVATION_SCHEME_PUK -> CardManagementScheme.PUK
        NativeCardManagementWire.ACTIVATION_SCHEME_PRESET -> CardManagementScheme.PRESET_PIN
        else -> CardManagementScheme.UNKNOWN
    }

/** Which PINs a native reply byte says still await activation. */
internal fun decodeActivationNeeds(byte: Int): CardActivationNeeds =
    when (byte) {
        NativeCardManagementWire.ACTIVATION_NEEDS_PIN1_ONLY -> CardActivationNeeds(pin1 = true, pin2 = false)
        NativeCardManagementWire.ACTIVATION_NEEDS_PIN2_ONLY -> CardActivationNeeds(pin1 = false, pin2 = true)
        NativeCardManagementWire.ACTIVATION_NEEDS_BOTH -> CardActivationNeeds(pin1 = true, pin2 = true)
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
    val pinLengths: CardPinLengths? = null,
)

/**
 * The digit counts the card accepts for PIN 1, PIN 2 and the PUK, as the
 * native core reads them where PINs are set: the card's EF.AOD, then the
 * citizen PIN policy, then the FINEID bounds. An empty range is a
 * credential for which the card accepts no length.
 */
internal data class CardPinLengths(
    val pin1: IntRange,
    val pin2: IntRange,
    val puk: IntRange,
) {
    companion object {
        /** The FINEID bounds (FINEID S4-1 v4.2 sections 4.1 and 8.1.5), before the card has listed its own. */
        val FINEID =
            CardPinLengths(
                pin1 = FINEID_PIN1_MIN_LENGTH..PIN_MAX_LENGTH,
                pin2 = FINEID_PIN2_MIN_LENGTH..PIN_MAX_LENGTH,
                puk = PUK_MIN_LENGTH..PUK_MAX_LENGTH,
            )
    }
}

private const val FINEID_PIN1_MIN_LENGTH = 4
private const val FINEID_PIN2_MIN_LENGTH = 6
private const val PIN_MAX_LENGTH = 12
private const val PUK_MIN_LENGTH = 8
private const val PUK_MAX_LENGTH = 12

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

/** Which card channel a management JNI entry point runs over. */
internal enum class CardManagementChannelMode(
    val wireValue: Int,
) {
    WIRED_APDU(NativeCardManagementWire.CHANNEL_MODE_WIRED_APDU),
    WIRED_T0_TPDU(NativeCardManagementWire.CHANNEL_MODE_WIRED_T0_TPDU),
    CONTACTLESS_PACE(NativeCardManagementWire.CHANNEL_MODE_CONTACTLESS_PACE),
    CONTACTLESS_HELD_SESSION(NativeCardManagementWire.CHANNEL_MODE_CONTACTLESS_HELD_SESSION),
    ;

    companion object {
        fun fromExchangeLevel(exchangeLevel: NativeCardExchangeLevel): CardManagementChannelMode =
            when (exchangeLevel) {
                NativeCardExchangeLevel.APDU -> WIRED_APDU
                NativeCardExchangeLevel.T0_TPDU -> WIRED_T0_TPDU
            }
    }
}

/** Which PIN management operation a parameterized JNI call executes. */
internal enum class PinManageOp(
    val wireValue: Int,
) {
    CHANGE_PIN1(NativeCardManagementWire.PIN_OP_CHANGE_PIN1),
    CHANGE_PIN2(NativeCardManagementWire.PIN_OP_CHANGE_PIN2),
    UNBLOCK_PIN1(NativeCardManagementWire.PIN_OP_UNBLOCK_PIN1),
    UNBLOCK_PIN2(NativeCardManagementWire.PIN_OP_UNBLOCK_PIN2),
}

/** Named wire constants shared with `native/refineid-android-core/src/card_management.rs`. */
internal object NativeCardManagementWire {
    const val CHANNEL_MODE_WIRED_APDU = 0
    const val CHANNEL_MODE_WIRED_T0_TPDU = 1
    const val CHANNEL_MODE_CONTACTLESS_PACE = 2
    const val CHANNEL_MODE_CONTACTLESS_HELD_SESSION = 3

    const val PIN_OP_CHANGE_PIN1 = 0
    const val PIN_OP_CHANGE_PIN2 = 1
    const val PIN_OP_UNBLOCK_PIN1 = 2
    const val PIN_OP_UNBLOCK_PIN2 = 3

    const val MANAGEMENT_TAG_BRIDGE_ERROR = 0
    const val MANAGEMENT_TAG_SUCCEEDED = 1
    const val MANAGEMENT_TAG_CARD_UNAVAILABLE = 2
    const val MANAGEMENT_TAG_TRANSPORT_ERROR = 3
    const val MANAGEMENT_TAG_INVALID_CREDENTIAL = 4
    const val MANAGEMENT_TAG_SAFETY_REFUSED = 5
    const val MANAGEMENT_TAG_PACE_REJECTED = 6
    const val MANAGEMENT_TAG_WRONG_CREDENTIAL = 7
    const val MANAGEMENT_TAG_LOCKED = 8
    const val MANAGEMENT_TAG_OTHER = 9

    const val PIN_STATE_VERIFIED = 1
    const val PIN_STATE_REMAINING = 2
    const val PIN_STATE_LOCKED = 3
    const val PIN_STATE_NO_INFO = 4
    const val PIN_STATE_UNRECOGNISED = 5

    const val SCHEME_CITIZEN = 1
    const val SCHEME_ORGANIZATIONAL = 2

    const val ACTIVATION_SCHEME_UNKNOWN = 0
    const val ACTIVATION_SCHEME_PUK = 1
    const val ACTIVATION_SCHEME_PRESET = 2

    const val ACTIVATION_NEEDS_NONE = 0
    const val ACTIVATION_NEEDS_PIN1_ONLY = 1
    const val ACTIVATION_NEEDS_PIN2_ONLY = 2
    const val ACTIVATION_NEEDS_BOTH = 3

    const val TAG_OFFSET = 0

    const val HEALTH_PIN1_STATE_OFFSET = 1
    const val HEALTH_PIN1_RETRIES_OFFSET = 2
    const val HEALTH_PIN2_STATE_OFFSET = 3
    const val HEALTH_PIN2_RETRIES_OFFSET = 4
    const val HEALTH_PUK_STATE_OFFSET = 5
    const val HEALTH_PUK_RETRIES_OFFSET = 6
    const val HEALTH_SCHEME_OFFSET = 7
    const val HEALTH_ACTIVATION_SCHEME_OFFSET = 8
    const val HEALTH_ACTIVATION_NEEDS_OFFSET = 9
    const val HEALTH_REPLY_LENGTH = 10
    const val HEALTH_PIN1_MIN_OFFSET = 10
    const val HEALTH_PIN1_MAX_OFFSET = 11
    const val HEALTH_PIN2_MIN_OFFSET = 12
    const val HEALTH_PIN2_MAX_OFFSET = 13
    const val HEALTH_PUK_MIN_OFFSET = 14
    const val HEALTH_PUK_MAX_OFFSET = 15
    const val HEALTH_REPLY_WITH_LENGTHS_LENGTH = 16

    const val OUTCOME_RETRIES_OFFSET = 1
    const val OUTCOME_MIN_RETRIES_LENGTH = 2
    const val OUTCOME_SW1_OFFSET = 2
    const val OUTCOME_MIN_SW1_LENGTH = 3
    const val OUTCOME_SW2_OFFSET = 3
    const val OUTCOME_REPLY_LENGTH = 4

    const val ACTIVATION_SCHEME_OFFSET = 1
    const val ACTIVATION_PIN1_TAG_OFFSET = 2
    const val ACTIVATION_PIN1_RETRIES_OFFSET = 3
    const val ACTIVATION_PIN2_TAG_OFFSET = 4
    const val ACTIVATION_PIN2_RETRIES_OFFSET = 5
    const val ACTIVATION_REPLY_LENGTH = 6

    const val OCTET_MASK = 0xFF
    const val ZERO_INT = 0
    const val ZERO_BYTE: Byte = 0
}

internal object NativeCardManagement {
    /**
     * The credential health, with the activation scheme the native core
     * decides from the card's numbering and its authentication
     * certificate's validity start, and the card's PIN and PUK lengths when
     * [readPinLengths] asks for them: only where PINs are set.
     */
    fun probeCredentialHealth(
        exchangeLevel: NativeCardExchangeLevel,
        readPinLengths: Boolean,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> =
        executeProbeCredentialHealth(
            target = ChannelTarget.wired(exchangeLevel),
            readPinLengths = readPinLengths,
            exchange = exchange,
        )

    fun changePin1(
        exchangeLevel: NativeCardExchangeLevel,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.wired(exchangeLevel),
            op = PinManageOp.CHANGE_PIN1,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun changePin2(
        exchangeLevel: NativeCardExchangeLevel,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.wired(exchangeLevel),
            op = PinManageOp.CHANGE_PIN2,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun unblockPin1(
        exchangeLevel: NativeCardExchangeLevel,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.wired(exchangeLevel),
            op = PinManageOp.UNBLOCK_PIN1,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun unblockPin2(
        exchangeLevel: NativeCardExchangeLevel,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.wired(exchangeLevel),
            op = PinManageOp.UNBLOCK_PIN2,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun activateCard(
        exchangeLevel: NativeCardExchangeLevel,
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> =
        executeActivateCard(
            target = ChannelTarget.wired(exchangeLevel),
            scheme = scheme,
            code = code,
            newPin1 = newPin1,
            newPin2 = newPin2,
            exchange = exchange,
        )

    // One-shot contactless PACE operations authenticated by the card access number.
    fun contactlessProbeCredentialHealth(
        can: ByteArray,
        readPinLengths: Boolean,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> =
        executeProbeCredentialHealth(
            target = ChannelTarget.pace(can),
            readPinLengths = readPinLengths,
            exchange = exchange,
        )

    fun contactlessChangePin1(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.pace(can),
            op = PinManageOp.CHANGE_PIN1,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessChangePin2(
        can: ByteArray,
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.pace(can),
            op = PinManageOp.CHANGE_PIN2,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessUnblockPin1(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.pace(can),
            op = PinManageOp.UNBLOCK_PIN1,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessUnblockPin2(
        can: ByteArray,
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.pace(can),
            op = PinManageOp.UNBLOCK_PIN2,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessActivateCard(
        can: ByteArray,
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> =
        executeActivateCard(
            target = ChannelTarget.pace(can),
            scheme = scheme,
            code = code,
            newPin1 = newPin1,
            newPin2 = newPin2,
            exchange = exchange,
        )

    // Operations on the secure-messaging session a prior
    // NativeContactlessSession.connect left open: no access number and no
    // second PACE. A card opened under PACE refuses plain commands, so a
    // reader holding that session sends management through these.
    fun contactlessProbeCredentialHealthOnSession(
        readPinLengths: Boolean,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> =
        executeProbeCredentialHealth(
            target = ChannelTarget.heldSession(),
            readPinLengths = readPinLengths,
            exchange = exchange,
        )

    fun contactlessChangePin1OnSession(
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.heldSession(),
            op = PinManageOp.CHANGE_PIN1,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessChangePin2OnSession(
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.heldSession(),
            op = PinManageOp.CHANGE_PIN2,
            firstSecret = currentPin,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessUnblockPin1OnSession(
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.heldSession(),
            op = PinManageOp.UNBLOCK_PIN1,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessUnblockPin2OnSession(
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        executeManagePin(
            target = ChannelTarget.heldSession(),
            op = PinManageOp.UNBLOCK_PIN2,
            firstSecret = puk,
            secondSecret = newPin,
            exchange = exchange,
        )

    fun contactlessActivateCardOnSession(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> =
        executeActivateCard(
            target = ChannelTarget.heldSession(),
            scheme = scheme,
            code = code,
            newPin1 = newPin1,
            newPin2 = newPin2,
            exchange = exchange,
        )

    private fun executeProbeCredentialHealth(
        target: ChannelTarget,
        readPinLengths: Boolean,
        exchange: NativeBlockExchange,
    ): CardManagementResult<CredentialHealth> =
        try {
            if (!NativeCore.isLoaded) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                val reply =
                    probeCredentialHealthNative(
                        target.mode.wireValue,
                        target.can,
                        readPinLengths,
                        exchange,
                    )
                decodeCredentialHealth(reply).also(ObservedCredentialHealth::record)
            }
        } catch (_: LinkageError) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } catch (_: RuntimeException) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } finally {
            target.can?.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    private fun executeManagePin(
        target: ChannelTarget,
        op: PinManageOp,
        firstSecret: ByteArray,
        secondSecret: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        try {
            if (!NativeCore.isLoaded) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                val reply =
                    managePinNative(
                        target.mode.wireValue,
                        op.wireValue,
                        target.can,
                        firstSecret,
                        secondSecret,
                        exchange,
                    )
                decodeManageOutcome(reply)
            }
        } catch (_: LinkageError) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } catch (_: RuntimeException) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } finally {
            target.can?.fill(NativeCardManagementWire.ZERO_BYTE)
            firstSecret.fill(NativeCardManagementWire.ZERO_BYTE)
            secondSecret.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    private fun executeActivateCard(
        target: ChannelTarget,
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ActivationReport> =
        try {
            if (!NativeCore.isLoaded) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                val reply =
                    activateCardNative(
                        target.mode.wireValue,
                        scheme.wireValue(),
                        target.can,
                        code,
                        newPin1,
                        newPin2,
                        exchange,
                    )
                decodeActivationReport(reply)
            }
        } catch (_: LinkageError) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } catch (_: RuntimeException) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } finally {
            target.can?.fill(NativeCardManagementWire.ZERO_BYTE)
            code.fill(NativeCardManagementWire.ZERO_BYTE)
            newPin1?.fill(NativeCardManagementWire.ZERO_BYTE)
            newPin2?.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    private fun CardManagementScheme.wireValue(): Int =
        when (this) {
            CardManagementScheme.PUK -> NativeCardManagementWire.ACTIVATION_SCHEME_PUK
            CardManagementScheme.PRESET_PIN -> NativeCardManagementWire.ACTIVATION_SCHEME_PRESET
            CardManagementScheme.UNKNOWN -> NativeCardManagementWire.ACTIVATION_SCHEME_UNKNOWN
        }

    internal fun decodeCredentialHealth(reply: ByteArray): CardManagementResult<CredentialHealth> =
        try {
            if (reply.isEmpty()) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                when (val tag = reply[NativeCardManagementWire.TAG_OFFSET].toInt()) {
                    NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED -> {
                        if (
                            reply.size != NativeCardManagementWire.HEALTH_REPLY_LENGTH &&
                            reply.size != NativeCardManagementWire.HEALTH_REPLY_WITH_LENGTHS_LENGTH
                        ) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        } else {
                            val p1State =
                                parsePin1State(
                                    reply[NativeCardManagementWire.HEALTH_PIN1_STATE_OFFSET].toInt(),
                                    reply[NativeCardManagementWire.HEALTH_PIN1_RETRIES_OFFSET].toInt(),
                                )
                            val p2State =
                                parsePin2State(
                                    reply[NativeCardManagementWire.HEALTH_PIN2_STATE_OFFSET].toInt(),
                                    reply[NativeCardManagementWire.HEALTH_PIN2_RETRIES_OFFSET].toInt(),
                                )
                            val pukState =
                                parsePin1State(
                                    reply[NativeCardManagementWire.HEALTH_PUK_STATE_OFFSET].toInt(),
                                    reply[NativeCardManagementWire.HEALTH_PUK_RETRIES_OFFSET].toInt(),
                                )
                            val scheme =
                                if (
                                    reply[NativeCardManagementWire.HEALTH_SCHEME_OFFSET].toInt() ==
                                    NativeCardManagementWire.SCHEME_ORGANIZATIONAL
                                ) {
                                    NativePinReferenceScheme.ORGANIZATIONAL
                                } else {
                                    NativePinReferenceScheme.CITIZEN
                                }
                            val actScheme =
                                decodeActivationScheme(
                                    reply[NativeCardManagementWire.HEALTH_ACTIVATION_SCHEME_OFFSET].toInt(),
                                )
                            val needs =
                                decodeActivationNeeds(
                                    reply[NativeCardManagementWire.HEALTH_ACTIVATION_NEEDS_OFFSET].toInt(),
                                )
                            CardManagementResult.Success(
                                CredentialHealth(
                                    pin1State = p1State,
                                    pin2State = p2State,
                                    pukState = pukState,
                                    scheme = scheme,
                                    activationScheme = actScheme,
                                    activationNeeds = needs,
                                    pinLengths = decodePinLengths(reply),
                                ),
                            )
                        }
                    }

                    else -> {
                        CardManagementResult.Failure(mapFailureTag(tag))
                    }
                }
            }
        } finally {
            reply.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    private fun decodePinLengths(reply: ByteArray): CardPinLengths? {
        if (reply.size != NativeCardManagementWire.HEALTH_REPLY_WITH_LENGTHS_LENGTH) return null

        fun range(
            minOffset: Int,
            maxOffset: Int,
        ): IntRange {
            val min = reply[minOffset].toInt() and NativeCardManagementWire.OCTET_MASK
            val max = reply[maxOffset].toInt() and NativeCardManagementWire.OCTET_MASK
            return if (min == NativeCardManagementWire.ZERO_INT) IntRange.EMPTY else min..max
        }
        return CardPinLengths(
            pin1 =
                range(
                    NativeCardManagementWire.HEALTH_PIN1_MIN_OFFSET,
                    NativeCardManagementWire.HEALTH_PIN1_MAX_OFFSET,
                ),
            pin2 =
                range(
                    NativeCardManagementWire.HEALTH_PIN2_MIN_OFFSET,
                    NativeCardManagementWire.HEALTH_PIN2_MAX_OFFSET,
                ),
            puk =
                range(
                    NativeCardManagementWire.HEALTH_PUK_MIN_OFFSET,
                    NativeCardManagementWire.HEALTH_PUK_MAX_OFFSET,
                ),
        )
    }

    internal fun decodeManageOutcome(reply: ByteArray): CardManagementResult<ManageOutcome> =
        try {
            if (reply.isEmpty()) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                when (val tag = reply[NativeCardManagementWire.TAG_OFFSET].toInt()) {
                    NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED -> {
                        CardManagementResult.Success(ManageOutcome.Succeeded)
                    }

                    NativeCardManagementWire.MANAGEMENT_TAG_WRONG_CREDENTIAL -> {
                        val attempts =
                            if (reply.size >= NativeCardManagementWire.OUTCOME_MIN_RETRIES_LENGTH) {
                                reply[NativeCardManagementWire.OUTCOME_RETRIES_OFFSET].toInt() and
                                    NativeCardManagementWire.OCTET_MASK
                            } else {
                                NativeCardManagementWire.ZERO_INT
                            }
                        CardManagementResult.Success(ManageOutcome.WrongCredential(attempts))
                    }

                    NativeCardManagementWire.MANAGEMENT_TAG_LOCKED -> {
                        CardManagementResult.Success(ManageOutcome.Locked)
                    }

                    NativeCardManagementWire.MANAGEMENT_TAG_OTHER -> {
                        val sw1 =
                            if (reply.size >= NativeCardManagementWire.OUTCOME_MIN_SW1_LENGTH) {
                                reply[NativeCardManagementWire.OUTCOME_SW1_OFFSET].toInt() and
                                    NativeCardManagementWire.OCTET_MASK
                            } else {
                                NativeCardManagementWire.ZERO_INT
                            }
                        val sw2 =
                            if (reply.size >= NativeCardManagementWire.OUTCOME_REPLY_LENGTH) {
                                reply[NativeCardManagementWire.OUTCOME_SW2_OFFSET].toInt() and
                                    NativeCardManagementWire.OCTET_MASK
                            } else {
                                NativeCardManagementWire.ZERO_INT
                            }
                        CardManagementResult.Success(ManageOutcome.Other(sw1, sw2))
                    }

                    else -> {
                        CardManagementResult.Failure(mapFailureTag(tag))
                    }
                }
            }
        } finally {
            reply.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    internal fun decodeActivationReport(reply: ByteArray): CardManagementResult<ActivationReport> =
        try {
            if (reply.isEmpty()) {
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
            } else {
                when (val tag = reply[NativeCardManagementWire.TAG_OFFSET].toInt()) {
                    NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED -> {
                        if (reply.size != NativeCardManagementWire.ACTIVATION_REPLY_LENGTH) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        } else {
                            val scheme =
                                decodeActivationScheme(
                                    reply[NativeCardManagementWire.ACTIVATION_SCHEME_OFFSET].toInt(),
                                )
                            val p1Outcome =
                                parseOutcomeTag(
                                    reply[NativeCardManagementWire.ACTIVATION_PIN1_TAG_OFFSET].toInt(),
                                    reply[NativeCardManagementWire.ACTIVATION_PIN1_RETRIES_OFFSET].toInt() and
                                        NativeCardManagementWire.OCTET_MASK,
                                )
                            val p2Outcome =
                                parseOutcomeTag(
                                    reply[NativeCardManagementWire.ACTIVATION_PIN2_TAG_OFFSET].toInt(),
                                    reply[NativeCardManagementWire.ACTIVATION_PIN2_RETRIES_OFFSET].toInt() and
                                        NativeCardManagementWire.OCTET_MASK,
                                )
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
        } finally {
            reply.fill(NativeCardManagementWire.ZERO_BYTE)
        }

    private fun parseOutcomeTag(
        tag: Int,
        retries: Int,
    ): ManageOutcome? =
        when (tag) {
            NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED -> {
                ManageOutcome.Succeeded
            }

            NativeCardManagementWire.MANAGEMENT_TAG_WRONG_CREDENTIAL -> {
                ManageOutcome.WrongCredential(retries)
            }

            NativeCardManagementWire.MANAGEMENT_TAG_LOCKED -> {
                ManageOutcome.Locked
            }

            NativeCardManagementWire.MANAGEMENT_TAG_OTHER -> {
                ManageOutcome.Other(
                    NativeCardManagementWire.ZERO_INT,
                    NativeCardManagementWire.ZERO_INT,
                )
            }

            else -> {
                null
            }
        }

    private fun parsePin1State(
        stateByte: Int,
        retryByte: Int,
    ): NativePin1State =
        when (stateByte) {
            NativeCardManagementWire.PIN_STATE_VERIFIED -> {
                NativePin1State.Verified
            }

            NativeCardManagementWire.PIN_STATE_REMAINING -> {
                NativePin1State.Remaining(retryByte and NativeCardManagementWire.OCTET_MASK)
            }

            NativeCardManagementWire.PIN_STATE_LOCKED -> {
                NativePin1State.Locked
            }

            NativeCardManagementWire.PIN_STATE_NO_INFO -> {
                NativePin1State.NoInformation
            }

            else -> {
                NativePin1State.Unrecognized
            }
        }

    private fun parsePin2State(
        stateByte: Int,
        retryByte: Int,
    ): NativePin2State =
        when (stateByte) {
            NativeCardManagementWire.PIN_STATE_VERIFIED -> {
                NativePin2State.Verified
            }

            NativeCardManagementWire.PIN_STATE_REMAINING -> {
                NativePin2State.Remaining(retryByte and NativeCardManagementWire.OCTET_MASK)
            }

            NativeCardManagementWire.PIN_STATE_LOCKED -> {
                NativePin2State.Locked
            }

            NativeCardManagementWire.PIN_STATE_NO_INFO -> {
                NativePin2State.NoInformation
            }

            else -> {
                NativePin2State.Unrecognized
            }
        }

    private fun mapFailureTag(tag: Int): CardManagementFailure =
        when (tag) {
            NativeCardManagementWire.MANAGEMENT_TAG_CARD_UNAVAILABLE -> CardManagementFailure.CARD_UNAVAILABLE
            NativeCardManagementWire.MANAGEMENT_TAG_TRANSPORT_ERROR -> CardManagementFailure.TRANSPORT_ERROR
            NativeCardManagementWire.MANAGEMENT_TAG_INVALID_CREDENTIAL -> CardManagementFailure.INVALID_CREDENTIAL
            NativeCardManagementWire.MANAGEMENT_TAG_SAFETY_REFUSED -> CardManagementFailure.SAFETY_REFUSED
            NativeCardManagementWire.MANAGEMENT_TAG_PACE_REJECTED -> CardManagementFailure.PACE_REJECTED
            else -> CardManagementFailure.BRIDGE_ERROR
        }

    private class ChannelTarget(
        val mode: CardManagementChannelMode,
        val can: ByteArray? = null,
    ) {
        companion object {
            fun wired(exchangeLevel: NativeCardExchangeLevel): ChannelTarget =
                ChannelTarget(mode = CardManagementChannelMode.fromExchangeLevel(exchangeLevel))

            fun pace(can: ByteArray): ChannelTarget =
                ChannelTarget(
                    mode = CardManagementChannelMode.CONTACTLESS_PACE,
                    can = can,
                )

            fun heldSession(): ChannelTarget = ChannelTarget(mode = CardManagementChannelMode.CONTACTLESS_HELD_SESSION)
        }
    }

    @JvmStatic
    private external fun probeCredentialHealthNative(
        channelMode: Int,
        can: ByteArray?,
        readPinLengths: Boolean,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun managePinNative(
        channelMode: Int,
        op: Int,
        can: ByteArray?,
        firstSecret: ByteArray,
        secondSecret: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    @Suppress("LongParameterList")
    private external fun activateCardNative(
        channelMode: Int,
        scheme: Int,
        can: ByteArray?,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        callback: Any,
    ): ByteArray
}

/**
 * The credential health the latest probe answered, for the diagnostics
 * report: counters, numbering and the activation scheme the native core
 * decided. It holds no credential and no holder data.
 */
internal object ObservedCredentialHealth {
    @Volatile
    var latest: CredentialHealth? = null
        private set

    fun record(result: CardManagementResult<CredentialHealth>) {
        if (result is CardManagementResult.Success) latest = result.value
    }
}
