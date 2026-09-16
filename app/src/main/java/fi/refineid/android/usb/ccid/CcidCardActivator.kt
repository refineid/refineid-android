package fi.refineid.android.usb.ccid

import fi.refineid.android.core.AtrValidation
import fi.refineid.android.diagnostics.AppTrace

internal enum class CcidActivationResult {
    READY,
    NO_CARD,
    CARD_ERROR,
    TRANSPORT_ERROR,
}

/** Resets one present card and validates its public ATR on an open CCID exchange. */
internal class CcidCardActivator(
    private val validateAtr: (ByteArray) -> AtrValidation,
    private val sequenceCounter: CcidSequenceCounter,
) {
    fun activate(
        exchange: CcidCommandExchange,
        exchangeLevel: CcidExchangeLevel,
    ): CcidActivationResult = exchangeSlotStatus(exchange, exchangeLevel)

    private fun exchangeSlotStatus(
        exchange: CcidCommandExchange,
        exchangeLevel: CcidExchangeLevel,
    ): CcidActivationResult {
        val command =
            CcidCommand.getSlotStatus(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
            )
        return try {
            when (val result = exchange.exchange(command)) {
                is CcidExchangeResult.Failure -> {
                    AppTrace.ccidSlotExchangeFailed(result.kind)
                    CcidActivationResult.TRANSPORT_ERROR
                }

                is CcidExchangeResult.Response -> {
                    when (val response = result.value) {
                        is CcidSlotStatus -> {
                            when (response.cardStatus) {
                                CcidCardStatus.ACTIVE,
                                CcidCardStatus.INACTIVE,
                                -> {
                                    AppTrace.ccidCardState(response.cardStatus)
                                    exchangePowerOn(exchange, exchangeLevel)
                                }

                                CcidCardStatus.NOT_PRESENT -> {
                                    AppTrace.ccidCardState(response.cardStatus)
                                    CcidActivationResult.NO_CARD
                                }
                            }
                        }

                        is CcidCommandFailure -> {
                            if (response.cardStatus == CcidCardStatus.NOT_PRESENT) {
                                CcidActivationResult.NO_CARD
                            } else {
                                CcidActivationResult.TRANSPORT_ERROR
                            }
                        }

                        is CcidTimeExtension -> {
                            CcidActivationResult.TRANSPORT_ERROR
                        }

                        is CcidDataBlock -> {
                            response.close()
                            CcidActivationResult.TRANSPORT_ERROR
                        }

                        is CcidParameters -> {
                            response.close()
                            CcidActivationResult.TRANSPORT_ERROR
                        }
                    }
                }
            }
        } finally {
            command.close()
        }
    }

    private fun exchangePowerOn(
        exchange: CcidCommandExchange,
        exchangeLevel: CcidExchangeLevel,
        allowPps: Boolean = true,
    ): CcidActivationResult {
        val command =
            CcidCommand.powerOnAutomatic(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
            )
        return try {
            when (val result = exchange.exchange(command)) {
                is CcidExchangeResult.Failure -> {
                    AppTrace.ccidPowerExchangeFailed(result.kind)
                    CcidActivationResult.TRANSPORT_ERROR
                }

                is CcidExchangeResult.Response -> {
                    when (val response = result.value) {
                        is CcidDataBlock -> {
                            validatePoweredCard(response, exchangeLevel, exchange, allowPps)
                        }

                        is CcidCommandFailure -> {
                            if (response.cardStatus == CcidCardStatus.NOT_PRESENT) {
                                CcidActivationResult.NO_CARD
                            } else {
                                CcidActivationResult.CARD_ERROR
                            }
                        }

                        is CcidTimeExtension -> {
                            AppTrace.ccidTimeExtension(
                                count = 1,
                                multiplier = response.multiplier,
                            )
                            CcidActivationResult.TRANSPORT_ERROR
                        }

                        is CcidSlotStatus -> {
                            AppTrace.ccidCardState(response.cardStatus)
                            CcidActivationResult.TRANSPORT_ERROR
                        }

                        is CcidParameters -> {
                            response.close()
                            CcidActivationResult.TRANSPORT_ERROR
                        }
                    }
                }
            }
        } finally {
            command.close()
        }
    }

    private fun validatePoweredCard(
        response: CcidDataBlock,
        exchangeLevel: CcidExchangeLevel,
        exchange: CcidCommandExchange,
        allowPps: Boolean,
    ): CcidActivationResult =
        response.use {
            if (
                response.cardStatus != CcidCardStatus.ACTIVE ||
                response.chainParameter != CcidChainParameter.COMPLETE ||
                response.payloadLength > MAXIMUM_ATR_LENGTH
            ) {
                AppTrace.ccidPowerResult(
                    cardStatus = response.cardStatus,
                    chainParameter = response.chainParameter.toString(),
                    payloadLength = response.payloadLength,
                )
                CcidActivationResult.CARD_ERROR
            } else {
                val atr = response.copyPayload()
                try {
                    val validation = validateAtr(atr)
                    val result = mapAtrValidation(validation, exchangeLevel)
                    AppTrace.ccidAtrResult(
                        length = atr.size,
                        validation = validation,
                        isSupported = result == CcidActivationResult.READY,
                        atrHex = atr.toHex(),
                    )
                    if (result == CcidActivationResult.READY) {
                        negotiateParameters(exchange, exchangeLevel, validation, atr, allowPps)
                    } else {
                        result
                    }
                } finally {
                    atr.fill(0)
                }
            }
        }

    /**
     * Run the T=0 parameter negotiation: enforce the T=0 protocol and,
     * when the ATR proposes a faster rate, switch the reader to it and
     * prove the faster link with one card exchange. A rejected switch
     * keeps the current speed; a dead link after an accepted switch
     * resets the card and activates once more at the default rate.
     */
    private fun negotiateParameters(
        exchange: CcidCommandExchange,
        exchangeLevel: CcidExchangeLevel,
        validation: AtrValidation,
        atr: ByteArray,
        allowPps: Boolean,
    ): CcidActivationResult {
        if (!isT0(validation)) return CcidActivationResult.READY
        val targetFiDi = if (allowPps) proposedFiDi(atr) ?: DEFAULT_FIDI else DEFAULT_FIDI
        val currentProtocol = readCurrentProtocol(exchange)
        if (currentProtocol != T0_PROTOCOL_NUMBER || targetFiDi != DEFAULT_FIDI) {
            if (!setParameters(exchange, validation, targetFiDi)) {
                return CcidActivationResult.READY
            }
            if (targetFiDi != DEFAULT_FIDI && !verifyLinkAlive(exchange)) {
                return recoverAtDefaultSpeed(exchange, exchangeLevel, validation)
            }
        }
        return CcidActivationResult.READY
    }

    private fun isT0(validation: AtrValidation): Boolean =
        validation == AtrValidation.VALID_T0_DIRECT ||
            validation == AtrValidation.VALID_T0_INVERSE

    /**
     * The ATR TA1 rate proposal, or null when the ATR carries none or
     * proposes the default rate already in force.
     */
    private fun proposedFiDi(atr: ByteArray): Int? {
        if (atr.size <= ATR_TA1_INDEX) return null
        if (atr[ATR_T0_INDEX].toInt() and T0_TA1_PRESENT_MASK == 0) return null
        val ta1 = atr[ATR_TA1_INDEX].toInt() and CcidWire.BYTE_MAX
        return if (ta1 == DEFAULT_FIDI) null else ta1
    }

    private fun readCurrentProtocol(exchange: CcidCommandExchange): Int? {
        val getCmd =
            CcidCommand.getParameters(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
            )
        var currentProtocol: Int? = null
        try {
            when (val getResult = exchange.exchange(getCmd)) {
                is CcidExchangeResult.Response -> {
                    when (val res = getResult.value) {
                        is CcidParameters -> {
                            res.use {
                                currentProtocol = res.protocolNum
                                AppTrace.ccidParameters(res.protocolNum, res.copyPayload().toHex())
                            }
                        }

                        is CcidCommandFailure -> {
                            AppTrace.ccidParametersFailure(res.errorCode)
                        }

                        is CcidDataBlock -> {
                            res.close()
                        }

                        else -> {}
                    }
                }

                is CcidExchangeResult.Failure -> {
                    AppTrace.ccidParametersExchangeFailed(getResult.kind)
                }
            }
        } finally {
            getCmd.close()
        }
        return currentProtocol
    }

    private fun setParameters(
        exchange: CcidCommandExchange,
        validation: AtrValidation,
        fiDi: Int,
    ): Boolean {
        val setCmd =
            CcidCommand.setParametersT0(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
                fiDi = fiDi,
                inverseConvention = validation == AtrValidation.VALID_T0_INVERSE,
            )
        try {
            when (val setResult = exchange.exchange(setCmd)) {
                is CcidExchangeResult.Response -> {
                    when (val res = setResult.value) {
                        is CcidParameters -> {
                            res.use {
                                AppTrace.ccidSetParametersResult(true, "protocol=" + res.protocolNum)
                            }
                            return true
                        }

                        is CcidCommandFailure -> {
                            AppTrace.ccidSetParametersResult(false, "error=" + res.errorCode)
                        }

                        is CcidDataBlock -> {
                            res.close()
                            AppTrace.ccidSetParametersResult(false, "unexpected")
                        }

                        else -> {
                            AppTrace.ccidSetParametersResult(false, "unexpected")
                        }
                    }
                }

                is CcidExchangeResult.Failure -> {
                    AppTrace.ccidSetParametersResult(false, "failure=" + setResult.kind)
                }
            }
        } finally {
            setCmd.close()
        }
        return false
    }

    /**
     * Prove the negotiated link with one replay-safe SELECT: any card
     * answer, even an error status, shows the link is alive. Only a
     * transport failure or reader-level error reports a dead link.
     */
    private fun verifyLinkAlive(exchange: CcidCommandExchange): Boolean {
        val probe =
            CcidCommand.transferBlock(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
                block = SELECT_MF,
            )
        try {
            when (val result = exchange.exchange(probe)) {
                is CcidExchangeResult.Response -> {
                    when (val res = result.value) {
                        is CcidDataBlock -> {
                            res.use {
                                AppTrace.ccidPpsLinkCheck(alive = true)
                            }
                            return true
                        }

                        is CcidParameters -> {
                            res.close()
                        }

                        else -> {}
                    }
                }

                is CcidExchangeResult.Failure -> {}
            }
        } finally {
            probe.close()
        }
        AppTrace.ccidPpsLinkCheck(alive = false)
        return false
    }

    /**
     * Bring a link that died under fast parameters back: re-assert the
     * default rate, which needs no card exchange, then reset the card
     * and activate once more without proposing fast parameters.
     */
    private fun recoverAtDefaultSpeed(
        exchange: CcidCommandExchange,
        exchangeLevel: CcidExchangeLevel,
        validation: AtrValidation,
    ): CcidActivationResult {
        setParameters(exchange, validation, DEFAULT_FIDI)
        return exchangePowerOn(exchange, exchangeLevel, allowPps = false)
    }

    private fun mapAtrValidation(
        validation: AtrValidation,
        exchangeLevel: CcidExchangeLevel,
    ): CcidActivationResult =
        when (validation) {
            AtrValidation.VALID_T0_DIRECT,
            AtrValidation.VALID_T0_INVERSE,
            -> {
                CcidActivationResult.READY
            }

            AtrValidation.VALID_NON_T0_DIRECT,
            AtrValidation.VALID_NON_T0_INVERSE,
            -> {
                if (exchangeLevel == CcidExchangeLevel.TPDU) {
                    CcidActivationResult.CARD_ERROR
                } else {
                    CcidActivationResult.READY
                }
            }

            AtrValidation.INVALID -> {
                CcidActivationResult.CARD_ERROR
            }

            AtrValidation.BRIDGE_ERROR -> {
                CcidActivationResult.TRANSPORT_ERROR
            }
        }

    private companion object {
        const val FIRST_SLOT = 0
        const val MAXIMUM_ATR_LENGTH = 33
        const val T0_PROTOCOL_NUMBER = 0
        const val DEFAULT_FIDI = 0x11
        const val ATR_T0_INDEX = 1
        const val ATR_TA1_INDEX = 2
        const val T0_TA1_PRESENT_MASK = 0x10
        const val SELECT_CLA: Byte = 0x00
        const val SELECT_INS = 0xA4
        const val SELECT_MF_P1: Byte = 0x00
        const val SELECT_MF_P2_NO_RESPONSE: Byte = 0x0C
        val SELECT_MF =
            byteArrayOf(SELECT_CLA, SELECT_INS.toByte(), SELECT_MF_P1, SELECT_MF_P2_NO_RESPONSE)
    }
}

/** Lowercase hex of public reset bytes; the ATR identifies the card model. */
private fun ByteArray.toHex(): String =
    joinToString("") {
        it
            .toInt()
            .and(CcidWire.BYTE_MAX)
            .toString(HEX_RADIX)
            .padStart(BYTE_HEX_DIGITS, '0')
    }

private const val HEX_RADIX = 16
private const val BYTE_HEX_DIGITS = 2
