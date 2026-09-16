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
                            validatePoweredCard(response, exchangeLevel, exchange)
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
                        configureParametersIfRequired(exchange, validation)
                    }
                    result
                } finally {
                    atr.fill(0)
                }
            }
        }

    private fun configureParametersIfRequired(
        exchange: CcidCommandExchange,
        validation: AtrValidation,
    ) {
        val isT0 =
            validation == AtrValidation.VALID_T0_DIRECT ||
                validation == AtrValidation.VALID_T0_INVERSE
        if (!isT0) return

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

        if (currentProtocol != 0) {
            val setCmd =
                CcidCommand.setParametersT0(
                    slot = FIRST_SLOT,
                    sequence = sequenceCounter.take(),
                    fiDi = 0x11,
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
                            }

                            is CcidCommandFailure -> {
                                AppTrace.ccidSetParametersResult(false, "error=" + res.errorCode)
                            }

                            is CcidDataBlock -> {
                                res.close()
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
        }
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
