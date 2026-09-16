package fi.refineid.android.usb.ccid

internal enum class CcidExchangeLevel {
    TPDU,
    SHORT_APDU,
    SHORT_AND_EXTENDED_APDU,
}

internal class CcidFunctionalDescriptor private constructor(
    val exchangeLevel: CcidExchangeLevel,
    val maximumMessageLength: Int,
    val features: Long,
    val protocols: Long,
) {
    val maximumPayloadLength: Int
        get() = maximumMessageLength - CcidWire.HEADER_SIZE

    /**
     * True when the host must drive the PPS exchange itself: a TPDU
     * reader declaring neither automatic parameter negotiation nor
     * automatic PPS (CCID Rev 1.1 section 5.1, footnote 4).
     * SetParameters alone only retunes such a reader while the card
     * stays at the default rate.
     */
    val hostPpsExchangeRequired: Boolean
        get() =
            exchangeLevel == CcidExchangeLevel.TPDU &&
                features and AUTOMATIC_PARAMETER_NEGOTIATION == 0L &&
                features and AUTOMATIC_PPS == 0L

    val maximumTransferBlockLength: Int
        get() =
            when (exchangeLevel) {
                CcidExchangeLevel.TPDU -> {
                    minOf(maximumPayloadLength, MAXIMUM_T0_TPDU_LENGTH)
                }

                CcidExchangeLevel.SHORT_APDU -> {
                    minOf(maximumPayloadLength, MAXIMUM_SHORT_APDU_LENGTH)
                }

                CcidExchangeLevel.SHORT_AND_EXTENDED_APDU -> {
                    maximumPayloadLength
                }
            }

    override fun toString(): String =
        "CcidFunctionalDescriptor(exchangeLevel=" + exchangeLevel +
            ", maximumMessageLength=" + maximumMessageLength +
            ", features=" + features.toString(HEX_RADIX) +
            ", protocols=" + protocols.toString(HEX_RADIX) + ")"

    companion object {
        fun parse(
            rawDescriptors: ByteArray,
            interfaceNumber: Int,
            alternateSetting: Int,
        ): CcidFunctionalDescriptor {
            requireUnsignedByte("interfaceNumber", interfaceNumber)
            requireUnsignedByte("alternateSetting", alternateSetting)

            var offset = 0
            var isTargetInterface = false
            while (offset < rawDescriptors.size) {
                if (rawDescriptors.size - offset < USB_DESCRIPTOR_HEADER_LENGTH) {
                    throw descriptorError(
                        CcidDescriptorErrorKind.TRUNCATED_DESCRIPTOR_HEADER,
                        "USB descriptor header is truncated",
                    )
                }

                val descriptorLength = rawDescriptors.unsignedByte(offset)
                if (descriptorLength < USB_DESCRIPTOR_HEADER_LENGTH) {
                    throw descriptorError(
                        CcidDescriptorErrorKind.INVALID_DESCRIPTOR_LENGTH,
                        "USB descriptor length is invalid",
                    )
                }
                val descriptorEnd = offset + descriptorLength
                if (descriptorEnd > rawDescriptors.size) {
                    throw descriptorError(
                        CcidDescriptorErrorKind.TRUNCATED_DESCRIPTOR,
                        "USB descriptor exceeds the received byte count",
                    )
                }

                when (rawDescriptors.unsignedByte(offset + DESCRIPTOR_TYPE_OFFSET)) {
                    USB_INTERFACE_DESCRIPTOR_TYPE -> {
                        if (descriptorLength < USB_INTERFACE_DESCRIPTOR_LENGTH) {
                            throw descriptorError(
                                CcidDescriptorErrorKind.INVALID_INTERFACE_DESCRIPTOR,
                                "USB interface descriptor is too short",
                            )
                        }
                        isTargetInterface =
                            rawDescriptors.unsignedByte(offset + INTERFACE_NUMBER_OFFSET) ==
                            interfaceNumber &&
                            rawDescriptors.unsignedByte(offset + ALTERNATE_SETTING_OFFSET) ==
                            alternateSetting &&
                            rawDescriptors.unsignedByte(offset + INTERFACE_CLASS_OFFSET) ==
                            CCID_INTERFACE_CLASS
                    }

                    CCID_FUNCTIONAL_DESCRIPTOR_TYPE -> {
                        if (isTargetInterface) {
                            return parseCcidDescriptor(
                                bytes = rawDescriptors,
                                offset = offset,
                                descriptorLength = descriptorLength,
                            )
                        }
                    }
                }

                offset = descriptorEnd
            }

            throw descriptorError(
                CcidDescriptorErrorKind.MISSING_CCID_DESCRIPTOR,
                "CCID functional descriptor was not found",
            )
        }

        private fun parseCcidDescriptor(
            bytes: ByteArray,
            offset: Int,
            descriptorLength: Int,
        ): CcidFunctionalDescriptor {
            if (descriptorLength < CCID_FUNCTIONAL_DESCRIPTOR_LENGTH) {
                throw descriptorError(
                    CcidDescriptorErrorKind.CCID_DESCRIPTOR_TOO_SHORT,
                    "CCID functional descriptor is too short",
                )
            }

            val features =
                bytes.readUnsignedIntLittleEndian(offset + FEATURES_OFFSET)
            val exchangeLevel =
                when (features and EXCHANGE_LEVEL_MASK) {
                    TPDU_EXCHANGE -> {
                        CcidExchangeLevel.TPDU
                    }

                    SHORT_APDU_EXCHANGE -> {
                        CcidExchangeLevel.SHORT_APDU
                    }

                    SHORT_AND_EXTENDED_APDU_EXCHANGE -> {
                        CcidExchangeLevel.SHORT_AND_EXTENDED_APDU
                    }

                    CHARACTER_EXCHANGE -> {
                        throw descriptorError(
                            CcidDescriptorErrorKind.UNSUPPORTED_EXCHANGE_LEVEL,
                            "CCID character-level exchange is not supported",
                        )
                    }

                    else -> {
                        throw descriptorError(
                            CcidDescriptorErrorKind.INVALID_EXCHANGE_LEVEL,
                            "CCID declares multiple exchange levels",
                        )
                    }
                }

            val automaticNegotiation =
                features and AUTOMATIC_PARAMETER_NEGOTIATION != 0L
            val automaticPps = features and AUTOMATIC_PPS != 0L
            if (automaticNegotiation && automaticPps) {
                throw descriptorError(
                    CcidDescriptorErrorKind.INVALID_APDU_CONFIGURATION,
                    "CCID declares conflicting automatic parameter handling",
                    featuresDetail(features, declaredMessageLength = -1),
                )
            }

            val declaredMessageLength =
                bytes.readUnsignedIntLittleEndian(offset + MAXIMUM_MESSAGE_LENGTH_OFFSET)
            if (declaredMessageLength > MAXIMUM_CCID_MESSAGE_LENGTH.toLong()) {
                throw descriptorError(
                    CcidDescriptorErrorKind.MESSAGE_LENGTH_OUT_OF_RANGE,
                    "CCID maximum message length exceeds the specification bound",
                    featuresDetail(features, declaredMessageLength),
                )
            }
            val minimumMessageLength =
                when (exchangeLevel) {
                    CcidExchangeLevel.TPDU -> MINIMUM_T0_TPDU_MESSAGE_LENGTH

                    CcidExchangeLevel.SHORT_APDU,
                    CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
                    -> MINIMUM_SHORT_APDU_MESSAGE_LENGTH
                }
            if (declaredMessageLength < minimumMessageLength.toLong()) {
                throw descriptorError(
                    CcidDescriptorErrorKind.TRANSFER_MESSAGE_BOUND_TOO_SMALL,
                    "CCID maximum message length cannot carry one transfer block",
                    featuresDetail(features, declaredMessageLength),
                )
            }

            val protocols = bytes.readUnsignedIntLittleEndian(offset + PROTOCOLS_OFFSET)
            return CcidFunctionalDescriptor(
                exchangeLevel = exchangeLevel,
                maximumMessageLength = declaredMessageLength.toInt(),
                features = features,
                protocols = protocols,
            )
        }

        /**
         * Feature flags and message length as plain integers for the
         * trace. A negative length omits it (not yet parsed at flag
         * checks).
         */
        private fun featuresDetail(
            features: Long,
            declaredMessageLength: Long,
        ): String {
            var detail = "features=" + features.toString(HEX_RADIX)
            if (declaredMessageLength >= 0) {
                detail += " max-message=" + declaredMessageLength
            }
            return detail
        }

        private fun ByteArray.unsignedByte(offset: Int): Int = this[offset].toInt() and CcidWire.BYTE_MAX

        private fun requireUnsignedByte(
            name: String,
            value: Int,
        ) {
            require(value in 0..CcidWire.BYTE_MAX) {
                name + " must fit one unsigned byte"
            }
        }

        private fun descriptorError(
            kind: CcidDescriptorErrorKind,
            message: String,
            detail: String = "",
        ): CcidDescriptorException = CcidDescriptorException(kind, message, detail = detail)

        private const val HEX_RADIX = 16
        private const val USB_DESCRIPTOR_HEADER_LENGTH = 2
        private const val DESCRIPTOR_TYPE_OFFSET = 1

        private const val USB_INTERFACE_DESCRIPTOR_TYPE = 0x04
        private const val USB_INTERFACE_DESCRIPTOR_LENGTH = 9
        private const val INTERFACE_NUMBER_OFFSET = 2
        private const val ALTERNATE_SETTING_OFFSET = 3
        private const val INTERFACE_CLASS_OFFSET = 5
        private const val CCID_INTERFACE_CLASS = 0x0B

        private const val CCID_FUNCTIONAL_DESCRIPTOR_TYPE = 0x21
        private const val CCID_FUNCTIONAL_DESCRIPTOR_LENGTH = 54
        private const val PROTOCOLS_OFFSET = 6
        private const val FEATURES_OFFSET = 40
        private const val MAXIMUM_MESSAGE_LENGTH_OFFSET = 44

        private const val AUTOMATIC_PARAMETER_CONFIGURATION = 0x00000002L
        private const val AUTOMATIC_PARAMETER_NEGOTIATION = 0x00000040L
        private const val AUTOMATIC_PPS = 0x00000080L
        private const val TPDU_EXCHANGE = 0x00010000L
        private const val SHORT_APDU_EXCHANGE = 0x00020000L
        private const val SHORT_AND_EXTENDED_APDU_EXCHANGE = 0x00040000L
        private const val EXCHANGE_LEVEL_MASK = 0x00070000L
        private const val CHARACTER_EXCHANGE = 0L

        private const val MAXIMUM_T0_TPDU_LENGTH = 260
        private const val MINIMUM_T0_TPDU_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_T0_TPDU_LENGTH
        private const val MAXIMUM_SHORT_APDU_LENGTH = 261
        private const val MINIMUM_SHORT_APDU_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_SHORT_APDU_LENGTH
        private const val MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH = 65_544
        private const val MAXIMUM_CCID_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH
    }
}

internal enum class CcidDescriptorErrorKind {
    TRUNCATED_DESCRIPTOR_HEADER,
    INVALID_DESCRIPTOR_LENGTH,
    TRUNCATED_DESCRIPTOR,
    INVALID_INTERFACE_DESCRIPTOR,
    MISSING_CCID_DESCRIPTOR,
    CCID_DESCRIPTOR_TOO_SHORT,
    UNSUPPORTED_EXCHANGE_LEVEL,
    INVALID_EXCHANGE_LEVEL,
    INVALID_APDU_CONFIGURATION,
    MESSAGE_LENGTH_OUT_OF_RANGE,
    TRANSFER_MESSAGE_BOUND_TOO_SMALL,
}

internal class CcidDescriptorException(
    val kind: CcidDescriptorErrorKind,
    message: String,
    /**
     * Integer-only framing detail (feature flags, lengths) — never
     * descriptor strings, which may carry serial numbers.
     */
    val detail: String = "",
) : Exception(message)
