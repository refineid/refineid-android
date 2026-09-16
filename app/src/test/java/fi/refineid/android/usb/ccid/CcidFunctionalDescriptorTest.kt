package fi.refineid.android.usb.ccid

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CcidFunctionalDescriptorTest {
    @Test
    fun acceptsShortApduExchangeWithAutomaticNegotiation() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features =
                            AUTOMATIC_PARAMETER_CONFIGURATION or
                                AUTOMATIC_PARAMETER_NEGOTIATION or
                                SHORT_APDU_EXCHANGE,
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertEquals(CcidExchangeLevel.SHORT_APDU, descriptor.exchangeLevel)
        assertEquals(MAXIMUM_MESSAGE_LENGTH, descriptor.maximumMessageLength)
        assertEquals(
            MAXIMUM_MESSAGE_LENGTH - CcidWire.HEADER_SIZE,
            descriptor.maximumPayloadLength,
        )
        assertEquals(
            MAXIMUM_SHORT_APDU_LENGTH,
            descriptor.maximumTransferBlockLength,
        )
    }

    @Test
    fun acceptsShortAndExtendedExchangeWithAutomaticPps() {
        val extendedMessageLength =
            CcidWire.HEADER_SIZE + EXTENDED_TRANSFER_BLOCK_LENGTH
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features =
                            AUTOMATIC_PARAMETER_CONFIGURATION or
                                AUTOMATIC_PPS or
                                SHORT_AND_EXTENDED_APDU_EXCHANGE,
                        maximumMessageLength = extendedMessageLength.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertEquals(
            CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
            descriptor.exchangeLevel,
        )
        assertEquals(
            EXTENDED_TRANSFER_BLOCK_LENGTH,
            descriptor.maximumTransferBlockLength,
        )
    }

    @Test
    fun acceptsTpduExchangeWithoutAutomaticParameterHandling() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = TPDU_EXCHANGE,
                        maximumMessageLength = MINIMUM_T0_TPDU_MESSAGE_LENGTH.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertEquals(CcidExchangeLevel.TPDU, descriptor.exchangeLevel)
        assertEquals(
            MINIMUM_T0_TPDU_MESSAGE_LENGTH,
            descriptor.maximumMessageLength,
        )
        assertEquals(
            MAXIMUM_T0_TPDU_LENGTH,
            descriptor.maximumTransferBlockLength,
        )
    }

    @Test
    fun tpduWithoutAutomaticPpsRequiresHostPps() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = TPDU_WITHOUT_AUTOMATIC_PPS_FEATURES,
                        maximumMessageLength = MAXIMUM_MESSAGE_LENGTH.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertTrue(descriptor.hostPpsExchangeRequired)
    }

    @Test
    fun tpduWithAutomaticPpsSkipsHostPps() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = TPDU_EXCHANGE or AUTOMATIC_PPS,
                        maximumMessageLength = MAXIMUM_MESSAGE_LENGTH.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertFalse(descriptor.hostPpsExchangeRequired)
    }

    @Test
    fun tpduWithAutomaticNegotiationSkipsHostPps() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = TPDU_EXCHANGE or AUTOMATIC_PARAMETER_NEGOTIATION,
                        maximumMessageLength = MAXIMUM_MESSAGE_LENGTH.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertFalse(descriptor.hostPpsExchangeRequired)
    }

    @Test
    fun apduExchangeNeverRequiresHostPps() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = VALID_SHORT_APDU_FEATURES,
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertFalse(descriptor.hostPpsExchangeRequired)
    }

    @Test
    fun capsTpduBlockBelowLargerReaderPayloadBound() {
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = TPDU_EXCHANGE,
                        maximumMessageLength = MAXIMUM_MESSAGE_LENGTH.toLong(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertEquals(
            MAXIMUM_T0_TPDU_LENGTH,
            descriptor.maximumTransferBlockLength,
        )
    }

    @Test
    fun selectsTheRequestedCcidInterface() {
        val unrelated =
            descriptors(
                interfaceNumber = OTHER_INTERFACE,
                features = TPDU_EXCHANGE,
            )
        val target =
            descriptors(
                features =
                    AUTOMATIC_PARAMETER_CONFIGURATION or
                        AUTOMATIC_PARAMETER_NEGOTIATION or
                        SHORT_APDU_EXCHANGE,
            )

        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors = unrelated + target,
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )

        assertEquals(CcidExchangeLevel.SHORT_APDU, descriptor.exchangeLevel)
    }

    @Test
    fun rejectsTruncatedDescriptorHeader() {
        assertDescriptorError(CcidDescriptorErrorKind.TRUNCATED_DESCRIPTOR_HEADER) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = byteArrayOf(USB_INTERFACE_DESCRIPTOR_LENGTH.toByte()),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsInvalidDescriptorLength() {
        assertDescriptorError(CcidDescriptorErrorKind.INVALID_DESCRIPTOR_LENGTH) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    byteArrayOf(
                        INVALID_ZERO_DESCRIPTOR_LENGTH,
                        USB_INTERFACE_DESCRIPTOR_TYPE.toByte(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsDescriptorThatExceedsTheReceivedBytes() {
        assertDescriptorError(CcidDescriptorErrorKind.TRUNCATED_DESCRIPTOR) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    byteArrayOf(
                        USB_INTERFACE_DESCRIPTOR_LENGTH.toByte(),
                        USB_INTERFACE_DESCRIPTOR_TYPE.toByte(),
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsShortInterfaceDescriptor() {
        val bytes =
            byteArrayOf(
                SHORT_INTERFACE_DESCRIPTOR_LENGTH.toByte(),
                USB_INTERFACE_DESCRIPTOR_TYPE.toByte(),
            )

        assertDescriptorError(CcidDescriptorErrorKind.INVALID_INTERFACE_DESCRIPTOR) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = bytes,
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsMissingFunctionalDescriptor() {
        assertDescriptorError(CcidDescriptorErrorKind.MISSING_CCID_DESCRIPTOR) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = interfaceDescriptor(TARGET_INTERFACE),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsShortFunctionalDescriptor() {
        val functional =
            ByteArray(SHORT_FUNCTIONAL_DESCRIPTOR_LENGTH).apply {
                this[LENGTH_OFFSET] = size.toByte()
                this[TYPE_OFFSET] = CCID_FUNCTIONAL_DESCRIPTOR_TYPE.toByte()
            }

        assertDescriptorError(CcidDescriptorErrorKind.CCID_DESCRIPTOR_TOO_SHORT) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = interfaceDescriptor(TARGET_INTERFACE) + functional,
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsCharacterExchangeLevel() {
        assertDescriptorError(CcidDescriptorErrorKind.UNSUPPORTED_EXCHANGE_LEVEL) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = descriptors(features = CHARACTER_EXCHANGE),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsMultipleExchangeLevels() {
        assertDescriptorError(CcidDescriptorErrorKind.INVALID_EXCHANGE_LEVEL) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features =
                            AUTOMATIC_PARAMETER_CONFIGURATION or
                                AUTOMATIC_PARAMETER_NEGOTIATION or
                                SHORT_APDU_EXCHANGE or
                                SHORT_AND_EXTENDED_APDU_EXCHANGE,
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsConflictingAutomaticParameterHandling() {
        val conflictingFeatures =
            SHORT_APDU_EXCHANGE or
                AUTOMATIC_PARAMETER_NEGOTIATION or
                AUTOMATIC_PPS
        assertDescriptorError(CcidDescriptorErrorKind.INVALID_APDU_CONFIGURATION) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors = descriptors(features = conflictingFeatures),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun invalidApduConfigurationCarriesFeatureFlags() {
        val conflictingFeatures =
            SHORT_APDU_EXCHANGE or
                AUTOMATIC_PARAMETER_NEGOTIATION or
                AUTOMATIC_PPS
        val exception =
            assertThrows(CcidDescriptorException::class.java) {
                CcidFunctionalDescriptor.parse(
                    rawDescriptors = descriptors(features = conflictingFeatures),
                    interfaceNumber = TARGET_INTERFACE,
                    alternateSetting = TARGET_ALTERNATE_SETTING,
                )
            }

        assertEquals(CcidDescriptorErrorKind.INVALID_APDU_CONFIGURATION, exception.kind)
        assertEquals(
            "features=" + conflictingFeatures.toString(HEX_RADIX),
            exception.detail,
        )
    }

    @Test
    fun acceptsOmnikey3021Features() {
        val omnikeyFeatures = 0x000407B8L
        val descriptor =
            CcidFunctionalDescriptor.parse(
                rawDescriptors = descriptors(features = omnikeyFeatures),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        assertEquals(CcidExchangeLevel.SHORT_AND_EXTENDED_APDU, descriptor.exchangeLevel)
        assertEquals(omnikeyFeatures, descriptor.features)
    }

    @Test
    fun rejectsMessageBoundBelowOneShortApdu() {
        assertDescriptorError(CcidDescriptorErrorKind.TRANSFER_MESSAGE_BOUND_TOO_SMALL) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = VALID_SHORT_APDU_FEATURES,
                        maximumMessageLength = MINIMUM_MESSAGE_LENGTH - 1L,
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    @Test
    fun rejectsMessageBoundAboveTheCcidMaximum() {
        assertDescriptorError(CcidDescriptorErrorKind.MESSAGE_LENGTH_OUT_OF_RANGE) {
            CcidFunctionalDescriptor.parse(
                rawDescriptors =
                    descriptors(
                        features = VALID_SHORT_APDU_FEATURES,
                        maximumMessageLength = MAXIMUM_CCID_MESSAGE_LENGTH + 1L,
                    ),
                interfaceNumber = TARGET_INTERFACE,
                alternateSetting = TARGET_ALTERNATE_SETTING,
            )
        }
    }

    private fun descriptors(
        interfaceNumber: Int = TARGET_INTERFACE,
        features: Long,
        maximumMessageLength: Long = MAXIMUM_MESSAGE_LENGTH.toLong(),
    ): ByteArray =
        interfaceDescriptor(interfaceNumber) +
            functionalDescriptor(features, maximumMessageLength)

    private fun interfaceDescriptor(interfaceNumber: Int): ByteArray =
        ByteArray(USB_INTERFACE_DESCRIPTOR_LENGTH).apply {
            this[LENGTH_OFFSET] = size.toByte()
            this[TYPE_OFFSET] = USB_INTERFACE_DESCRIPTOR_TYPE.toByte()
            this[INTERFACE_NUMBER_OFFSET] = interfaceNumber.toByte()
            this[ALTERNATE_SETTING_OFFSET] = TARGET_ALTERNATE_SETTING.toByte()
            this[INTERFACE_CLASS_OFFSET] = CCID_INTERFACE_CLASS.toByte()
        }

    private fun functionalDescriptor(
        features: Long,
        maximumMessageLength: Long,
    ): ByteArray =
        ByteArray(CCID_FUNCTIONAL_DESCRIPTOR_LENGTH).apply {
            this[LENGTH_OFFSET] = size.toByte()
            this[TYPE_OFFSET] = CCID_FUNCTIONAL_DESCRIPTOR_TYPE.toByte()
            writeUnsignedIntLittleEndian(FEATURES_OFFSET, features)
            writeUnsignedIntLittleEndian(
                MAXIMUM_MESSAGE_LENGTH_OFFSET,
                maximumMessageLength,
            )
        }

    private fun ByteArray.writeUnsignedIntLittleEndian(
        offset: Int,
        value: Long,
    ) {
        repeat(UNSIGNED_INT_LENGTH) { index ->
            this[offset + index] =
                (value ushr (index * Byte.SIZE_BITS)).toByte()
        }
    }

    private fun assertDescriptorError(
        expected: CcidDescriptorErrorKind,
        action: () -> Unit,
    ) {
        val exception =
            assertThrows(CcidDescriptorException::class.java) {
                action()
            }
        assertEquals(expected, exception.kind)
    }

    private companion object {
        const val LENGTH_OFFSET = 0
        const val TYPE_OFFSET = 1

        const val USB_INTERFACE_DESCRIPTOR_TYPE = 0x04
        const val INVALID_ZERO_DESCRIPTOR_LENGTH: Byte = 0
        const val USB_INTERFACE_DESCRIPTOR_LENGTH = 9
        const val SHORT_INTERFACE_DESCRIPTOR_LENGTH = 2
        const val INTERFACE_NUMBER_OFFSET = 2
        const val ALTERNATE_SETTING_OFFSET = 3
        const val INTERFACE_CLASS_OFFSET = 5
        const val CCID_INTERFACE_CLASS = 0x0B

        const val CCID_FUNCTIONAL_DESCRIPTOR_TYPE = 0x21
        const val CCID_FUNCTIONAL_DESCRIPTOR_LENGTH = 54
        const val SHORT_FUNCTIONAL_DESCRIPTOR_LENGTH =
            CCID_FUNCTIONAL_DESCRIPTOR_LENGTH - 1
        const val FEATURES_OFFSET = 40
        const val MAXIMUM_MESSAGE_LENGTH_OFFSET = 44
        const val UNSIGNED_INT_LENGTH = 4

        const val AUTOMATIC_PARAMETER_CONFIGURATION = 0x00000002L
        const val AUTOMATIC_PARAMETER_NEGOTIATION = 0x00000040L
        const val AUTOMATIC_PPS = 0x00000080L
        const val TPDU_EXCHANGE = 0x00010000L
        const val AUTOMATIC_CLOCK_CHANGE = 0x00000010L
        const val AUTOMATIC_BAUD_CHANGE = 0x00000020L
        const val TPDU_WITHOUT_AUTOMATIC_PPS_FEATURES =
            TPDU_EXCHANGE or AUTOMATIC_CLOCK_CHANGE or AUTOMATIC_BAUD_CHANGE
        const val HEX_RADIX = 16
        const val SHORT_APDU_EXCHANGE = 0x00020000L
        const val SHORT_AND_EXTENDED_APDU_EXCHANGE = 0x00040000L
        const val CHARACTER_EXCHANGE = 0L
        const val VALID_SHORT_APDU_FEATURES =
            AUTOMATIC_PARAMETER_CONFIGURATION or
                AUTOMATIC_PARAMETER_NEGOTIATION or
                SHORT_APDU_EXCHANGE

        const val TARGET_INTERFACE = 3
        const val OTHER_INTERFACE = 7
        const val TARGET_ALTERNATE_SETTING = 0
        const val MAXIMUM_T0_TPDU_LENGTH = 260
        const val MINIMUM_T0_TPDU_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_T0_TPDU_LENGTH
        const val MAXIMUM_SHORT_APDU_LENGTH = 261
        const val MINIMUM_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_SHORT_APDU_LENGTH
        const val MAXIMUM_MESSAGE_LENGTH = MINIMUM_MESSAGE_LENGTH
        const val EXTENDED_TRANSFER_BLOCK_LENGTH = 1_024
        const val MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH = 65_544
        const val MAXIMUM_CCID_MESSAGE_LENGTH =
            CcidWire.HEADER_SIZE + MAXIMUM_CCID_COMMAND_PAYLOAD_LENGTH
    }
}
