package fi.refineid.android.usb.ccid

import fi.refineid.android.core.AtrValidation
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class CcidCardActivatorTest {
    @Test
    fun acceptsT0AtrForTpduReader() {
        val io = poweredCardIo()
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )

        val result = activate(io, AtrValidation.VALID_T0_DIRECT, CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(GET_PARAMETERS_COMMAND_INDEX + 1, io.writtenFrames.size)
        assertEquals(
            CcidWire.PC_TO_RDR_GET_SLOT_STATUS,
            io.writtenFrames[SLOT_STATUS_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertEquals(
            CcidWire.PC_TO_RDR_ICC_POWER_ON,
            io.writtenFrames[POWER_ON_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertEquals(
            CcidWire.PC_TO_RDR_GET_PARAMETERS,
            io.writtenFrames[GET_PARAMETERS_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        io.close()
    }

    @Test
    fun tpduReaderWithoutParametersGetsT0Configuration() {
        val io = poweredCardIo()
        io.appendResponse(
            commandFailureFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                error = NO_PARAMETERS_CONFIGURED_ERROR,
            ),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + SET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )

        val result = activate(io, AtrValidation.VALID_T0_DIRECT, CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(SET_PARAMETERS_COMMAND_INDEX + 1, io.writtenFrames.size)
        assertEquals(
            CcidWire.PC_TO_RDR_GET_PARAMETERS,
            io.writtenFrames[GET_PARAMETERS_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertEquals(
            CcidWire.PC_TO_RDR_SET_PARAMETERS,
            io.writtenFrames[SET_PARAMETERS_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertEquals(
            T0_PROTOCOL_NUMBER,
            io.writtenFrames[SET_PARAMETERS_COMMAND_INDEX].unsignedByte(CcidWire.STATUS_OFFSET),
        )
        io.close()
    }

    @Test
    fun rejectsNonT0AtrAtTpduBoundary() {
        val io = poweredCardIo()

        val result =
            activate(
                io = io,
                validation = AtrValidation.VALID_NON_T0_DIRECT,
                exchangeLevel = CcidExchangeLevel.TPDU,
            )

        assertEquals(CcidActivationResult.CARD_ERROR, result)
        io.close()
    }

    @Test
    fun acceptsNonT0AtrWhenReaderOwnsApduProtocol() {
        val io = poweredCardIo()

        val result =
            activate(
                io = io,
                validation = AtrValidation.VALID_NON_T0_INVERSE,
                exchangeLevel = CcidExchangeLevel.SHORT_APDU,
            )

        assertEquals(CcidActivationResult.READY, result)
        io.close()
    }

    @Test
    fun mapsNativeAtrBridgeFailureToTransportError() {
        val io = poweredCardIo()

        val result =
            activate(
                io = io,
                validation = AtrValidation.BRIDGE_ERROR,
                exchangeLevel = CcidExchangeLevel.SHORT_APDU,
            )

        assertEquals(CcidActivationResult.TRANSPORT_ERROR, result)
        io.close()
    }

    @Test
    fun inactivePowerBlockIsCardErrorWithoutValidation() {
        val io =
            ScriptedBulkIo(
                listOf(
                    slotStatusFrame(
                        sequence = TEST_SEQUENCE,
                        cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                    ),
                    responseFrame(
                        messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                        sequence = TEST_SEQUENCE + 1,
                        cardStatus = CcidWire.CARD_STATUS_INACTIVE,
                        responseParameter = CcidWire.COMPLETE_CHAIN,
                    ),
                ),
            )
        var validationCalls = 0
        val activator =
            CcidCardActivator(
                validateAtr = {
                    validationCalls += 1
                    AtrValidation.VALID_T0_DIRECT
                },
                sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
            )

        val result = activator.activate(exchange(io), CcidExchangeLevel.SHORT_AND_EXTENDED_APDU)

        assertEquals(CcidActivationResult.CARD_ERROR, result)
        assertEquals(0, validationCalls)
        assertEquals(2, io.writtenFrames.size)
        io.close()
    }

    @Test
    fun fastTa1SwitchesRateAndVerifiesLink() {
        val io = poweredCardIoWithAtr(SYNTHETIC_ATR_FAST_TA1)
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + SET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            dataBlockFrame(
                sequence = TEST_SEQUENCE + LINK_CHECK_COMMAND_INDEX,
                payload = SELECT_MF_RESPONSE,
            ),
        )

        val result = activateWithAtr(io, SYNTHETIC_ATR_FAST_TA1, CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(LINK_CHECK_COMMAND_INDEX + 1, io.writtenFrames.size)
        assertEquals(
            SYNTHETIC_TA1_FAST,
            io.writtenFrames[SET_PARAMETERS_COMMAND_INDEX].unsignedByte(SET_PARAMETERS_FIDI_OFFSET),
        )
        assertEquals(
            CcidWire.PC_TO_RDR_XFR_BLOCK,
            io.writtenFrames[LINK_CHECK_COMMAND_INDEX].unsignedByte(CcidWire.MESSAGE_TYPE_OFFSET),
        )
        assertSelectMf(io.writtenFrames[LINK_CHECK_COMMAND_INDEX])
        io.close()
    }

    @Test
    fun rejectedFastSwitchKeepsCurrentSpeed() {
        val io = poweredCardIoWithAtr(SYNTHETIC_ATR_FAST_TA1)
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            commandFailureFrame(
                sequence = TEST_SEQUENCE + SET_PARAMETERS_COMMAND_INDEX,
                error = PARAMETERS_REJECTED_ERROR,
            ),
        )

        val result = activateWithAtr(io, SYNTHETIC_ATR_FAST_TA1, CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(SET_PARAMETERS_COMMAND_INDEX + 1, io.writtenFrames.size)
        io.close()
    }

    @Test
    fun deadLinkAfterFastSwitchRecoversAtDefaultSpeed() {
        val io = poweredCardIoWithAtr(SYNTHETIC_ATR_FAST_TA1)
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + SET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            cardMuteFrame(sequence = TEST_SEQUENCE + LINK_CHECK_COMMAND_INDEX),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + RECOVERY_SET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )
        io.appendResponse(
            dataBlockFrame(
                sequence = TEST_SEQUENCE + RECOVERY_POWER_ON_COMMAND_INDEX,
                payload = SYNTHETIC_ATR_FAST_TA1,
            ),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + RECOVERY_GET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )

        val result =
            activateWithAtr(
                io,
                SYNTHETIC_ATR_FAST_TA1,
                CcidExchangeLevel.TPDU,
                expectedValidations = RECOVERY_VALIDATION_COUNT,
            )

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(RECOVERY_GET_PARAMETERS_COMMAND_INDEX + 1, io.writtenFrames.size)
        assertEquals(
            SYNTHETIC_TA1_FAST,
            io.writtenFrames[SET_PARAMETERS_COMMAND_INDEX].unsignedByte(SET_PARAMETERS_FIDI_OFFSET),
        )
        assertEquals(
            DEFAULT_FIDI,
            io.writtenFrames[RECOVERY_SET_PARAMETERS_COMMAND_INDEX]
                .unsignedByte(SET_PARAMETERS_FIDI_OFFSET),
        )
        io.close()
    }

    @Test
    fun defaultTa1KeepsLegacyPathWithoutLinkCheck() {
        val io = poweredCardIoWithAtr(SYNTHETIC_ATR_DEFAULT_TA1)
        io.appendResponse(
            commandFailureFrame(
                sequence = TEST_SEQUENCE + GET_PARAMETERS_COMMAND_INDEX,
                error = NO_PARAMETERS_CONFIGURED_ERROR,
            ),
        )
        io.appendResponse(
            parametersFrame(
                sequence = TEST_SEQUENCE + SET_PARAMETERS_COMMAND_INDEX,
                protocolNum = T0_PROTOCOL_NUMBER,
            ),
        )

        val result = activateWithAtr(io, SYNTHETIC_ATR_DEFAULT_TA1, CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.READY, result)
        assertEquals(SET_PARAMETERS_COMMAND_INDEX + 1, io.writtenFrames.size)
        assertEquals(
            DEFAULT_FIDI,
            io.writtenFrames[SET_PARAMETERS_COMMAND_INDEX].unsignedByte(SET_PARAMETERS_FIDI_OFFSET),
        )
        io.close()
    }

    @Test
    fun emptySlotDoesNotPowerOrValidate() {
        val io =
            ScriptedBulkIo(
                listOf(
                    slotStatusFrame(
                        sequence = TEST_SEQUENCE,
                        cardStatus = CcidWire.CARD_STATUS_NOT_PRESENT,
                    ),
                ),
            )
        var validationCalls = 0
        val activator =
            CcidCardActivator(
                validateAtr = {
                    validationCalls += 1
                    AtrValidation.VALID_T0_DIRECT
                },
                sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
            )

        val result = activator.activate(exchange(io), CcidExchangeLevel.TPDU)

        assertEquals(CcidActivationResult.NO_CARD, result)
        assertEquals(0, validationCalls)
        assertEquals(1, io.writtenFrames.size)
        io.close()
    }

    private fun activate(
        io: ScriptedBulkIo,
        validation: AtrValidation,
        exchangeLevel: CcidExchangeLevel,
    ): CcidActivationResult {
        var validationCalls = 0
        val activator =
            CcidCardActivator(
                validateAtr = { atr ->
                    validationCalls += 1
                    assertArrayEquals(SYNTHETIC_ATR, atr)
                    validation
                },
                sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
            )

        return activator.activate(exchange(io), exchangeLevel).also {
            assertEquals(1, validationCalls)
        }
    }

    private fun exchange(io: CcidBulkIo): CcidCommandExchange =
        CcidCommandExchange(
            bulkIo = io,
            maximumMessageLength = MAXIMUM_MESSAGE_LENGTH,
        )

    private fun poweredCardIo(): ScriptedBulkIo = poweredCardIoWithAtr(SYNTHETIC_ATR)

    private fun poweredCardIoWithAtr(atr: ByteArray): ScriptedBulkIo =
        ScriptedBulkIo(
            listOf(
                slotStatusFrame(
                    sequence = TEST_SEQUENCE,
                    cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                ),
                dataBlockFrame(
                    sequence = TEST_SEQUENCE + POWER_ON_COMMAND_INDEX,
                    payload = atr,
                ),
            ),
        )

    private fun activateWithAtr(
        io: ScriptedBulkIo,
        atr: ByteArray,
        exchangeLevel: CcidExchangeLevel,
        expectedValidations: Int = SINGLE_VALIDATION_COUNT,
    ): CcidActivationResult {
        var validationCalls = 0
        val activator =
            CcidCardActivator(
                validateAtr = { actual ->
                    validationCalls += 1
                    assertArrayEquals(atr, actual)
                    AtrValidation.VALID_T0_DIRECT
                },
                sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
            )

        return activator.activate(exchange(io), exchangeLevel).also {
            assertEquals(expectedValidations, validationCalls)
        }
    }

    private fun assertSelectMf(frame: ByteArray) {
        val expected = intArrayOf(SELECT_MF_CLA, SELECT_MF_INS, SELECT_MF_P1, SELECT_MF_P2)
        expected.forEachIndexed { index, byte ->
            assertEquals(byte, frame.unsignedByte(CcidWire.HEADER_SIZE + index))
        }
    }

    private fun cardMuteFrame(sequence: Int): ByteArray {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                sequence = sequence,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                responseParameter = CcidWire.COMPLETE_CHAIN,
            )
        frame[CcidWire.STATUS_OFFSET] =
            (
                (CcidWire.COMMAND_STATUS_FAILED shl CcidWire.COMMAND_STATUS_SHIFT) or
                    CcidWire.CARD_STATUS_ACTIVE
            ).toByte()
        frame[CcidWire.ERROR_OFFSET] = CARD_MUTE_ERROR.toByte()
        return frame
    }

    private fun slotStatusFrame(
        sequence: Int,
        cardStatus: Int,
    ): ByteArray =
        responseFrame(
            messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
            sequence = sequence,
            cardStatus = cardStatus,
            responseParameter = CcidWire.CLOCK_RUNNING,
        )

    private fun dataBlockFrame(
        sequence: Int,
        payload: ByteArray,
    ): ByteArray =
        responseFrame(
            messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
            sequence = sequence,
            cardStatus = CcidWire.CARD_STATUS_ACTIVE,
            responseParameter = CcidWire.COMPLETE_CHAIN,
            payload = payload,
        )

    private fun parametersFrame(
        sequence: Int,
        protocolNum: Int,
    ): ByteArray =
        responseFrame(
            messageType = CcidWire.RDR_TO_PC_PARAMETERS,
            sequence = sequence,
            cardStatus = CcidWire.CARD_STATUS_ACTIVE,
            responseParameter = protocolNum,
            payload = ByteArray(T0_PARAMETER_RESPONSE_LENGTH),
        )

    private fun commandFailureFrame(
        sequence: Int,
        error: Int,
    ): ByteArray {
        val frame =
            responseFrame(
                messageType = CcidWire.RDR_TO_PC_PARAMETERS,
                sequence = sequence,
                cardStatus = CcidWire.CARD_STATUS_ACTIVE,
                responseParameter = 0,
            )
        frame[CcidWire.STATUS_OFFSET] =
            (
                (CcidWire.COMMAND_STATUS_FAILED shl CcidWire.COMMAND_STATUS_SHIFT) or
                    CcidWire.CARD_STATUS_ACTIVE
            ).toByte()
        frame[CcidWire.ERROR_OFFSET] = error.toByte()
        return frame
    }

    private fun responseFrame(
        messageType: Int,
        sequence: Int,
        cardStatus: Int,
        responseParameter: Int,
        payload: ByteArray = byteArrayOf(),
    ): ByteArray =
        ByteArray(CcidWire.HEADER_SIZE + payload.size).apply {
            this[CcidWire.MESSAGE_TYPE_OFFSET] = messageType.toByte()
            writeLength(payload.size)
            this[CcidWire.SLOT_OFFSET] = FIRST_SLOT.toByte()
            this[CcidWire.SEQUENCE_OFFSET] = sequence.toByte()
            this[CcidWire.STATUS_OFFSET] = cardStatus.toByte()
            this[CcidWire.RESPONSE_PARAMETER_OFFSET] = responseParameter.toByte()
            payload.copyInto(this, destinationOffset = CcidWire.HEADER_SIZE)
        }

    private fun ByteArray.writeLength(length: Int) {
        repeat(LENGTH_FIELD_SIZE) { index ->
            this[CcidWire.LENGTH_OFFSET + index] =
                (length ushr (index * Byte.SIZE_BITS)).toByte()
        }
    }

    private fun ByteArray.unsignedByte(offset: Int): Int = this[offset].toInt() and CcidWire.BYTE_MAX

    private class ScriptedBulkIo(
        responses: List<ByteArray>,
    ) : CcidBulkIo,
        AutoCloseable {
        private val responses = responses.map(ByteArray::copyOf).toMutableList()
        val writtenFrames = mutableListOf<ByteArray>()

        fun appendResponse(frame: ByteArray) {
            responses += frame.copyOf()
        }

        override fun write(frame: ByteArray): Int {
            writtenFrames += frame.copyOf()
            return frame.size
        }

        override fun read(frame: ByteArray): Int {
            if (responses.isEmpty()) {
                return -1
            }
            val response = responses.removeAt(0)
            return try {
                response.copyInto(frame)
                response.size
            } finally {
                response.fill(0)
            }
        }

        override fun close() {
            responses.forEach { response -> response.fill(0) }
            writtenFrames.forEach { frame -> frame.fill(0) }
        }
    }

    private companion object {
        const val FIRST_SLOT = 0
        const val SLOT_STATUS_COMMAND_INDEX = 0
        const val POWER_ON_COMMAND_INDEX = 1
        const val GET_PARAMETERS_COMMAND_INDEX = 2
        const val SET_PARAMETERS_COMMAND_INDEX = 3
        const val LINK_CHECK_COMMAND_INDEX = 4
        const val RECOVERY_SET_PARAMETERS_COMMAND_INDEX = 5
        const val RECOVERY_POWER_ON_COMMAND_INDEX = 6
        const val RECOVERY_GET_PARAMETERS_COMMAND_INDEX = 7
        const val SINGLE_VALIDATION_COUNT = 1
        const val RECOVERY_VALIDATION_COUNT = 2
        const val SET_PARAMETERS_FIDI_OFFSET = CcidWire.HEADER_SIZE
        const val SYNTHETIC_T0_TA1_PRESENT: Byte = 0x10
        const val SYNTHETIC_TA1_FAST = 0x96
        const val SYNTHETIC_TA1_DEFAULT = 0x11
        const val DEFAULT_FIDI = 0x11
        const val SELECT_MF_CLA = 0x00
        const val SELECT_MF_INS = 0xA4
        const val SELECT_MF_P1 = 0x00
        const val SELECT_MF_P2 = 0x0C
        const val SW1_SUCCESS = 0x90
        const val SW2_SUCCESS = 0x00
        const val PARAMETERS_REJECTED_ERROR = 0xF0
        const val CARD_MUTE_ERROR = 0xFE
        val SYNTHETIC_ATR_FAST_TA1 =
            byteArrayOf(
                SYNTHETIC_TS_DIRECT,
                SYNTHETIC_T0_TA1_PRESENT,
                SYNTHETIC_TA1_FAST.toByte(),
            )
        val SYNTHETIC_ATR_DEFAULT_TA1 =
            byteArrayOf(
                SYNTHETIC_TS_DIRECT,
                SYNTHETIC_T0_TA1_PRESENT,
                SYNTHETIC_TA1_DEFAULT.toByte(),
            )
        val SELECT_MF_RESPONSE = byteArrayOf(SW1_SUCCESS.toByte(), SW2_SUCCESS.toByte())
        const val TEST_SEQUENCE = 41
        const val LENGTH_FIELD_SIZE = 4
        const val MAXIMUM_MESSAGE_LENGTH = 512
        const val T0_PROTOCOL_NUMBER = 0
        const val T0_PARAMETER_RESPONSE_LENGTH = 5
        const val NO_PARAMETERS_CONFIGURED_ERROR = 0xFE
        const val SYNTHETIC_TS_DIRECT: Byte = 0x3B
        const val SYNTHETIC_T0_NO_INTERFACE_BYTES: Byte = 0x00
        val SYNTHETIC_ATR =
            byteArrayOf(
                SYNTHETIC_TS_DIRECT,
                SYNTHETIC_T0_NO_INTERFACE_BYTES,
            )
    }
}
