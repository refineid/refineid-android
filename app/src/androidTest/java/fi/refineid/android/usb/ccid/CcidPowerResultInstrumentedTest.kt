package fi.refineid.android.usb.ccid

import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.AtrValidation
import fi.refineid.android.diagnostics.AppTrace
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A power-on data block the activator rejects (here: card reported
 * INACTIVE instead of ACTIVE, as seen on an empty PICC slot) must end
 * in CARD_ERROR *and* leave a power-result trace line naming the card
 * state — otherwise the next reader quirk needs another round trip.
 */
@RunWith(AndroidJUnit4::class)
class CcidPowerResultInstrumentedTest {
    @Test
    fun rejectedPowerOnReportsCardState() {
        AppTrace.clearTraceLog()
        try {
            val bulkIo =
                ScriptedBulkIo(
                    slotStatusCard = CcidWire.CARD_STATUS_ACTIVE,
                    powerOnCard = CcidWire.CARD_STATUS_INACTIVE,
                )
            val activator =
                CcidCardActivator(
                    validateAtr = { AtrValidation.INVALID },
                    sequenceCounter = CcidSequenceCounter(),
                    hostPpsRequired = false,
                )
            val exchange =
                CcidCommandExchange(
                    bulkIo = bulkIo,
                    maximumMessageLength = SYNTHETIC_MAX_MESSAGE_LENGTH,
                )

            val result =
                activator.activate(
                    exchange = exchange,
                    exchangeLevel = CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
                )

            assertEquals(CcidActivationResult.CARD_ERROR, result)
            val powerLines = AppTrace.getTraceLog().filter { it.contains("ccid:power-result") }
            assertEquals(
                "expected one power-result line, got ${AppTrace.getTraceLog()}",
                1,
                powerLines.size,
            )
            assertTrue(
                "power-result lacks card state: ${powerLines[0]}",
                powerLines[0].contains("card=INACTIVE"),
            )
        } finally {
            AppTrace.clearTraceLog()
        }
    }

    /**
     * Answers GetSlotStatus then PowerOn with canned 10-byte headers.
     * Only the card-status nibble varies; everything else is success.
     */
    private class ScriptedBulkIo(
        private val slotStatusCard: Int,
        private val powerOnCard: Int,
    ) : CcidBulkIo {
        private var reads = 0

        override fun write(frame: ByteArray): Int = frame.size

        override fun read(frame: ByteArray): Int {
            val response =
                if (reads == 0) {
                    header(
                        messageType = CcidWire.RDR_TO_PC_SLOT_STATUS,
                        cardStatus = slotStatusCard,
                        sequence = 0,
                    )
                } else {
                    header(
                        messageType = CcidWire.RDR_TO_PC_DATA_BLOCK,
                        cardStatus = powerOnCard,
                        sequence = 1,
                    )
                }
            reads += 1
            response.copyInto(frame)
            return response.size
        }

        private fun header(
            messageType: Int,
            cardStatus: Int,
            sequence: Int,
        ): ByteArray {
            val frame = ByteArray(CcidWire.HEADER_SIZE)
            frame[CcidWire.MESSAGE_TYPE_OFFSET] = messageType.toByte()
            frame[CcidWire.SLOT_OFFSET] = 0
            frame[CcidWire.SEQUENCE_OFFSET] = sequence.toByte()
            frame[CcidWire.STATUS_OFFSET] = cardStatus.toByte()
            return frame
        }
    }

    private companion object {
        const val SYNTHETIC_MAX_MESSAGE_LENGTH = 271
    }
}
