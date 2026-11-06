// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import fi.refineid.android.nfc.NfcCardChannel
import fi.refineid.android.nfc.NfcNativeBlockExchange
import fi.refineid.android.nfc.NfcTransceiveResult
import fi.refineid.android.usb.ccid.CcidBlockResult
import fi.refineid.android.usb.ccid.CcidBlockTransport
import fi.refineid.android.usb.ccid.CcidBulkIo
import fi.refineid.android.usb.ccid.CcidBulkOutOutcome
import fi.refineid.android.usb.ccid.CcidCommandExchange
import fi.refineid.android.usb.ccid.CcidSequenceCounter
import fi.refineid.android.usb.ccid.CcidWire
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RULE #2: no trace line may let a reader derive a credential length. Two
 * credential blocks of different lengths must leave the same trace once
 * timestamps and durations are set aside.
 */
class CredentialLengthTraceTest {
    @After
    fun tearDown() {
        AppTrace.clearTraceLog()
    }

    @Test
    fun ccidCredentialTraceIsIndependentOfCredentialLength() {
        val shortTrace = ccidCredentialTrace(SHORT_CREDENTIAL_BLOCK.encodeToByteArray())
        val longTrace = ccidCredentialTrace(LONG_CREDENTIAL_BLOCK.encodeToByteArray())

        assertTrue(
            "expected a CCID exchange line, got $shortTrace",
            shortTrace.any { line -> line.startsWith(CCID_EXCHANGE_EVENT) },
        )
        assertEquals(shortTrace, longTrace)
    }

    @Test
    fun bulkOutTraceCarriesTheOutcomeAlone() {
        val shortFrameLength = SHORT_CREDENTIAL_BLOCK.length + CcidWire.HEADER_SIZE
        val longFrameLength = LONG_CREDENTIAL_BLOCK.length + CcidWire.HEADER_SIZE

        AppTrace.clearTraceLog()
        AppTrace.ccidBulkOut(CcidBulkOutOutcome.of(requested = shortFrameLength, transferred = shortFrameLength))
        AppTrace.ccidBulkOut(CcidBulkOutOutcome.of(requested = longFrameLength, transferred = longFrameLength))

        assertEquals(
            listOf(BULK_OUT_COMPLETE_LINE, BULK_OUT_COMPLETE_LINE),
            AppTrace.getTraceLog().map(::withoutTimestamp),
        )
    }

    @Test
    fun bulkOutOutcomeDistinguishesCompleteShortAndFailedTransfers() {
        val frameLength = LONG_CREDENTIAL_BLOCK.length + CcidWire.HEADER_SIZE

        assertEquals(
            CcidBulkOutOutcome.COMPLETE,
            CcidBulkOutOutcome.of(requested = frameLength, transferred = frameLength),
        )
        assertEquals(
            CcidBulkOutOutcome.SHORT,
            CcidBulkOutOutcome.of(requested = frameLength, transferred = frameLength - 1),
        )
        assertEquals(
            CcidBulkOutOutcome.FAILED,
            CcidBulkOutOutcome.of(requested = frameLength, transferred = FAILED_TRANSFER),
        )
    }

    @Test
    fun nfcCredentialTraceIsIndependentOfCredentialLength() {
        val shortTrace = nfcCredentialTrace(SHORT_CREDENTIAL_BLOCK.encodeToByteArray())
        val longTrace = nfcCredentialTrace(LONG_CREDENTIAL_BLOCK.encodeToByteArray())

        assertTrue(
            "expected an NFC credential line, got $shortTrace",
            shortTrace.any { line -> line.startsWith(NFC_CREDENTIAL_EVENT) },
        )
        assertEquals(shortTrace, longTrace)
    }

    private fun ccidCredentialTrace(block: ByteArray): List<String> {
        val transport =
            CcidBlockTransport(
                exchange =
                    CcidCommandExchange(
                        bulkIo = SuccessfulBulkIo(),
                        maximumMessageLength = MAXIMUM_CCID_MESSAGE_LENGTH,
                    ),
                maximumBlockLength = MAXIMUM_TRANSFER_BLOCK_LENGTH,
                sequenceCounter = CcidSequenceCounter(TEST_SEQUENCE),
            )
        AppTrace.clearTraceLog()
        val result = transport.transmitCredential(block)
        assertTrue("credential exchange failed: $result", result is CcidBlockResult.Response)
        (result as CcidBlockResult.Response).close()
        return AppTrace.getTraceLog().map(::withoutTimestamp).map(::withoutDuration)
    }

    private fun nfcCredentialTrace(block: ByteArray): List<String> {
        val exchange = NfcNativeBlockExchange(SuccessfulNfcChannel())
        AppTrace.clearTraceLog()
        exchange.exchangeCredential(block)
        return AppTrace.getTraceLog().map(::withoutTimestamp).map(::withoutDuration)
    }

    private fun withoutTimestamp(line: String): String = line.split(' ', limit = TIMESTAMPED_LINE_PARTS).last()

    private fun withoutDuration(line: String): String = DURATION.replace(line, DURATION_PLACEHOLDER)

    /** Accepts every command and answers it with a bare success status word. */
    private class SuccessfulBulkIo : CcidBulkIo {
        override fun write(frame: ByteArray): Int = frame.size

        override fun read(frame: ByteArray): Int {
            val response = successFrame()
            response.copyInto(frame)
            return response.size
        }

        private fun successFrame(): ByteArray =
            ByteArray(CcidWire.HEADER_SIZE + STATUS_WORD_LENGTH).apply {
                this[CcidWire.MESSAGE_TYPE_OFFSET] = CcidWire.RDR_TO_PC_DATA_BLOCK.toByte()
                this[CcidWire.LENGTH_OFFSET] = STATUS_WORD_LENGTH.toByte()
                this[CcidWire.SLOT_OFFSET] = FIRST_SLOT.toByte()
                this[CcidWire.SEQUENCE_OFFSET] = TEST_SEQUENCE.toByte()
                this[CcidWire.STATUS_OFFSET] =
                    (
                        CcidWire.CARD_STATUS_ACTIVE or
                            (CcidWire.COMMAND_STATUS_SUCCEEDED shl CcidWire.COMMAND_STATUS_SHIFT)
                    ).toByte()
                this[CcidWire.RESPONSE_PARAMETER_OFFSET] = CcidWire.COMPLETE_CHAIN.toByte()
                successStatusWord().copyInto(this, destinationOffset = CcidWire.HEADER_SIZE)
            }
    }

    private class SuccessfulNfcChannel : NfcCardChannel {
        override val maximumTransceiveLength: Int = MAXIMUM_TRANSFER_BLOCK_LENGTH

        override fun transceive(command: ByteArray): NfcTransceiveResult =
            NfcTransceiveResult.Response(successStatusWord())
    }

    private companion object {
        /** Synthetic credential-command stand-ins: only their lengths differ. */
        const val SHORT_CREDENTIAL_BLOCK = "synthetic-short"
        const val LONG_CREDENTIAL_BLOCK = "synthetic-credential-block-that-is-longer"

        const val FIRST_SLOT = 0
        const val TEST_SEQUENCE = 29
        const val MAXIMUM_TRANSFER_BLOCK_LENGTH = 261
        const val MAXIMUM_CCID_MESSAGE_LENGTH = CcidWire.HEADER_SIZE + MAXIMUM_TRANSFER_BLOCK_LENGTH
        const val FAILED_TRANSFER = -1

        /** ISO 7816-4 normal processing status word, SW1 then SW2. */
        const val ISO_STATUS_SUCCESS = 0x9000
        const val STATUS_WORD_LENGTH = 2

        const val CCID_EXCHANGE_EVENT = "ccid:exchange "
        const val NFC_CREDENTIAL_EVENT = "nfc:transceive credential"
        const val BULK_OUT_COMPLETE_LINE = "ccid:bulk dir=out outcome=COMPLETE"

        /** A trace line is "MM-dd HH:mm:ss.SSSZ message". */
        const val TIMESTAMPED_LINE_PARTS = 3
        val DURATION = Regex("""us=\d+""")
        const val DURATION_PLACEHOLDER = "us"

        fun successStatusWord(): ByteArray =
            byteArrayOf(
                (ISO_STATUS_SUCCESS ushr Byte.SIZE_BITS).toByte(),
                ISO_STATUS_SUCCESS.toByte(),
            )
    }
}
