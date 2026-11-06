package fi.refineid.android.nfc

import fi.refineid.android.core.NativeBlockExchange
import fi.refineid.android.core.NativeExchangeReplyTag
import fi.refineid.android.diagnostics.AppTrace

/**
 * Adapts one connected ISO-DEP card to the synchronous native callback
 * ABI. ISO-DEP moves complete APDUs, so both paths submit one block per
 * call and never retry; a lost tag is a typed absence, not an error. The
 * credential path traces neither the command header nor its length.
 */
internal class NfcNativeBlockExchange(
    private val channel: NfcCardChannel,
) : NativeBlockExchange {
    override fun exchangePublic(block: ByteArray): ByteArray = exchange(block, BlockKind.PUBLIC)

    override fun exchangeCredential(block: ByteArray): ByteArray = exchange(block, BlockKind.CREDENTIAL)

    private enum class BlockKind {
        PUBLIC,
        CREDENTIAL,
    }

    private fun exchange(
        block: ByteArray,
        kind: BlockKind,
    ): ByteArray {
        if (block.isEmpty() || block.size > channel.maximumTransceiveLength) {
            return byteArrayOf(NativeExchangeReplyTag.BACKEND_FAILURE.wireValue)
        }
        val startedAtNanos = System.nanoTime()
        val result = channel.transceive(block)
        val elapsedMicros = (System.nanoTime() - startedAtNanos) / NANOSECONDS_PER_MICROSECOND
        return when (result) {
            is NfcTransceiveResult.Response -> {
                val sw =
                    if (result.bytes.size >= STATUS_WORD_LENGTH) {
                        val sw1 = result.bytes[result.bytes.size - STATUS_WORD_LENGTH].toInt() and 0xFF
                        val sw2 = result.bytes[result.bytes.size - 1].toInt() and 0xFF
                        (sw1 shl 8) or sw2
                    } else {
                        0
                    }
                when (kind) {
                    BlockKind.PUBLIC -> tracePublic(block, result.bytes.size, elapsedMicros, sw)
                    BlockKind.CREDENTIAL -> AppTrace.nfcCredentialTransceive(result.bytes.size, elapsedMicros, sw)
                }
                encodeResponse(result.bytes)
            }

            NfcTransceiveResult.CardLost -> {
                byteArrayOf(NativeExchangeReplyTag.NO_CARD.wireValue)
            }

            NfcTransceiveResult.TransceiveFailed -> {
                byteArrayOf(NativeExchangeReplyTag.TIMEOUT_UNKNOWN_STATE.wireValue)
            }
        }
    }

    // The header is public routing; bodies stay out of the trace.
    private fun tracePublic(
        block: ByteArray,
        responseLength: Int,
        elapsedMicros: Long,
        sw: Int,
    ) {
        val hasHeader = block.size >= APDU_HEADER_LENGTH
        AppTrace.nfcTransceive(
            block.size,
            responseLength,
            elapsedMicros,
            sw,
            cla = if (hasHeader) block[CLASS_BYTE_OFFSET].toInt() and 0xFF else -1,
            ins = if (hasHeader) block[INSTRUCTION_OFFSET].toInt() and 0xFF else -1,
            p1 = if (hasHeader) block[PARAMETER_ONE_OFFSET].toInt() and 0xFF else -1,
            p2 = if (hasHeader) block[PARAMETER_TWO_OFFSET].toInt() and 0xFF else -1,
        )
    }

    private fun encodeResponse(payload: ByteArray): ByteArray =
        try {
            if (
                payload.size < STATUS_WORD_LENGTH ||
                payload.size > MAXIMUM_RESPONSE_LENGTH
            ) {
                byteArrayOf(NativeExchangeReplyTag.PROTOCOL_DESYNC.wireValue)
            } else {
                ByteArray(TAG_LENGTH + payload.size).also { reply ->
                    reply[TAG_OFFSET] = NativeExchangeReplyTag.RESPONSE.wireValue
                    payload.copyInto(
                        destination = reply,
                        destinationOffset = TAG_LENGTH,
                    )
                }
            }
        } finally {
            payload.fill(0)
        }

    private companion object {
        const val NANOSECONDS_PER_MICROSECOND = 1_000

        const val TAG_OFFSET = 0
        const val TAG_LENGTH = 1

        /** An ISO 7816-4 command carries at least CLA, INS, P1, P2. */
        const val APDU_HEADER_LENGTH = 4
        const val CLASS_BYTE_OFFSET = 0
        const val INSTRUCTION_OFFSET = 1
        const val PARAMETER_ONE_OFFSET = 2
        const val PARAMETER_TWO_OFFSET = 3

        /** An ISO 7816-4 response carries at least SW1 and SW2. */
        const val STATUS_WORD_LENGTH = 2

        /** Extended-length response body bound plus the status word. */
        const val MAXIMUM_RESPONSE_BODY_LENGTH = 1 shl 16
        const val MAXIMUM_RESPONSE_LENGTH =
            MAXIMUM_RESPONSE_BODY_LENGTH + STATUS_WORD_LENGTH
    }
}
