package fi.refineid.android.rapp

import java.io.DataInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** The fi.refineid.stream.v1 frame encoder and decoder. */
internal object StreamRelayFraming {
    const val LENGTH_PREFIX_BYTE_COUNT = 2
    const val MAXIMUM_PAYLOAD_BYTE_COUNT = 65535

    fun encode(payload: ByteArray): ByteArray? {
        if (payload.isEmpty() || payload.size > MAXIMUM_PAYLOAD_BYTE_COUNT) {
            return null
        }
        val buffer = ByteBuffer.allocate(LENGTH_PREFIX_BYTE_COUNT + payload.size)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putShort(payload.size.toShort())
        buffer.put(payload)
        return buffer.array()
    }

    /**
     * Reads one frame from [input]: a nonzero length prefix and that many
     * payload bytes.
     *
     * @throws IOException on an empty frame, a failed read or the end of the stream.
     */
    fun read(input: DataInputStream): ByteArray {
        val length = input.readUnsignedShort()
        if (length == 0) {
            throw IOException("empty stream frame")
        }
        return ByteArray(length).also(input::readFully)
    }

    fun payloadByteCount(lengthPrefix: ByteArray): Int? {
        if (lengthPrefix.size != LENGTH_PREFIX_BYTE_COUNT) return null
        val buffer = ByteBuffer.wrap(lengthPrefix)
        buffer.order(ByteOrder.BIG_ENDIAN)
        val len = buffer.short.toInt() and 0xFFFF
        return if (len >= 1) len else null
    }
}
