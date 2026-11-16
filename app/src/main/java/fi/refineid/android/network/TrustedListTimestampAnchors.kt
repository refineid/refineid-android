// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
// https://www.apache.org/licenses/LICENSE-2.0

package fi.refineid.android.network

import androidx.annotation.Keep
import fi.refineid.android.core.NativeCore
import java.nio.ByteBuffer
import java.time.Instant

internal fun interface TimestampAnchorSource {
    /** Owned certificates granted for time-stamping at the token's generation time. */
    fun copyAnchorsAt(generatedAt: Instant): List<ByteArray>
}

/** Verified EU trusted-list anchors; unavailable or expired trust produces no anchor. */
internal class TrustedListTimestampAnchors(
    transport: SigningNetworkTransport,
) : TimestampAnchorSource {
    private val fetcher = TrustedListResourceFetcher(transport)

    override fun copyAnchorsAt(generatedAt: Instant): List<ByteArray> {
        if (!NativeCore.isLoaded) {
            return emptyList()
        }
        val encoded =
            try {
                NativeTimestampTrust.timestampAnchorsNative(generatedAt.epochSecond, generatedAt.nano, fetcher)
            } catch (_: RuntimeException) {
                return emptyList()
            } catch (_: LinkageError) {
                return emptyList()
            }
        return try {
            decodeAnchors(encoded)
        } finally {
            encoded.fill(CLEARED_BYTE)
        }
    }

    private fun decodeAnchors(encoded: ByteArray): List<ByteArray> {
        if (encoded.size !in WORD_BYTES..MAXIMUM_ANCHOR_REPLY_BYTES) {
            return emptyList()
        }
        val input = ByteBuffer.wrap(encoded)
        val count = input.int
        if (count !in MINIMUM_ANCHORS..MAXIMUM_ANCHORS) {
            return emptyList()
        }
        val anchors = mutableListOf<ByteArray>()
        repeat(count) {
            if (input.remaining() < WORD_BYTES) {
                return cleared(anchors)
            }
            val length = input.int
            if (length !in MINIMUM_CERTIFICATE_BYTES..MAXIMUM_CERTIFICATE_BYTES || length > input.remaining()) {
                return cleared(anchors)
            }
            anchors += ByteArray(length).also(input::get)
        }
        return if (input.hasRemaining()) cleared(anchors) else anchors
    }

    private fun cleared(anchors: List<ByteArray>): List<ByteArray> {
        anchors.forEach { it.fill(CLEARED_BYTE) }
        return emptyList()
    }

    private companion object {
        const val WORD_BYTES = Int.SIZE_BYTES
        const val MINIMUM_ANCHORS = 1
        const val MAXIMUM_ANCHORS = 1_024
        const val MINIMUM_CERTIFICATE_BYTES = 1
        const val MAXIMUM_CERTIFICATE_BYTES = 65_536
        const val MAXIMUM_ANCHOR_REPLY_BYTES = 16_777_216
        const val CLEARED_BYTE: Byte = 0
    }
}

/** Synchronous bounded shell transport called only for signed trusted-list locations. */
@Keep
internal class TrustedListResourceFetcher(
    private val transport: SigningNetworkTransport,
) {
    fun get(address: String): ByteArray? =
        try {
            transport.get(
                address = address,
                maximumResponseBytes = MAXIMUM_LIST_BYTES,
                endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
            )
        } catch (_: Exception) {
            null
        }

    private companion object {
        const val MAXIMUM_LIST_BYTES = 16_777_216
    }
}

@Keep
internal object NativeTimestampTrust {
    @JvmStatic
    external fun timestampAnchorsNative(
        generatedAtEpochSeconds: Long,
        generatedAtNanoseconds: Int,
        fetcher: Any,
    ): ByteArray
}
