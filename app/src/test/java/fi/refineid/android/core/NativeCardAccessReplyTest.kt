package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeCardAccessReplyTest {
    @Test
    fun decodesACitizenCard() {
        val result =
            NativeCardAccessReply.decode(
                byteArrayOf(
                    CARD_ACCESS_SUCCEEDED,
                    CARD_KIND_PERSONAL,
                    SYNTHETIC_ENTRY_COUNT,
                ),
            )

        assertEquals(
            NativeCardAccessResult.Success(
                NativeCardAccessSummary(
                    cardKind = NfcCardKind.PERSONAL,
                    paceEntryCount = SYNTHETIC_ENTRY_COUNT.toInt(),
                ),
            ),
            result,
        )
    }

    @Test
    fun decodesACardOfNoKnownKind() {
        val result =
            NativeCardAccessReply.decode(
                byteArrayOf(
                    CARD_ACCESS_SUCCEEDED,
                    CARD_KIND_UNKNOWN,
                    SINGLE_ENTRY_COUNT,
                ),
            )

        assertEquals(
            NativeCardAccessResult.Success(
                NativeCardAccessSummary(
                    cardKind = null,
                    paceEntryCount = SINGLE_ENTRY_COUNT.toInt(),
                ),
            ),
            result,
        )
    }

    @Test
    fun decodesAnOrganizationCard() {
        val result =
            NativeCardAccessReply.decode(
                byteArrayOf(
                    CARD_ACCESS_SUCCEEDED,
                    CARD_KIND_ORGANIZATION,
                    SYNTHETIC_ENTRY_COUNT,
                ),
            )

        assertEquals(
            NativeCardAccessResult.Success(
                NativeCardAccessSummary(
                    cardKind = NfcCardKind.ORGANIZATION,
                    paceEntryCount = SYNTHETIC_ENTRY_COUNT.toInt(),
                ),
            ),
            result,
        )
    }

    @Test
    fun decodesEveryTypedFailure() {
        val expected =
            mapOf(
                CARD_ACCESS_CARD_UNAVAILABLE to NativeCardAccessFailure.CARD_UNAVAILABLE,
                CARD_ACCESS_REJECTED to NativeCardAccessFailure.REJECTED,
                CARD_ACCESS_TRANSPORT_ERROR to NativeCardAccessFailure.TRANSPORT_ERROR,
                CARD_ACCESS_INVALID to NativeCardAccessFailure.INVALID_CARD_ACCESS,
                CARD_ACCESS_BRIDGE_ERROR to NativeCardAccessFailure.BRIDGE_ERROR,
            )
        expected.forEach { (tag, kind) ->
            assertEquals(
                NativeCardAccessResult.Failure(kind),
                NativeCardAccessReply.decode(byteArrayOf(tag)),
            )
        }
    }

    @Test
    fun rejectsMalformedReplies() {
        val malformed =
            listOf(
                byteArrayOf(),
                byteArrayOf(UNKNOWN_TAG),
                byteArrayOf(CARD_ACCESS_SUCCEEDED),
                byteArrayOf(CARD_ACCESS_SUCCEEDED, CARD_KIND_PERSONAL),
                byteArrayOf(
                    CARD_ACCESS_SUCCEEDED,
                    CARD_KIND_PERSONAL,
                    SYNTHETIC_ENTRY_COUNT,
                    TRAILING_GARBAGE,
                ),
                byteArrayOf(
                    CARD_ACCESS_SUCCEEDED,
                    UNKNOWN_KIND,
                    SYNTHETIC_ENTRY_COUNT,
                ),
                byteArrayOf(CARD_ACCESS_SUCCEEDED, CARD_KIND_PERSONAL, ZERO_ENTRY_COUNT),
                byteArrayOf(CARD_ACCESS_TRANSPORT_ERROR, TRAILING_GARBAGE),
            )
        malformed.forEach { reply ->
            assertEquals(
                NativeCardAccessResult.Failure(NativeCardAccessFailure.BRIDGE_ERROR),
                NativeCardAccessReply.decode(reply),
            )
        }
    }

    @Test
    fun clearsTheReplyBufferAfterDecoding() {
        val reply =
            byteArrayOf(
                CARD_ACCESS_SUCCEEDED,
                CARD_KIND_PERSONAL,
                SYNTHETIC_ENTRY_COUNT,
            )

        NativeCardAccessReply.decode(reply)

        assertTrue(reply.all { it == ZERO_BYTE })
    }

    private companion object {
        const val CARD_ACCESS_BRIDGE_ERROR: Byte = 0
        const val CARD_ACCESS_SUCCEEDED: Byte = 1
        const val CARD_ACCESS_CARD_UNAVAILABLE: Byte = 2
        const val CARD_ACCESS_REJECTED: Byte = 3
        const val CARD_ACCESS_TRANSPORT_ERROR: Byte = 4
        const val CARD_ACCESS_INVALID: Byte = 5
        const val CARD_KIND_UNKNOWN: Byte = 0
        const val CARD_KIND_PERSONAL: Byte = 1
        const val CARD_KIND_ORGANIZATION: Byte = 2
        const val UNKNOWN_KIND: Byte = 3
        const val UNKNOWN_TAG: Byte = 6
        const val SYNTHETIC_ENTRY_COUNT: Byte = 2
        const val SINGLE_ENTRY_COUNT: Byte = 1
        const val ZERO_ENTRY_COUNT: Byte = 0
        const val TRAILING_GARBAGE: Byte = 0x7F
        const val ZERO_BYTE: Byte = 0
    }
}
