// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class StreamRendezvousHintTest {
    private val ownToken = ByteArray(TOKEN_SIZE) { OWN_TOKEN_BYTE }
    private val otherToken = ByteArray(TOKEN_SIZE) { OTHER_TOKEN_BYTE }

    /** A stand-in hint that names the token and the window, nothing more. */
    private val fakeHint: (ByteArray, Long) -> ByteArray = { token, unixSeconds ->
        byteArrayOf(token.first(), (unixSeconds / StreamRendezvousName.HINT_WINDOW_SECONDS).toByte())
    }

    @Test
    fun coreHintMatchesTheProtocolCorpus() {
        RappNativeTestLibrary.require()
        val token = ByteArray(TOKEN_SIZE) { CORPUS_TOKEN_BYTE }
        val hint =
            StreamRendezvousName.coreHint(token, CORPUS_EPOCH * StreamRendezvousName.HINT_WINDOW_SECONDS)
        assertEquals(CORPUS_HINT_HEX, hint.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun sessionRecordWithoutPairingsCarriesNoHints() {
        val attributes = StreamRendezvousName.sessionAttributes(emptyList(), NOW_SECONDS, fakeHint)
        assertEquals(StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION), attributes)
    }

    @Test
    fun sessionRecordCarriesAtMostFourHints() {
        val tokens = List(StreamRendezvousName.MAX_HINTS + 1) { index -> ByteArray(TOKEN_SIZE) { index.toByte() } }
        val hints =
            StreamRendezvousName
                .sessionAttributes(tokens, NOW_SECONDS, fakeHint)
                .getValue(StreamRendezvousName.ATTRIBUTE_HINTS)
                .split(',')
        assertEquals(StreamRendezvousName.MAX_HINTS, hints.size)
    }

    @Test
    fun hintNamesItsPairingInTheCurrentAndAdjacentWindows() {
        for (offset in -1L..1L) {
            val published =
                StreamRendezvousName.sessionAttributes(
                    listOf(ownToken),
                    NOW_SECONDS + offset * StreamRendezvousName.HINT_WINDOW_SECONDS,
                    fakeHint,
                )
            assertEquals(
                StreamRendezvousName.HintMatch.NAMED,
                StreamRendezvousName.hintMatch(resolved(published), ownToken, NOW_SECONDS, fakeHint),
            )
        }
    }

    @Test
    fun hintTwoWindowsAwayDoesNotName() {
        val published =
            StreamRendezvousName.sessionAttributes(
                listOf(ownToken),
                NOW_SECONDS + 2 * StreamRendezvousName.HINT_WINDOW_SECONDS,
                fakeHint,
            )
        assertEquals(
            StreamRendezvousName.HintMatch.OTHER,
            StreamRendezvousName.hintMatch(resolved(published), ownToken, NOW_SECONDS, fakeHint),
        )
    }

    @Test
    fun hintsOfOtherPairingsAreOtherAndAbsentHintsAreUnhinted() {
        val others = StreamRendezvousName.sessionAttributes(listOf(otherToken), NOW_SECONDS, fakeHint)
        assertEquals(
            StreamRendezvousName.HintMatch.OTHER,
            StreamRendezvousName.hintMatch(resolved(others), ownToken, NOW_SECONDS, fakeHint),
        )
        val bare = StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION)
        assertEquals(
            StreamRendezvousName.HintMatch.UNHINTED,
            StreamRendezvousName.hintMatch(resolved(bare), ownToken, NOW_SECONDS, fakeHint),
        )
    }

    @Test
    fun publishedRecordCarriesNoTokenBytes() {
        val published = StreamRendezvousName.sessionAttributes(listOf(ownToken), NOW_SECONDS, fakeHint)
        val tokenHex = ownToken.joinToString("") { "%02x".format(it) }
        assertFalse(published.values.any { value -> value.contains(tokenHex) })
    }

    @Test
    fun nextWindowIsAtTheBoundary() {
        val windowMillis = StreamRendezvousName.HINT_WINDOW_SECONDS * MILLIS_PER_SECOND
        assertEquals(windowMillis, StreamRendezvousName.millisUntilNextWindow(windowMillis * WINDOW_INDEX))
        assertEquals(1L, StreamRendezvousName.millisUntilNextWindow(windowMillis * WINDOW_INDEX - 1))
    }

    private fun resolved(attributes: Map<String, String>): Map<String, ByteArray?> =
        attributes.mapValues { (_, value) -> value.toByteArray() }

    private companion object {
        const val TOKEN_SIZE = 16
        const val OWN_TOKEN_BYTE: Byte = 0x11
        const val OTHER_TOKEN_BYTE: Byte = 0x22
        const val CORPUS_TOKEN_BYTE: Byte = 0x5a
        const val CORPUS_EPOCH = 1_990_560L
        const val CORPUS_HINT_HEX = "96b4d41e75873658"
        const val NOW_SECONDS = 1_791_504_450L
        const val MILLIS_PER_SECOND = 1_000L
        const val WINDOW_INDEX = 7L
    }
}
