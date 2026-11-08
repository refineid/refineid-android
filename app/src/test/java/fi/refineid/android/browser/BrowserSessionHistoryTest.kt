// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserSessionHistoryTest {
    private companion object {
        const val EXAMPLE = "https://example.test/start"
        const val EXAMPLE_WITH_SECRETS = "https://example.test/callback?code=synthetic#state=synthetic"
        const val EXAMPLE_CALLBACK = "https://example.test/callback"
        const val OTHER = "https://www.other.test/"
        const val OTHER_INDEX = "https://www.other.test/index"
        const val CLEARTEXT = "http://example.test/"
        const val SMALL_LIMIT = 2
    }

    @Test
    fun suggestionsAreNewestFirst() {
        val history = BrowserSessionHistory()
        history.record(EXAMPLE)
        history.record(EXAMPLE_CALLBACK)
        assertEquals(listOf(EXAMPLE_CALLBACK, EXAMPLE), history.suggestions("example"))
    }

    @Test
    fun queryAndFragmentAreNeverKept() {
        val history = BrowserSessionHistory()
        history.record(EXAMPLE_WITH_SECRETS)
        assertEquals(listOf(EXAMPLE_CALLBACK), history.suggestions("exa"))
        assertTrue(history.suggestions("code").isEmpty())
    }

    @Test
    fun hostPrefixMatchesComeBeforeContainedOnes() {
        val history = BrowserSessionHistory()
        history.record(EXAMPLE)
        history.record(OTHER_INDEX)
        assertEquals(listOf(EXAMPLE, OTHER_INDEX), history.suggestions("ex"))
    }

    @Test
    fun aRevisitMovesTheAddressToTheFrontOnce() {
        val history = BrowserSessionHistory()
        history.record(EXAMPLE)
        history.record(OTHER)
        history.record(EXAMPLE)
        assertEquals(listOf(EXAMPLE, OTHER), history.suggestions("test"))
    }

    @Test
    fun theOldestAddressLeavesAtTheLimit() {
        val history = BrowserSessionHistory(entryLimit = SMALL_LIMIT)
        history.record(EXAMPLE)
        history.record(EXAMPLE_CALLBACK)
        history.record(OTHER)
        assertEquals(listOf(OTHER, EXAMPLE_CALLBACK), history.suggestions("test"))
    }

    @Test
    fun emptyCleartextAndExactEntriesOfferNothing() {
        val history = BrowserSessionHistory()
        history.record(CLEARTEXT)
        history.record(EXAMPLE)
        assertTrue(history.suggestions("  ").isEmpty())
        assertTrue(history.suggestions("http://example").isEmpty())
        assertTrue(history.suggestions(EXAMPLE).isEmpty())
        assertNull(BrowserSessionHistory.entryOf(CLEARTEXT))
    }

    @Test
    fun clearForgetsEverything() {
        val history = BrowserSessionHistory()
        history.record(EXAMPLE)
        history.clear()
        assertTrue(history.suggestions("example").isEmpty())
    }
}
