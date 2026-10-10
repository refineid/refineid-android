// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RappDialCandidatesTest {
    private val named = RappDialCandidates.Endpoint("named", PORT)
    private val unhinted = RappDialCandidates.Endpoint("unhinted", PORT)
    private val worse = RappDialCandidates.Endpoint("worse", PORT)

    @Test
    fun namedPhoneIsDialedAtOnce() {
        val candidates = RappDialCandidates()
        assertEquals(
            RappDialCandidates.Decision.DialNow(named),
            candidates.offer(named, RappDialCandidates.BEST_RANK),
        )
    }

    @Test
    fun namedPhoneWinsOverAnEarlierUnhintedOne() {
        val candidates = RappDialCandidates()
        assertEquals(
            RappDialCandidates.Decision.Hold(startGrace = true),
            candidates.offer(unhinted, RappDialCandidates.UNHINTED_RANK),
        )
        assertEquals(
            RappDialCandidates.Decision.DialNow(named),
            candidates.offer(named, RappDialCandidates.BEST_RANK),
        )
    }

    @Test
    fun graceStartsOnceAndKeepsTheBestHeldPhone() {
        val candidates = RappDialCandidates()
        candidates.offer(worse, WORSE_RANK)
        assertEquals(
            RappDialCandidates.Decision.Hold(startGrace = false),
            candidates.offer(unhinted, RappDialCandidates.UNHINTED_RANK),
        )
        candidates.offer(worse, WORSE_RANK)
        assertEquals(unhinted, candidates.bestHeld())
    }

    @Test
    fun phoneNamingOnlyOtherPairingsIsNeverDialed() {
        val candidates = RappDialCandidates()
        assertEquals(RappDialCandidates.Decision.Ignore, candidates.offer(worse, null))
        assertNull(candidates.bestHeld())
    }

    private companion object {
        const val PORT = 4242
        const val WORSE_RANK = 2
    }
}
