// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappPreAuthenticationLimiter

/**
 * Only a session preamble that routes to a served pairing counts against the
 * pre-authentication bound (RAPP v26.10.29 section 3.3 item 6).
 */
class RappSessionDialGateTest {
    private companion object {
        const val FIRST_DIAL_MS = 1_000UL

        /** A dial inside the spacing of the one before it. */
        const val INSIDE_SPACING_MS = 1UL
        const val ROUTED = "served pairing"
    }

    private val released = mutableListOf<String>()
    private var rateLimited = 0

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun RappSessionDialGate.dial(
        now: ULong,
        routed: String?,
    ): String? = admit(now, { routed }, { released += it }, { rateLimited++ })

    @Test
    fun aFirstFrameThatRoutesNowhereDoesNotHoldOffTheNextDial() {
        val gate = RappSessionDialGate(RappPreAuthenticationLimiter())

        assertNull(gate.dial(FIRST_DIAL_MS, null))
        assertEquals(ROUTED, gate.dial(FIRST_DIAL_MS + INSIDE_SPACING_MS, ROUTED))

        assertEquals(0, rateLimited)
        assertEquals(emptyList<String>(), released)
    }

    @Test
    fun aRoutedDialInsideTheSpacingIsRefusedAndReleased() {
        val gate = RappSessionDialGate(RappPreAuthenticationLimiter())
        assertEquals(ROUTED, gate.dial(FIRST_DIAL_MS, ROUTED))

        assertNull(gate.dial(FIRST_DIAL_MS + INSIDE_SPACING_MS, ROUTED))

        assertEquals(1, rateLimited)
        assertEquals(listOf(ROUTED), released)
    }
}
