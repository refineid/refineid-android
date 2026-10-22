// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class NativePin1StateTest {
    @Test
    fun aVerifiedPinAllowsItsTryLimit() {
        assertEquals(FINEID_PIN_TRY_LIMIT, NativePin1State.Verified.attemptsLeft())
    }

    @Test
    fun aCountedPinAllowsWhatTheCardSays() {
        assertEquals(ONE_ATTEMPT_SPENT, NativePin1State.Remaining(ONE_ATTEMPT_SPENT).attemptsLeft())
        assertEquals(BLOCKED, NativePin1State.Locked.attemptsLeft())
    }

    @Test
    fun aCardThatDoesNotSayGivesNoCount() {
        assertNull(NativePin1State.NoInformation.attemptsLeft())
        assertNull(NativePin1State.Unrecognized.attemptsLeft())
    }

    @Test
    fun aCardStillHoldingItsLastVerifyGivesLeaveToHoldThePin() {
        assertNotNull(Pin1Retention.of(CARD, NativePin1State.Verified.attemptsLeft()))
        assertNull(Pin1Retention.of(CARD, NativePin1State.Remaining(ONE_ATTEMPT_SPENT).attemptsLeft()))
        assertNull(Pin1Retention.of(CARD, NativePin1State.NoInformation.attemptsLeft()))
    }

    private companion object {
        const val ONE_ATTEMPT_SPENT = FINEID_PIN_TRY_LIMIT - 1
        const val BLOCKED = 0
        val CARD =
            checkNotNull(AuthenticationCardIdentity.of("synthetic authentication certificate".encodeToByteArray()))
    }
}
