// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Test

class RappCredentialRejectionTest {
    private companion object {
        const val SYNTHETIC_RETRIES_LEFT = 2
    }

    @Test
    fun aCountedWrongPinKeepsThePairing() {
        assertEquals(
            RappCredentialRejection.AttemptsRemain(SYNTHETIC_RETRIES_LEFT.toUByte()),
            RappCredentialRejection.of(SYNTHETIC_RETRIES_LEFT),
        )
    }

    @Test
    fun aBlockedCounterRevokes() {
        assertEquals(RappCredentialRejection.Blocked, RappCredentialRejection.of(null))
    }

    @Test
    fun anImpossibleCountIsTreatedAsBlocked() {
        assertEquals(RappCredentialRejection.Blocked, RappCredentialRejection.of(0))
        assertEquals(RappCredentialRejection.Blocked, RappCredentialRejection.of(-1))
    }
}
