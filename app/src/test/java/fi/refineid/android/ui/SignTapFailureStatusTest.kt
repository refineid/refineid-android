// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import fi.refineid.android.nfc.SignTapFailure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SignTapFailureStatusTest {
    @Test
    fun onlyACardThatNeverAnsweredReadsAsNoCard() {
        assertEquals(DocumentSigningStatus.NO_CARD, SignTapFailure.NO_CARD.signingStatus())
        SignTapFailure.entries.filter { it != SignTapFailure.NO_CARD }.forEach { failure ->
            assertNotEquals(failure.name, DocumentSigningStatus.NO_CARD, failure.signingStatus())
        }
    }

    @Test
    fun eachReasonHasItsOwnStatus() {
        val statuses = SignTapFailure.entries.map { it.signingStatus() }
        assertEquals(statuses.size, statuses.toSet().size)
    }
}
