// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.SignFailure

class SigningStatusTest {
    @Test
    fun aRevokedCertificateReadsAsRevokedWithOrWithoutAReason() {
        assertEquals(
            DocumentSigningStatus.CERT_REVOKED,
            signingStatusOf(SignFailure.Revoked(REVOKED_AT, KEY_COMPROMISE), wrongPin = false),
        )
        assertEquals(
            DocumentSigningStatus.CERT_REVOKED,
            signingStatusOf(SignFailure.Revoked(REVOKED_AT, null), wrongPin = false),
        )
    }

    @Test
    fun otherMaterialFailuresStayUnavailable() {
        assertEquals(
            DocumentSigningStatus.UNAVAILABLE,
            signingStatusOf(SignFailure.Material(MATERIAL_DETAIL), wrongPin = false),
        )
    }

    @Test
    fun aDeclinedReentryAfterAWrongPinReadsAsTheWrongPin() {
        assertEquals(
            DocumentSigningStatus.WRONG_PIN,
            signingStatusOf(SignFailure.Card(CardSignRefusal.Declined()), wrongPin = true),
        )
        assertEquals(
            DocumentSigningStatus.PIN_LOCKED,
            signingStatusOf(SignFailure.Card(CardSignRefusal.RetryFloor()), wrongPin = false),
        )
    }

    private companion object {
        const val REVOKED_AT = "2026-01-01T00:00:00Z"
        const val KEY_COMPROMISE = "keyCompromise"
        const val MATERIAL_DETAIL = "synthetic material failure"
    }
}
