// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import fi.refineid.android.R
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.SignFailure

class SigningStatusTest {
    @Test
    fun aRevokedCertificateReadsAsRevokedWithOrWithoutAReason() {
        val expected =
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signer_revoked,
                    R.string.signing_action_card_issuer,
                ),
            )
        assertEquals(
            expected,
            SignFailure.Revoked(REVOKED_AT, KEY_COMPROMISE).signingStop(wrongPin = false),
        )
        assertEquals(
            expected,
            SignFailure.Revoked(REVOKED_AT, null).signingStop(wrongPin = false),
        )
    }

    @Test
    fun aMaterialFailureReadsAsUnreachableValidationServices() {
        assertEquals(
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_validation_services_unreachable,
                    R.string.signing_action_network,
                    frame = R.string.signing_frame_validation_material,
                ),
            ),
            SignFailure.Material(MATERIAL_DETAIL).signingStop(wrongPin = false),
        )
    }

    @Test
    fun aTimestampFailureReadsAsNoSignatureTimestamp() {
        assertEquals(
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signature_timestamp_failed,
                    R.string.signing_action_timestamp_authority,
                ),
            ),
            SignFailure.Timestamp(TIMESTAMP_DETAIL).signingStop(wrongPin = false),
        )
    }

    @Test
    fun aDeclinedReentryAfterAWrongPinReadsAsTheWrongPin() {
        assertEquals(
            DocumentSigningStop.Status(DocumentSigningStatus.WRONG_PIN),
            SignFailure.Card(CardSignRefusal.Declined()).signingStop(wrongPin = true),
        )
        assertEquals(
            DocumentSigningStop.Status(DocumentSigningStatus.PIN_LOCKED),
            SignFailure.Card(CardSignRefusal.RetryFloor()).signingStop(wrongPin = false),
        )
        assertEquals(
            DocumentSigningStop.Status(DocumentSigningStatus.IDLE),
            SignFailure.Card(CardSignRefusal.Declined()).signingStop(wrongPin = false),
        )
    }

    @Test
    fun cardAvailabilityAndKeyFailuresNameTheirCause() {
        val unreachable =
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.NOT_SIGNED,
                    R.string.signing_cause_card_unreachable,
                    R.string.signing_action_hold_card,
                ),
            )
        assertEquals(
            unreachable,
            SignFailure.Card(CardSignRefusal.CardUnavailable()).signingStop(wrongPin = false),
        )
        assertEquals(
            unreachable,
            SignFailure.Card(CardSignRefusal.Expired()).signingStop(wrongPin = false),
        )
        val unsupported =
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.NOT_SIGNED,
                    R.string.signing_cause_key_unsupported,
                    R.string.signing_action_other_card,
                ),
            )
        assertEquals(
            unsupported,
            SignFailure.Card(CardSignRefusal.Unsupported()).signingStop(wrongPin = false),
        )
        assertEquals(
            unsupported,
            SignFailure.Certificate(CERTIFICATE_DETAIL).signingStop(wrongPin = false),
        )
        assertEquals(
            DocumentSigningStop.Failed(internalFailure(SigningFailureOutcome.NOT_SIGNED)),
            SignFailure.Card(CardSignRefusal.CardFailed()).signingStop(wrongPin = false),
        )
    }

    @Test
    fun inputOutputDocumentAndSignatureFailuresKeepTheirMeaning() {
        assertEquals(
            DocumentSigningStop.Failed(FileUnreadableFailure),
            SignFailure.InputRead().signingStop(wrongPin = false),
        )
        assertEquals(
            DocumentSigningStop.Failed(saveFailure(partly = false)),
            SignFailure.OutputWrite().signingStop(wrongPin = false),
        )
        assertEquals(
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signature_not_verified,
                    R.string.signing_action_report,
                ),
            ),
            SignFailure.SignatureInvalid().signingStop(wrongPin = false),
        )
        assertEquals(
            DocumentSigningStop.Failed(internalFailure(SigningFailureOutcome.NOT_SIGNED)),
            SignFailure.Document(DOCUMENT_DETAIL).signingStop(wrongPin = false),
        )
    }

    private companion object {
        const val REVOKED_AT = "2026-01-01T00:00:00Z"
        const val KEY_COMPROMISE = "keyCompromise"
        const val MATERIAL_DETAIL = "synthetic material failure"
        const val TIMESTAMP_DETAIL = "synthetic timestamp failure"
        const val CERTIFICATE_DETAIL = "synthetic certificate failure"
        const val DOCUMENT_DETAIL = "synthetic document failure"
    }
}
