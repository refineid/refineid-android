// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import androidx.annotation.StringRes
import fi.refineid.android.R
import fi.refineid.android.asic.AsicSigningFailure
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.document.BaselineLevel
import fi.refineid.android.document.PdfSigningFailure
import fi.refineid.android.document.QualifiedDocumentCmsFailure
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.QualifiedPdfTimestampPhase
import fi.refineid.android.document.SignedDocumentName
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationPathRole

/** What became of the signature when signing stopped; each names its lead and consequence sentences. */
internal enum class SigningFailureOutcome(
    @param:StringRes val lead: Int,
    @param:StringRes val consequence: Int?,
) {
    /** Stopped before a signed document existed. */
    NOT_SIGNED(R.string.signing_failed_not_signed, null),

    /** The card signed, completion failed, and the signature was discarded unsaved. */
    SIGNATURE_DISCARDED(R.string.signing_failed_signature_made, R.string.signing_outcome_discarded),

    /** The signed document existed and could not be written, so it was discarded. */
    NOT_SAVED(R.string.signing_failed_not_saved, R.string.signing_outcome_not_saved),

    /** Some signed documents of a batch were written; the rest were discarded. */
    PARTLY_SAVED(R.string.signing_failed_not_saved, R.string.signing_outcome_partly_saved),
}

/**
 * Why signing stopped, as the holder reads it: what became of the
 * signature, the cause (optionally inside a [frame] that names the
 * stage), and what the holder can do.
 */
internal data class DocumentSigningFailure(
    val outcome: SigningFailureOutcome,
    @param:StringRes val cause: Int,
    @param:StringRes val action: Int,
    @param:StringRes val frame: Int? = null,
) {
    /** The cause inside its frame, e.g. "the material ... could not be collected: the issuer ...". */
    fun problem(
        string: (Int) -> String,
        format: (Int, String) -> String,
    ): String {
        val cause = string(cause)
        return frame?.let { format(it, cause) } ?: cause
    }

    /** The full message: lead with the problem, the consequence, and the action. */
    fun text(
        string: (Int) -> String,
        format: (Int, String) -> String,
    ): String =
        listOfNotNull(
            format(outcome.lead, problem(string, format)),
            outcome.consequence?.let(string),
            string(action),
        ).joinToString(SENTENCE_SEPARATOR)

    private companion object {
        const val SENTENCE_SEPARATOR = " "
    }
}

/** The signature standard a signed file follows, by the name it gives its signatures. */
internal enum class SignatureStandard(
    val label: String,
) {
    /** A PDF signed in place (ETSI EN 319 142-1). */
    PADES("PAdES"),

    /** The signature of an ASiC-E container (ETSI EN 319 132-1). */
    XADES("XAdES"),
}

/**
 * A development file saved below B-LTA: its [standard], the [level] it
 * reached and why it went no further.
 */
internal data class BelowLongTermNotice(
    val standard: SignatureStandard,
    val level: BaselineLevel,
    val failure: DocumentSigningFailure,
) {
    /** The status line naming the standard and level, the file-name mark and the cause. */
    fun text(
        string: (Int) -> String,
        format: (Int, List<String>) -> String,
    ): String =
        format(
            R.string.signed_below_long_term,
            listOf(
                standard.label,
                level.label,
                SignedDocumentName.developmentSuffix(level),
                failure.problem(string) { id, argument -> format(id, listOf(argument)) },
            ),
        )
}

/** A stop that keeps its own status line, or a failure with its cause. */
internal sealed interface DocumentSigningStop {
    data class Status(
        val status: DocumentSigningStatus,
    ) : DocumentSigningStop

    data class Failed(
        val failure: DocumentSigningFailure,
    ) : DocumentSigningStop
}

/** Signing never started: the session had no ready card. */
internal val CardNotReadyFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.NOT_SIGNED,
        R.string.signing_cause_card_not_ready,
        R.string.signing_action_present_card,
    )

/** A chosen file could not be read. */
internal val FileUnreadableFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.NOT_SIGNED,
        R.string.signing_cause_file_unreadable,
        R.string.signing_action_choose_file_again,
    )

/** The stored timestamp authority settings could not be read. */
internal val TimestampSettingsFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.NOT_SIGNED,
        R.string.signing_cause_timestamp_settings_unreadable,
        R.string.signing_action_timestamp_authority,
    )

/** An unexpected fault in the given stage. */
internal fun internalFailure(outcome: SigningFailureOutcome): DocumentSigningFailure =
    DocumentSigningFailure(outcome, R.string.signing_cause_internal_error, R.string.signing_action_report)

/** The signed output could not be written; [partly] when some files of a batch were. */
internal fun saveFailure(partly: Boolean): DocumentSigningFailure =
    DocumentSigningFailure(
        if (partly) SigningFailureOutcome.PARTLY_SAVED else SigningFailureOutcome.NOT_SAVED,
        R.string.signing_cause_file_not_written,
        R.string.signing_action_choose_other_location,
    )

internal fun QualifiedPdfArchivalFailure.signingFailure(): DocumentSigningFailure {
    val outcome = SigningFailureOutcome.SIGNATURE_DISCARDED
    return when (this) {
        is QualifiedPdfArchivalFailure.Timestamp -> {
            timestampFailure(phase)
        }

        is QualifiedPdfArchivalFailure.Validation -> {
            validationFailure(kind, pathRole)
        }

        QualifiedPdfArchivalFailure.ValidationUnavailable -> {
            validationUnavailableFailure()
        }

        is QualifiedPdfArchivalFailure.Cms -> {
            kind.signingFailure(outcome)
        }

        is QualifiedPdfArchivalFailure.Document -> {
            kind.signingFailure(outcome)
        }

        QualifiedPdfArchivalFailure.InternalError -> {
            internalFailure(outcome)
        }
    }
}

internal fun QualifiedPdfSigningFailure.signingStop(): DocumentSigningStop {
    val outcome = SigningFailureOutcome.NOT_SIGNED
    return when (this) {
        is QualifiedPdfSigningFailure.Card -> kind.signingStop()
        is QualifiedPdfSigningFailure.Certificate -> DocumentSigningStop.Failed(kind.signingFailure())
        QualifiedPdfSigningFailure.KeyProfileUnsupported -> DocumentSigningStop.Failed(KeyUnsupportedFailure)
        is QualifiedPdfSigningFailure.Cms -> DocumentSigningStop.Failed(kind.signingFailure(outcome))
        is QualifiedPdfSigningFailure.Document -> DocumentSigningStop.Failed(kind.signingFailure(outcome))
        QualifiedPdfSigningFailure.InternalError -> DocumentSigningStop.Failed(internalFailure(outcome))
    }
}

internal fun AsicSigningFailure.signingStop(): DocumentSigningStop {
    val discarded = SigningFailureOutcome.SIGNATURE_DISCARDED
    return when (this) {
        is AsicSigningFailure.Card -> {
            kind.signingStop()
        }

        is AsicSigningFailure.Certificate -> {
            DocumentSigningStop.Failed(kind.signingFailure())
        }

        AsicSigningFailure.KeyProfileUnsupported -> {
            DocumentSigningStop.Failed(KeyUnsupportedFailure)
        }

        AsicSigningFailure.UnusableNames -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.NOT_SIGNED,
                    R.string.signing_cause_unusable_names,
                    R.string.signing_action_rename_file,
                ),
            )
        }

        AsicSigningFailure.ContainerOverflow -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    discarded,
                    R.string.signing_cause_container_too_large,
                    R.string.signing_action_fewer_files,
                ),
            )
        }

        is AsicSigningFailure.Timestamp -> {
            DocumentSigningStop.Failed(timestampFailure(phase))
        }

        AsicSigningFailure.ArchiveTimestampPathUncovered -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    discarded,
                    R.string.signing_cause_archive_timestamp_path_uncovered,
                    R.string.signing_action_timestamp_authority,
                ),
            )
        }

        is AsicSigningFailure.Validation -> {
            DocumentSigningStop.Failed(validationFailure(kind, pathRole))
        }

        AsicSigningFailure.ValidationUnavailable -> {
            DocumentSigningStop.Failed(validationUnavailableFailure())
        }

        AsicSigningFailure.InternalError -> {
            DocumentSigningStop.Failed(internalFailure(discarded))
        }
    }
}

/**
 * The failure a completion-stage reason reports, as a development
 * container below B-LTA names it. Every such reason stops as
 * [DocumentSigningStop.Failed]; a card status cannot arise there.
 */
internal fun AsicSigningFailure.archivalFailure(): DocumentSigningFailure =
    when (val stop = signingStop()) {
        is DocumentSigningStop.Failed -> stop.failure
        is DocumentSigningStop.Status -> internalFailure(SigningFailureOutcome.SIGNATURE_DISCARDED)
    }

internal fun QualifiedSignFailure.signingStop(): DocumentSigningStop =
    when (this) {
        QualifiedSignFailure.WRONG_PIN -> {
            DocumentSigningStop.Status(DocumentSigningStatus.WRONG_PIN)
        }

        QualifiedSignFailure.PIN_LOCKED -> {
            DocumentSigningStop.Status(DocumentSigningStatus.PIN_LOCKED)
        }

        else -> {
            DocumentSigningStop.Failed(cardFailure())
        }
    }

private fun QualifiedSignFailure.cardFailure(): DocumentSigningFailure {
    val (cause, action) =
        when (this) {
            QualifiedSignFailure.CARD_UNAVAILABLE -> {
                R.string.signing_cause_card_unreachable to R.string.signing_action_hold_card
            }

            QualifiedSignFailure.TRANSPORT_ERROR -> {
                R.string.signing_cause_card_connection_lost to R.string.signing_action_hold_card
            }

            QualifiedSignFailure.SAFETY_REFUSED -> {
                R.string.signing_cause_pin2_low_attempts to R.string.signing_action_reset_pin2
            }

            QualifiedSignFailure.INVALID_PIN -> {
                R.string.signing_cause_pin2_invalid_form to R.string.signing_action_enter_pin2
            }

            QualifiedSignFailure.VERIFICATION_REJECTED -> {
                R.string.signing_cause_pin2_verification_rejected to R.string.signing_action_enter_pin2
            }

            QualifiedSignFailure.CERTIFICATE_REJECTED,
            QualifiedSignFailure.INVALID_CERTIFICATE,
            -> {
                R.string.signing_cause_certificate_unreadable to R.string.signing_action_card_issuer
            }

            QualifiedSignFailure.CERTIFICATE_MISMATCH,
            QualifiedSignFailure.KEY_PROFILE_MISMATCH,
            -> {
                R.string.signing_cause_certificate_mismatch to R.string.signing_action_card_issuer
            }

            QualifiedSignFailure.SIGNING_REJECTED -> {
                R.string.signing_cause_card_refused_signing to R.string.signing_action_sign_again
            }

            QualifiedSignFailure.LOCAL_VERIFICATION_FAILED -> {
                R.string.signing_cause_signature_not_verified to R.string.signing_action_report
            }

            QualifiedSignFailure.BRIDGE_ERROR,
            QualifiedSignFailure.WRONG_PIN,
            QualifiedSignFailure.PIN_LOCKED,
            -> {
                R.string.signing_cause_internal_error to R.string.signing_action_report
            }
        }
    return DocumentSigningFailure(SigningFailureOutcome.NOT_SIGNED, cause, action)
}

internal fun NativeCertificateReadFailure.signingFailure(): DocumentSigningFailure {
    val (cause, action) =
        when (this) {
            NativeCertificateReadFailure.CARD_UNAVAILABLE -> {
                R.string.signing_cause_card_unreachable to R.string.signing_action_hold_card
            }

            NativeCertificateReadFailure.TRANSPORT_ERROR -> {
                R.string.signing_cause_card_connection_lost to R.string.signing_action_hold_card
            }

            NativeCertificateReadFailure.REJECTED,
            NativeCertificateReadFailure.INVALID_CERTIFICATE,
            -> {
                R.string.signing_cause_certificate_unreadable to R.string.signing_action_card_issuer
            }

            NativeCertificateReadFailure.PACE_REJECTED -> {
                R.string.signing_cause_secure_channel_refused to R.string.signing_action_hold_card
            }

            NativeCertificateReadFailure.BRIDGE_ERROR -> {
                R.string.signing_cause_internal_error to R.string.signing_action_report
            }

            NativeCertificateReadFailure.ACTIVATION_REQUIRED -> {
                R.string.signing_cause_card_not_activated to R.string.signing_action_activate_card
            }

            NativeCertificateReadFailure.ORGANIZATION_CARD -> {
                R.string.signing_cause_organization_card_not_read to R.string.signing_action_read_organization_card
            }
        }
    return DocumentSigningFailure(SigningFailureOutcome.NOT_SIGNED, cause, action)
}

private val KeyUnsupportedFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.NOT_SIGNED,
        R.string.signing_cause_key_unsupported,
        R.string.signing_action_other_card,
    )

private fun PdfSigningFailure.signingFailure(outcome: SigningFailureOutcome): DocumentSigningFailure {
    val (cause, action) =
        when (this) {
            PdfSigningFailure.ENCRYPTED -> {
                R.string.signing_cause_document_encrypted to R.string.signing_action_other_document
            }

            PdfSigningFailure.NOT_A_PDF -> {
                R.string.signing_cause_not_a_pdf to R.string.signing_action_other_document
            }

            PdfSigningFailure.STREAM_ENCODING_UNSUPPORTED,
            PdfSigningFailure.STRUCTURE_UNREADABLE,
            -> {
                R.string.signing_cause_pdf_unsupported to R.string.signing_action_other_document
            }

            PdfSigningFailure.PLACEHOLDER_MALFORMED,
            PdfSigningFailure.SIGNATURE_CLAIM_MALFORMED,
            PdfSigningFailure.SIGNATURE_TOO_LARGE,
            PdfSigningFailure.VALIDATION_MATERIAL_MALFORMED,
            PdfSigningFailure.VALIDATION_MATERIAL_UNAVAILABLE,
            -> {
                R.string.signing_cause_document_assembly_failed to R.string.signing_action_report
            }
        }
    return DocumentSigningFailure(outcome, cause, action)
}

private fun QualifiedDocumentCmsFailure.signingFailure(outcome: SigningFailureOutcome): DocumentSigningFailure {
    val (cause, action) =
        when (this) {
            QualifiedDocumentCmsFailure.CERTIFICATE_UNPARSEABLE -> {
                R.string.signing_cause_certificate_unreadable to R.string.signing_action_card_issuer
            }

            QualifiedDocumentCmsFailure.CERTIFICATE_PROFILE_MISMATCH -> {
                R.string.signing_cause_certificate_mismatch to R.string.signing_action_card_issuer
            }

            QualifiedDocumentCmsFailure.TIMESTAMP_MISSING,
            QualifiedDocumentCmsFailure.TIMESTAMP_IMPRINT_MISMATCH,
            QualifiedDocumentCmsFailure.TIMESTAMP_TOKEN_UNAVAILABLE,
            -> {
                R.string.signing_cause_signature_timestamp_failed to R.string.signing_action_timestamp_authority
            }

            QualifiedDocumentCmsFailure.DOCUMENT_DIGEST_MALFORMED,
            QualifiedDocumentCmsFailure.SIGNATURE_MALFORMED,
            QualifiedDocumentCmsFailure.SIGNED_ATTRIBUTES_MALFORMED,
            -> {
                R.string.signing_cause_document_assembly_failed to R.string.signing_action_report
            }
        }
    return DocumentSigningFailure(outcome, cause, action)
}

private fun timestampFailure(phase: QualifiedPdfTimestampPhase): DocumentSigningFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.SIGNATURE_DISCARDED,
        when (phase) {
            QualifiedPdfTimestampPhase.SIGNATURE -> R.string.signing_cause_signature_timestamp_failed
            QualifiedPdfTimestampPhase.ARCHIVE -> R.string.signing_cause_archive_timestamp_failed
        },
        R.string.signing_action_timestamp_authority,
    )

private fun validationUnavailableFailure(): DocumentSigningFailure =
    DocumentSigningFailure(
        SigningFailureOutcome.SIGNATURE_DISCARDED,
        R.string.signing_cause_validation_services_unreachable,
        R.string.signing_action_network,
        frame = R.string.signing_frame_validation_material,
    )

/** A long-term validation material failure, named by its kind and, for a revocation, by its path. */
internal fun validationFailure(
    kind: ValidationMaterialCollectionFailure,
    pathRole: ValidationPathRole?,
): DocumentSigningFailure {
    val (cause, action) =
        when (kind) {
            ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE -> {
                R.string.signing_cause_issuer_unavailable to R.string.signing_action_network
            }

            ValidationMaterialCollectionFailure.REVOCATION_UNAVAILABLE -> {
                R.string.signing_cause_revocation_unavailable to R.string.signing_action_network
            }

            ValidationMaterialCollectionFailure.TRUST_ANCHOR_UNAVAILABLE -> {
                R.string.signing_cause_trust_anchor_unavailable to R.string.signing_action_network
            }

            ValidationMaterialCollectionFailure.RANDOM_UNAVAILABLE -> {
                R.string.signing_cause_random_unavailable to R.string.signing_action_sign_again
            }

            ValidationMaterialCollectionFailure.REVOKED -> {
                when (pathRole) {
                    ValidationPathRole.DOCUMENT_SIGNER -> {
                        R.string.signing_cause_signer_revoked to R.string.signing_action_card_issuer
                    }

                    ValidationPathRole.TIMESTAMP_AUTHORITY -> {
                        R.string.signing_cause_timestamp_authority_revoked to
                            R.string.signing_action_timestamp_authority
                    }

                    null -> {
                        R.string.signing_cause_chain_certificate_revoked to R.string.signing_action_card_issuer
                    }
                }
            }

            ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED -> {
                R.string.signing_cause_chain_certificate_malformed to R.string.signing_action_report
            }

            ValidationMaterialCollectionFailure.CHAIN_CYCLE -> {
                R.string.signing_cause_chain_cycle to R.string.signing_action_report
            }

            ValidationMaterialCollectionFailure.CHAIN_TOO_DEEP -> {
                R.string.signing_cause_chain_too_deep to R.string.signing_action_report
            }

            ValidationMaterialCollectionFailure.CANDIDATE_LIMIT_EXCEEDED -> {
                R.string.signing_cause_candidate_limit_exceeded to R.string.signing_action_report
            }

            ValidationMaterialCollectionFailure.PATH_LIMIT_EXCEEDED -> {
                R.string.signing_cause_path_limit_exceeded to R.string.signing_action_report
            }
        }
    return DocumentSigningFailure(
        SigningFailureOutcome.SIGNATURE_DISCARDED,
        cause,
        action,
        frame = R.string.signing_frame_validation_material,
    )
}
