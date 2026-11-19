// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import androidx.annotation.StringRes
import fi.refineid.android.R
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.QualifiedSignFailure
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.SignFailure

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

/**
 * Where a core signing failure stops: its own status line for a PIN the
 * holder re-enters or declines, else the failure that names its cause.
 * [wrongPin] when the card already refused one PIN 2 entry, so a
 * declined re-entry reads as the wrong PIN.
 */
internal fun SignFailure.signingStop(wrongPin: Boolean): DocumentSigningStop =
    when (this) {
        is SignFailure.Card -> {
            when (refusal) {
                is CardSignRefusal.Declined -> {
                    if (wrongPin) {
                        DocumentSigningStop.Status(DocumentSigningStatus.WRONG_PIN)
                    } else {
                        DocumentSigningStop.Status(DocumentSigningStatus.IDLE)
                    }
                }

                is CardSignRefusal.RetryFloor -> {
                    DocumentSigningStop.Status(DocumentSigningStatus.PIN_LOCKED)
                }

                is CardSignRefusal.CardUnavailable,
                is CardSignRefusal.Expired,
                -> {
                    DocumentSigningStop.Failed(
                        DocumentSigningFailure(
                            SigningFailureOutcome.NOT_SIGNED,
                            R.string.signing_cause_card_unreachable,
                            R.string.signing_action_hold_card,
                        ),
                    )
                }

                is CardSignRefusal.Unsupported -> {
                    DocumentSigningStop.Failed(
                        DocumentSigningFailure(
                            SigningFailureOutcome.NOT_SIGNED,
                            R.string.signing_cause_key_unsupported,
                            R.string.signing_action_other_card,
                        ),
                    )
                }

                is CardSignRefusal.CardFailed -> {
                    DocumentSigningStop.Failed(internalFailure(SigningFailureOutcome.NOT_SIGNED))
                }
            }
        }

        is SignFailure.Certificate -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.NOT_SIGNED,
                    R.string.signing_cause_key_unsupported,
                    R.string.signing_action_other_card,
                ),
            )
        }

        is SignFailure.Revoked -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signer_revoked,
                    R.string.signing_action_card_issuer,
                ),
            )
        }

        is SignFailure.Timestamp -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signature_timestamp_failed,
                    R.string.signing_action_timestamp_authority,
                ),
            )
        }

        is SignFailure.Material -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_validation_services_unreachable,
                    R.string.signing_action_network,
                    frame = R.string.signing_frame_validation_material,
                ),
            )
        }

        is SignFailure.InputRead -> {
            DocumentSigningStop.Failed(FileUnreadableFailure)
        }

        is SignFailure.OutputWrite -> {
            DocumentSigningStop.Failed(saveFailure(partly = false))
        }

        is SignFailure.SignatureInvalid -> {
            DocumentSigningStop.Failed(
                DocumentSigningFailure(
                    SigningFailureOutcome.SIGNATURE_DISCARDED,
                    R.string.signing_cause_signature_not_verified,
                    R.string.signing_action_report,
                ),
            )
        }

        is SignFailure.Document -> {
            DocumentSigningStop.Failed(internalFailure(SigningFailureOutcome.NOT_SIGNED))
        }
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
