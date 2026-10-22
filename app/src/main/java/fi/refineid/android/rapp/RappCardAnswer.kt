// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.QualifiedSignFailure

/** Why a remote operation ends without a result (RAPP v26.10.21 section 10.3). */
internal enum class RappCardFailure {
    /** The holder declined or cancelled on the phone: `user_cancelled`. */
    USER_CANCELLED,

    /** The card allows fewer than three PIN attempts, or will not say how many: `retry_floor`. */
    RETRY_FLOOR,

    /** The card did not answer: `card_error`. */
    CARD_ERROR,

    /** The card does not hold the requested key or algorithm: `unsupported_parameter`. */
    UNSUPPORTED,

    /** The phone could not carry the operation out: `operation_failed`. */
    OPERATION_FAILED,
}

/**
 * What a PIN-consuming card command means for the remote operation that ran
 * it (RAPP v26.10.21 section 10.2).
 *
 * The native card session reads the PIN status with a header-only VERIFY
 * before every verification and, without sending one, refuses one or two
 * remaining attempts, a blocked PIN, and a status that carries no count and
 * is not "verified"; those refusals end the operation as `retry_floor`. A
 * wrong PIN is the holder's to correct on the phone while the card still
 * allows at least [MINIMUM_REMAINING_ATTEMPTS]; the requester learns nothing
 * of it.
 */
internal sealed interface RappCardAnswer {
    /** The card did what the operation asked. */
    data object Done : RappCardAnswer

    /**
     * The PIN was wrong and the holder is asked again. [attemptsLeft] is the
     * card's count, at least [MINIMUM_REMAINING_ATTEMPTS], or null when the
     * phone refused a PIN the card had already rejected and no command was
     * sent.
     */
    class WrongPin private constructor(
        val attemptsLeft: Int?,
    ) : RappCardAnswer {
        companion object {
            /** The phone refused a PIN the card had already rejected; no count is known. */
            val ALREADY_REJECTED = WrongPin(null)

            /** The card's count after a wrong PIN, when it leaves the holder another try; null below the floor. */
            fun after(remainingRetries: Int): WrongPin? =
                if (remainingRetries >= MINIMUM_REMAINING_ATTEMPTS) WrongPin(remainingRetries) else null
        }
    }

    /** The operation ends with [failure]. */
    data class Ends(
        val failure: RappCardFailure,
    ) : RappCardAnswer

    companion object {
        /** The fewest attempts a card must allow before RefineID presents a PIN to it. */
        const val MINIMUM_REMAINING_ATTEMPTS = 3

        /** The answer of an authentication command that failed with [failure]. */
        fun of(
            failure: AuthenticationSignFailure,
            remainingRetries: Int?,
        ): RappCardAnswer =
            when (failure) {
                AuthenticationSignFailure.WRONG_PIN -> {
                    afterWrongPin(remainingRetries)
                }

                AuthenticationSignFailure.SAFETY_REFUSED, AuthenticationSignFailure.PIN_LOCKED -> {
                    Ends(RappCardFailure.RETRY_FLOOR)
                }

                AuthenticationSignFailure.CARD_UNAVAILABLE,
                AuthenticationSignFailure.TRANSPORT_ERROR,
                AuthenticationSignFailure.BRIDGE_ERROR,
                -> {
                    Ends(RappCardFailure.CARD_ERROR)
                }

                AuthenticationSignFailure.KEY_PROFILE_MISMATCH -> {
                    Ends(RappCardFailure.UNSUPPORTED)
                }

                AuthenticationSignFailure.INVALID_PIN,
                AuthenticationSignFailure.VERIFICATION_REJECTED,
                AuthenticationSignFailure.SIGNING_REJECTED,
                AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                -> {
                    Ends(RappCardFailure.OPERATION_FAILED)
                }
            }

        /** The answer of a qualified-signature command that failed with [failure]. */
        fun of(
            failure: QualifiedSignFailure,
            remainingRetries: Int?,
        ): RappCardAnswer =
            when (failure) {
                QualifiedSignFailure.WRONG_PIN -> {
                    afterWrongPin(remainingRetries)
                }

                QualifiedSignFailure.SAFETY_REFUSED, QualifiedSignFailure.PIN_LOCKED -> {
                    Ends(RappCardFailure.RETRY_FLOOR)
                }

                QualifiedSignFailure.CARD_UNAVAILABLE,
                QualifiedSignFailure.TRANSPORT_ERROR,
                QualifiedSignFailure.BRIDGE_ERROR,
                QualifiedSignFailure.CERTIFICATE_MISMATCH,
                -> {
                    Ends(RappCardFailure.CARD_ERROR)
                }

                QualifiedSignFailure.KEY_PROFILE_MISMATCH -> {
                    Ends(RappCardFailure.UNSUPPORTED)
                }

                QualifiedSignFailure.INVALID_PIN,
                QualifiedSignFailure.VERIFICATION_REJECTED,
                QualifiedSignFailure.CERTIFICATE_REJECTED,
                QualifiedSignFailure.INVALID_CERTIFICATE,
                QualifiedSignFailure.SIGNING_REJECTED,
                QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
                -> {
                    Ends(RappCardFailure.OPERATION_FAILED)
                }
            }

        /**
         * A wrong PIN leaves the count the card reported: at the floor or
         * above, the holder enters the PIN again; below it, or without a
         * count, the next verification would be refused, so the operation
         * ends there.
         */
        private fun afterWrongPin(remainingRetries: Int?): RappCardAnswer =
            remainingRetries?.let(WrongPin::after) ?: Ends(RappCardFailure.RETRY_FLOOR)
    }
}
