// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * How the custodian reports a credential the card refused (RAPP v26.10.1
 * section 10.2). Only the card's own remaining count proves attempts remain;
 * anything else is reported as a blocked credential, which revokes the
 * pairing.
 */
internal sealed interface RappCredentialRejection {
    /** A typo with [remainingRetries] attempts left; the pairing stays. */
    data class AttemptsRemain(
        val remainingRetries: UByte,
    ) : RappCredentialRejection

    /** The counter is exhausted or its state is unknown. */
    data object Blocked : RappCredentialRejection

    companion object {
        fun of(remainingRetries: Int?): RappCredentialRejection =
            if (remainingRetries != null && remainingRetries in 1..UByte.MAX_VALUE.toInt()) {
                AttemptsRemain(remainingRetries.toUByte())
            } else {
                Blocked
            }
    }
}
