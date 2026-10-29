package fi.refineid.android.core

import java.security.MessageDigest

/**
 * The card a held PIN 1 belongs to: the SHA-256 digest of the canonical DER
 * encoding of its authentication certificate, the fingerprint RAPP reports
 * the card by (RAPP v26.10.29 section 8.4). Each card carries its own
 * certificate, so two cards never share an identity; the held PIN 1 is
 * bound to it (credential custody: the held entry is bound to the card
 * token).
 */
internal class AuthenticationCardIdentity private constructor(
    private val digest: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is AuthenticationCardIdentity && MessageDigest.isEqual(digest, other.digest)

    override fun hashCode(): Int = digest.contentHashCode()

    override fun toString(): String = "AuthenticationCardIdentity"

    companion object {
        private const val DIGEST_ALGORITHM = "SHA-256"
        private const val CLEARED_BYTE: Byte = 0

        /**
         * The identity of the card whose authentication certificate has the
         * canonical DER encoding [der]; null for no certificate. The card
         * reads, the certificate RAPP offers and the primed store all hand
         * over that canonical encoding.
         */
        fun of(der: ByteArray): AuthenticationCardIdentity? {
            if (der.isEmpty()) return null
            return AuthenticationCardIdentity(MessageDigest.getInstance(DIGEST_ALGORITHM).digest(der))
        }

        /** The identity of the card [certificate] came from; null once the certificate is closed. */
        fun of(certificate: NativeAuthenticationCertificate): AuthenticationCardIdentity? {
            val der =
                try {
                    certificate.copyDer()
                } catch (_: IllegalStateException) {
                    return null
                }
            return try {
                of(der)
            } finally {
                der.fill(CLEARED_BYTE)
            }
        }
    }
}

/**
 * Leave to hold a verified PIN 1 for reuse: the [card] it was verified on,
 * whose PIN 1 retry counter read pristine, at its try limit, before that
 * verification (credential custody: reusable retention only with pristine
 * counters). A PIN verified on a card whose counter read lower, or could not
 * be read, serves its one operation and is not held. The PIN 2 counter is
 * not part of the leave; the authentication flows read only the PIN 1
 * counter.
 */
internal class Pin1Retention private constructor(
    val card: AuthenticationCardIdentity,
) {
    override fun toString(): String = "Pin1Retention"

    companion object {
        /** The leave for [card] when its PIN 1 counter read [attemptsBefore]; null unless both say so. */
        fun of(
            card: AuthenticationCardIdentity?,
            attemptsBefore: Int?,
        ): Pin1Retention? = if (card != null && attemptsBefore == FINEID_PIN_TRY_LIMIT) Pin1Retention(card) else null
    }
}
