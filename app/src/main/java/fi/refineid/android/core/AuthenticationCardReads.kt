package fi.refineid.android.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Bounded reads from the card behind an [AuthenticationCardService]: which
 * card it is, and the PIN 1 attempts it allows. A service that does not
 * answer in time counts as one that cannot say.
 */
internal object AuthenticationCardReads {
    /** How long a card service may take to answer one read. */
    const val TIMEOUT_MS = 5_000L

    /** The card behind [service], named by its authentication certificate; null when it does not say in time. */
    suspend fun identity(
        service: AuthenticationCardService,
        timeoutMs: Long = TIMEOUT_MS,
    ): AuthenticationCardIdentity? {
        val answer = CompletableDeferred<AuthenticationCardIdentity?>()
        service.requestAuthenticationCertificate { certificate ->
            val identity =
                try {
                    certificate?.let(AuthenticationCardIdentity::of)
                } finally {
                    certificate?.close()
                }
            answer.complete(identity)
        }
        return withTimeoutOrNull(timeoutMs) { answer.await() }
    }

    /**
     * The PIN 1 attempts [card] allows when it is the card behind [service],
     * read without a VERIFY; null for another card, or when the service does
     * not say in time. A count read this way always belongs to [card].
     */
    suspend fun pin1AttemptsLeft(
        service: AuthenticationCardService,
        card: AuthenticationCardIdentity,
        timeoutMs: Long = TIMEOUT_MS,
    ): Int? {
        if (identity(service, timeoutMs) != card) return null
        return pin1AttemptsLeft(service, timeoutMs)
    }

    /**
     * The PIN 1 attempts the card behind [service] allows, read without a
     * VERIFY; null when it does not say in time.
     */
    suspend fun pin1AttemptsLeft(
        service: AuthenticationCardService,
        timeoutMs: Long = TIMEOUT_MS,
    ): Int? {
        val answer = CompletableDeferred<Int?>()
        service.requestPin1AttemptsLeft { attempts -> answer.complete(attempts) }
        return withTimeoutOrNull(timeoutMs) { answer.await() }
    }
}
