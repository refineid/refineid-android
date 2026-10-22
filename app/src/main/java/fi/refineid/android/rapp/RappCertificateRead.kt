// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Bounded reads of a card's certificates for RAPP. A card service that does
 * not hand a certificate over in time counts as a card that cannot answer
 * now, so no wait on it can stall what a session reports (RAPP v26.10.21
 * section 8.4 item 1).
 */
internal object RappCertificateRead {
    /** How long a card service may take to hand a certificate over. */
    const val TIMEOUT_MS = 5_000L

    /**
     * The authentication certificate [service] hands over within
     * [timeoutMs]; null when it hands over none, none that parses, or none
     * in time.
     */
    suspend fun authentication(
        service: AuthenticationCardService,
        timeoutMs: Long = TIMEOUT_MS,
    ): RappCertificate? {
        val answer = CompletableDeferred<RappCertificate?>()
        service.requestAuthenticationCertificate { certificate ->
            val read =
                try {
                    certificate?.copyDer()?.let(RappCertificate::fromDer)
                } catch (_: IllegalStateException) {
                    null
                } finally {
                    certificate?.close()
                }
            answer.complete(read)
        }
        return withTimeoutOrNull(timeoutMs) { answer.await() }
    }
}
