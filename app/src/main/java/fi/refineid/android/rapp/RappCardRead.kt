// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardReads
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.QualifiedSigningService
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Bounded reads from a card for RAPP: its authentication certificate and the
 * attempts its PIN 2 allows; [AuthenticationCardReads] reads PIN 1's. A card
 * service that does not answer in time counts as a card that cannot answer
 * now, so no wait on it can stall what a session reports (RAPP v26.10.29 section 8.4 item 1) or what a PIN command
 * decides (section 10.2).
 */
internal object RappCardRead {
    /** How long a card service may take to answer one read. */
    const val TIMEOUT_MS = AuthenticationCardReads.TIMEOUT_MS

    /** The count of a blocked PIN. */
    private const val BLOCKED_ATTEMPTS = 0

    /**
     * The authentication certificate [service] hands over within
     * [timeoutMs]; null when it hands over none, none that parses, or none
     * in time.
     */
    suspend fun authenticationCertificate(
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

    /**
     * The PIN 2 attempts the card behind [service] allows, read without a
     * VERIFY; null when it does not say in time.
     */
    suspend fun pin2AttemptsLeft(
        service: QualifiedSigningService,
        timeoutMs: Long = TIMEOUT_MS,
    ): Int? {
        val answer = CompletableDeferred<Int?>()
        service.requestPin2Preflight { result ->
            val attempts =
                when (val state = (result as? NativePin2PreflightResult.Success)?.preflight?.state) {
                    is NativePin2State.Remaining -> state.attempts
                    NativePin2State.Locked -> BLOCKED_ATTEMPTS
                    NativePin2State.Verified, NativePin2State.NoInformation, NativePin2State.Unrecognized, null -> null
                }
            answer.complete(attempts)
        }
        return withTimeoutOrNull(timeoutMs) { answer.await() }
    }
}
