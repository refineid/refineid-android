// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.diagnostics.AppTrace
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappSweepOutcome
import java.util.concurrent.TimeUnit

/** The pairing of the session this phone serves, and whether that session is established yet. */
internal class RappServedSession(
    val pairId: RappPairId,
    val established: Boolean,
)

/**
 * Idle expiry of the pairings this phone serves (RAPP v26.10.29 section 4.6
 * item 5; core STPA CC-103).
 *
 * A pairing with no established session for 30 days expires: the core
 * stores its record as forgotten, keeping the key only for the
 * `pairing_revoked` close of a later session, and the computer leaves the
 * list of paired computers, as when the holder forgets it while no session
 * is open. Nothing is sent and nothing is shown.
 *
 * The phone sweeps every pairing when the app starts and every
 * [SWEEP_INTERVAL_MS] while it runs, and the pairing of a session when the
 * session is established and when it ends, so a pairing in use never
 * expires. The core stores a sweep's change before it takes it into memory:
 * a sweep that failed to store changed nothing, and the next one repeats it.
 */
internal object RappIdleExpiry {
    /** Hours between two sweeps while the app runs. */
    private const val SWEEP_INTERVAL_HOURS = 1L

    /**
     * Milliseconds between two sweeps while the app runs. A delay does not
     * advance while the device sleeps, so the interval is far shorter than
     * the day section 4.6 item 5 allows between sweeps.
     */
    val SWEEP_INTERVAL_MS: Long = TimeUnit.HOURS.toMillis(SWEEP_INTERVAL_HOURS)

    /**
     * Sweeps every active pairing this phone serves as custodian at [nowMs],
     * milliseconds since the Unix epoch, and returns the ones that expired;
     * each has left [catalog]'s list. [session] is the session this phone
     * serves, if any. Its pairing is recorded once the session is
     * established, and left as it is while the session comes up, since that
     * session goes on with the record it loaded when it was routed.
     */
    fun sweep(
        catalog: RappPairCatalog,
        vault: RappPairVault,
        nowMs: ULong,
        session: RappServedSession?,
    ): List<RappPairId> {
        val expired = mutableListOf<RappPairId>()
        for (stored in RappStoredPairs.served(catalog, vault) { nowMs }) {
            stored.record.use { record ->
                val pairing = stored.pairing
                val established =
                    when {
                        pairing.role != RappEndpointRole.PROXY || pairing.state != RappPairState.Active -> null
                        session?.pairId != pairing.id -> false
                        session.established -> true
                        else -> null
                    }
                if (established != null && sweep(record, vault, nowMs, established) == RappSweepOutcome.EXPIRED) {
                    catalog.markForgotten(stored.peer.pairIdHex, nowMs.toLong())
                    AppTrace.rappPairingExpired()
                    expired += pairing.id
                }
            }
        }
        return expired
    }

    /**
     * Records that the session to [record]'s pairing is established at
     * [nowMs], milliseconds since the Unix epoch. The phone calls it when the
     * session is established and when it ends.
     */
    fun recordSession(
        record: RappPairRecord,
        vault: RappPairVault,
        nowMs: ULong,
    ) {
        sweep(record, vault, nowMs, sessionEstablished = true)
    }

    /** One pairing's sweep; null when it failed, which changed nothing. */
    private fun sweep(
        record: RappPairRecord,
        vault: RappPairVault,
        nowMs: ULong,
        sessionEstablished: Boolean,
    ): RappSweepOutcome? =
        try {
            record.sweep(vault, nowMs, sessionEstablished)
        } catch (failure: RappBindingException) {
            AppTrace.rappIdleSweepFailed(failure)
            null
        }
}
