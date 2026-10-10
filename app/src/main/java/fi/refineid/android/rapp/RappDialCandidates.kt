// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * Chooses which resolved phone a requester dials (RAPP discovery hierarchy
 * section 4.3).
 *
 * A phone ranked [BEST_RANK], one whose hint names this pairing, is dialed at
 * once. A lower-ranked phone, such as one publishing no hints, is only held:
 * the best held phone is dialed when the grace period ends without a
 * best-ranked one. A phone ranked null is never dialed.
 */
internal class RappDialCandidates {
    /** One resolved listener endpoint. */
    data class Endpoint(
        val host: String,
        val port: Int,
    )

    /** What to do with one resolved phone. */
    sealed interface Decision {
        /** Dial this endpoint now. */
        data class DialNow(
            val endpoint: Endpoint,
        ) : Decision

        /** Keep it as a fallback; start the grace timer if [startGrace]. */
        data class Hold(
            val startGrace: Boolean,
        ) : Decision

        /** Never dial it. */
        data object Ignore : Decision
    }

    private var held: Pair<Endpoint, Int>? = null
    private var graceStarted = false

    @Synchronized
    fun offer(
        endpoint: Endpoint,
        rank: Int?,
    ): Decision {
        if (rank == null) return Decision.Ignore
        if (rank == BEST_RANK) return Decision.DialNow(endpoint)
        val current = held
        if (current == null || rank < current.second) {
            held = endpoint to rank
        }
        val startGrace = !graceStarted
        graceStarted = true
        return Decision.Hold(startGrace)
    }

    /** The best held phone, for dialing when the grace period ends. */
    @Synchronized
    fun bestHeld(): Endpoint? = held?.first

    companion object {
        /** The rank of a phone whose hint names this pairing. */
        const val BEST_RANK = 0

        /** The rank of a phone publishing no hints. */
        const val UNHINTED_RANK = 1

        /** How long a held phone waits for a best-ranked one. */
        const val GRACE_MS = 2_000L
    }
}
