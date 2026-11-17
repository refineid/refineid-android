// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

/**
 * Origin-scoped authorization for client-certificate presentation during a browser session.
 * Tracks the origins the holder has explicitly permitted to receive their authentication
 * certificate, and serializes concurrent certificate requests for one origin behind that
 * origin's single prompt. Every approval covers one origin, never a host name alone.
 */
internal class BrowserOriginAuthority(
    initialApprovedOrigins: Set<BrowserOrigin> = emptySet(),
) {
    private val lock = Any()
    private val approvedOrigins: MutableSet<BrowserOrigin> = initialApprovedOrigins.toMutableSet()
    private val pendingByOrigin = mutableMapOf<BrowserOrigin, MutableList<PendingCertRequest>>()

    private class PendingCertRequest(
        val onProceed: () -> Unit,
        val onCancel: () -> Unit,
    )

    fun isApproved(origin: BrowserOrigin): Boolean = synchronized(lock) { approvedOrigins.contains(origin) }

    fun approve(origin: BrowserOrigin) {
        synchronized(lock) { approvedOrigins.add(origin) }
    }

    /**
     * Enqueues a request waiting for consent for [origin].
     * Returns true if this is the first request for [origin] (meaning UI prompt should be shown).
     * Returns false if a prompt for [origin] is already active.
     */
    fun enqueue(
        origin: BrowserOrigin,
        onProceed: () -> Unit,
        onCancel: () -> Unit,
    ): Boolean =
        synchronized(lock) {
            val pending = pendingByOrigin.getOrPut(origin) { mutableListOf() }
            val isFirst = pending.isEmpty()
            pending.add(PendingCertRequest(onProceed, onCancel))
            isFirst
        }

    /**
     * Completes all pending requests for [origin] with either approval or cancellation.
     * Approval is recorded before any callback runs, so a request arriving for the approved
     * origin meanwhile finds it approved instead of queueing a second prompt behind it.
     */
    fun complete(
        origin: BrowserOrigin,
        approved: Boolean,
    ) {
        val requests =
            synchronized(lock) {
                val pending = pendingByOrigin.remove(origin) ?: return
                if (approved) {
                    approvedOrigins.add(origin)
                }
                pending
            }

        for (request in requests) {
            if (approved) request.onProceed() else request.onCancel()
        }
    }

    /**
     * Cancels all pending requests across all origins (e.g. on close).
     */
    fun cancelAll() {
        val requests =
            synchronized(lock) {
                val pending = pendingByOrigin.values.flatten()
                pendingByOrigin.clear()
                pending
            }

        for (request in requests) {
            request.onCancel()
        }
    }

    fun clear() {
        val requests =
            synchronized(lock) {
                val pending = pendingByOrigin.values.flatten()
                pendingByOrigin.clear()
                approvedOrigins.clear()
                pending
            }

        for (request in requests) {
            request.onCancel()
        }
    }
}
