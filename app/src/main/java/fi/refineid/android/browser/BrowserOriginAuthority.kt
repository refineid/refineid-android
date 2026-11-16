// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

import java.util.Collections

/**
 * Origin-scoped authorization for client-certificate presentation during a browser session.
 * Tracks hosts the holder has explicitly permitted to receive their authentication certificate,
 * and serializes concurrent certificate requests for the same host.
 */
internal class BrowserOriginAuthority(
    initialApprovedHosts: Set<String> = emptySet(),
) {
    private val approvedHosts = Collections.synchronizedSet(initialApprovedHosts.toMutableSet())
    private val lock = Any()
    private val pendingByHost = mutableMapOf<String, MutableList<PendingCertRequest>>()

    private class PendingCertRequest(
        val onProceed: () -> Unit,
        val onCancel: () -> Unit,
    )

    fun isApproved(host: String?): Boolean {
        if (host.isNullOrBlank()) return false
        return approvedHosts.contains(host)
    }

    fun approve(host: String) {
        if (host.isNotBlank()) {
            approvedHosts.add(host)
        }
    }

    /**
     * Enqueues a request waiting for consent for [host].
     * Returns true if this is the first request for [host] (meaning UI prompt should be shown).
     * Returns false if a prompt for [host] is already active.
     */
    fun enqueue(
        host: String,
        onProceed: () -> Unit,
        onCancel: () -> Unit,
    ): Boolean {
        synchronized(lock) {
            val list = pendingByHost.getOrPut(host) { mutableListOf() }
            val isFirst = list.isEmpty()
            list.add(PendingCertRequest(onProceed, onCancel))
            return isFirst
        }
    }

    /**
     * Completes all pending requests for [host] with either approval or cancellation.
     */
    fun complete(
        host: String,
        approved: Boolean,
    ) {
        val requests =
            synchronized(lock) {
                pendingByHost.remove(host)
            } ?: return

        if (approved) {
            approve(host)
            for (req in requests) {
                req.onProceed()
            }
        } else {
            for (req in requests) {
                req.onCancel()
            }
        }
    }

    /**
     * Cancels all pending requests across all hosts (e.g. on close).
     */
    fun cancelAll() {
        val allRequests =
            synchronized(lock) {
                val copy = pendingByHost.values.flatten()
                pendingByHost.clear()
                copy
            }
        for (req in allRequests) {
            req.onCancel()
        }
    }

    fun clear() {
        cancelAll()
        approvedHosts.clear()
    }
}
