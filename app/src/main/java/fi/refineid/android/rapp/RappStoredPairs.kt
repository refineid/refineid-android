// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.diagnostics.AppTrace
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault

/** A catalogued pairing with its decoded record and the typed view of that record. */
internal class RappStoredPair(
    val peer: PairedPeer,
    val record: RappPairRecord,
    val pairing: RappPairing,
)

/**
 * The catalogued pairings whose records the core decodes and confirms.
 *
 * A record in a format the core does not decode, or one the vault no longer
 * holds, is removed from the catalog and the vault, so its device pairs
 * again. A record stored before its peer confirmed storage (RAPP v26.10.22
 * section 4.3 item 4) is revoked. A forgotten record whose close has not
 * reached its peer within 30 days of the forgetting (section 4.6 item 3) is
 * revoked too, by every load: the start, each routed connection, each
 * discovery-hint window and each change of the pairings rebuild the served
 * set, so a record past its window neither routes nor stays announced. A
 * storage failure removes nothing. The start also sweeps every pairing for
 * idle expiry ([RappIdleExpiry]).
 */
internal object RappStoredPairs {
    /**
     * Every pairing this phone routes and announces, most recently used
     * first: the active ones and the forgotten ones whose records still wait
     * to deliver the `pairing_revoked` close on their next session (section
     * 4.6 item 2), judged at [wallMs], milliseconds since the Unix epoch.
     */
    fun served(
        catalog: RappPairCatalog,
        vault: RappPairVault,
        wallMs: () -> ULong = RappClock::wallMs,
    ): List<RappStoredPair> =
        catalog
            .allPairs()
            .sortedByDescending { it.lastUsedMs }
            .mapNotNull { peer -> loadOne(peer, catalog, vault, wallMs) }

    /**
     * Removes every catalogued pairing whose record the core no longer
     * decodes, revokes catalogued records left unconfirmed or past their
     * notice window, sweeps the others for idle expiry with no session open
     * (section 4.6 item 5), and revokes every vault record no catalogue
     * entry names: a ceremony interrupted after it stored its record leaves
     * one behind (section 4.3 item 4).
     */
    fun cleanAtStartup(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ) {
        RappIdleExpiry.sweep(catalog, vault, RappClock.wallMs(), session = null)
        val catalogued = catalog.allPairs().map { it.pairIdHex }
        for (pairIdHex in orphanPairIds(vault.storedPairIds, catalogued)) {
            val pairId = RappPairId.fromKey(pairIdHex) ?: continue
            RappPairRevocation.revoke(pairId, vault)
        }
    }

    /** The stored record identifiers that no catalogue entry names. */
    internal fun orphanPairIds(
        stored: Collection<String>,
        catalogued: Collection<String>,
    ): List<String> {
        val named = catalogued.mapTo(HashSet()) { it.lowercase() }
        return stored.filterNot { it.lowercase() in named }
    }

    private fun loadOne(
        peer: PairedPeer,
        catalog: RappPairCatalog,
        vault: RappPairVault,
        wallMs: () -> ULong,
    ): RappStoredPair? {
        val pairId = RappPairId.fromKey(peer.pairIdHex)
        if (pairId == null) {
            catalog.removePair(peer.pairIdHex)
            return null
        }
        val record =
            try {
                RappPairRecord.loadFromVault(pairId.toWire(), vault)
            } catch (_: RappBindingException.InvalidInput) {
                AppTrace.rappPairRecordRefused()
                vault.revokeDeviceOnly(pairId.toWire(), RappClock.wallMs())
                catalog.removePair(peer.pairIdHex)
                return null
            } catch (_: RappBindingException.PairNotFound) {
                catalog.removePair(peer.pairIdHex)
                return null
            } catch (_: RappBindingException) {
                return null
            }
        val pairing =
            try {
                record.pairing()
            } catch (_: Exception) {
                record.close()
                return null
            }
        val expired =
            try {
                record.revocationNoticeExpired(wallMs())
            } catch (_: RappBindingException) {
                false
            }
        val state = pairing.state
        if (state == RappPairState.Unconfirmed || expired) {
            RappPairRevocation.revoke(pairing.id, record, vault)
            catalog.removePair(peer.pairIdHex)
            return null
        }
        if (state is RappPairState.Forgotten && peer.forgottenAtMs == null) {
            catalog.markForgotten(peer.pairIdHex, state.atMs)
        }
        return RappStoredPair(peer, record, pairing)
    }
}
