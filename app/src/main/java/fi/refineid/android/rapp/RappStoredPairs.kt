// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord

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
 * again. A record stored before its peer confirmed storage (RAPP v26.10.21
 * section 4.3 item 4), and a forgotten record that kept its key for 30 days
 * without delivering its close (section 4.6 item 3), is revoked. A storage
 * failure removes nothing.
 */
internal object RappStoredPairs {
    /** Every pairing the user has not forgotten, most recently used first. */
    fun load(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ): List<RappStoredPair> =
        served(catalog, vault).filter { stored ->
            val active = stored.pairing.state == RappPairState.Active
            if (!active) stored.record.close()
            active
        }

    /**
     * Every pairing this phone routes and announces, most recently used
     * first: the active ones and the forgotten ones whose records still wait
     * to deliver the `pairing_revoked` close on their next session (section
     * 4.6 item 2).
     */
    fun served(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ): List<RappStoredPair> =
        catalog
            .allPairs()
            .sortedByDescending { it.lastUsedMs }
            .mapNotNull { peer -> loadOne(peer, catalog, vault) }

    /**
     * Removes every catalogued pairing whose record the core no longer
     * decodes, revokes catalogued records left unconfirmed or past their
     * notice window, and revokes every vault record no catalogue entry
     * names: a ceremony interrupted after it stored its record leaves one
     * behind (section 4.3 item 4).
     */
    fun cleanAtStartup(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ) {
        served(catalog, vault).forEach { it.record.close() }
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
        vault: AndroidRappVault,
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
                record.revocationNoticeExpired(RappClock.wallMs())
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
