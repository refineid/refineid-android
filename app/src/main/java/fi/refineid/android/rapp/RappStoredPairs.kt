// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord

/**
 * The catalogued pairings whose records the core decodes.
 *
 * A record in a format the core does not decode, or one the vault no longer
 * holds, is removed from the catalog and the vault, so its device pairs
 * again. A storage failure removes nothing.
 */
internal object RappStoredPairs {
    /** Every catalogued pairing with its decoded record, most recently used first. */
    fun load(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ): List<Pair<PairedPeer, RappPairRecord>> =
        catalog
            .listPairs()
            .sortedByDescending { it.lastUsedMs }
            .mapNotNull { peer -> loadOne(peer, catalog, vault)?.let { peer to it } }

    /** Removes every catalogued pairing whose record the core no longer decodes. */
    fun dropUndecodable(
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ) {
        catalog.listPairs().forEach { peer -> loadOne(peer, catalog, vault)?.close() }
    }

    private fun loadOne(
        peer: PairedPeer,
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ): RappPairRecord? {
        val pairId = RappPairingModel.decodeHexOrNull(peer.pairIdHex)
        if (pairId == null) {
            catalog.removePair(peer.pairIdHex)
            return null
        }
        return try {
            RappPairRecord.loadFromVault(pairId, vault)
        } catch (_: RappBindingException.InvalidInput) {
            vault.revokeDeviceOnly(pairId, RappClock.wallMs())
            catalog.removePair(peer.pairIdHex)
            null
        } catch (_: RappBindingException.PairNotFound) {
            catalog.removePair(peer.pairIdHex)
            null
        } catch (_: RappBindingException) {
            null
        }
    }
}
