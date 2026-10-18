// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord

/**
 * The catalogued pairings whose records the core decodes and confirms.
 *
 * A record in a format the core does not decode, or one the vault no longer
 * holds, is removed from the catalog and the vault, so its device pairs
 * again. A record stored before its peer confirmed storage (RAPP v26.10.18
 * section 4.3 item 4) is revoked and its revocation retained for
 * announcement. A storage failure removes nothing.
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

    /** Revokes a record whose peer never confirmed storage; the retention is kept to announce it. */
    private fun revokeUnconfirmed(
        record: RappPairRecord,
        peer: PairedPeer,
        catalog: RappPairCatalog,
        vault: AndroidRappVault,
    ) {
        try {
            record.revoke(vault, RappClock.wallMs())?.let(vault::retainRevocation)
        } catch (_: RappBindingException) {
        } finally {
            record.close()
        }
        catalog.removePair(peer.pairIdHex)
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
            val record = RappPairRecord.loadFromVault(pairId, vault)
            if (record.metadata().storageConfirmed) {
                record
            } else {
                revokeUnconfirmed(record, peer, catalog, vault)
                null
            }
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
