// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappForgetOutcome
import uniffi.refineid_rapp.RappPairRecord

/**
 * Forgets and revokes stored pairings the way RAPP v26.10.21 section 4.6
 * requires. Forgetting with no session to the peer open keeps the record's
 * key only to deliver the `pairing_revoked` close on the next session;
 * revoking destroys the key at once. A record the core no longer decodes is
 * revoked through the vault, since it can serve nothing.
 */
internal object RappPairRevocation {
    /** Destroys the record of [pairId] in [vault] at once. */
    fun revoke(
        pairId: RappPairId,
        vault: AndroidRappVault,
    ) {
        val record = load(pairId, vault)
        if (record == null) {
            vault.revokeDeviceOnly(pairId.toWire(), RappClock.wallMs())
            return
        }
        revoke(pairId, record, vault)
    }

    /** Destroys a loaded [record] of [pairId] in [vault] at once and closes it. */
    fun revoke(
        pairId: RappPairId,
        record: RappPairRecord,
        vault: AndroidRappVault,
    ) {
        try {
            record.revoke(vault, RappClock.wallMs())
        } catch (_: RappBindingException) {
            vault.revokeDeviceOnly(pairId.toWire(), RappClock.wallMs())
        } finally {
            record.close()
        }
    }

    /**
     * The local user forgets [pairId] while no session to its peer is open.
     * Returns true when the record now waits to deliver the close, and false
     * when it was destroyed: one the peer never confirmed, or one that no
     * longer loads.
     */
    fun forget(
        pairId: RappPairId,
        vault: AndroidRappVault,
    ): Boolean {
        val record = load(pairId, vault)
        if (record == null) {
            vault.revokeDeviceOnly(pairId.toWire(), RappClock.wallMs())
            return false
        }
        return try {
            record.forget(vault, RappClock.wallMs()) == RappForgetOutcome.NOTICE_PENDING
        } catch (_: RappBindingException) {
            vault.revokeDeviceOnly(pairId.toWire(), RappClock.wallMs())
            false
        } finally {
            record.close()
        }
    }

    private fun load(
        pairId: RappPairId,
        vault: AndroidRappVault,
    ): RappPairRecord? =
        try {
            RappPairRecord.loadFromVault(pairId.toWire(), vault)
        } catch (_: RappBindingException) {
            null
        }
}
