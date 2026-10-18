// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord

/**
 * Revokes a stored pairing the way RAPP v26.10.18 section 4.6 requires: the
 * core derives and returns the revocation retention before the record's key
 * is destroyed, and the vault keeps the retention for announcement. A record
 * the core no longer decodes is revoked without a retention, since no key
 * can be derived from it.
 */
internal object RappPairRevocation {
    /** Revokes [pairId] in [vault], retaining its revocation when the record still loads. */
    fun revoke(
        pairId: ByteArray,
        vault: AndroidRappVault,
    ) {
        val record =
            try {
                RappPairRecord.loadFromVault(pairId, vault)
            } catch (_: RappBindingException) {
                null
            }
        if (record == null) {
            vault.revokeDeviceOnly(pairId, RappClock.wallMs())
            return
        }
        revoke(record, vault)
    }

    /** Revokes a loaded [record] in [vault] and retains its revocation; closes the record. */
    fun revoke(
        record: RappPairRecord,
        vault: AndroidRappVault,
    ) {
        try {
            record.revoke(vault, RappClock.wallMs())?.let(vault::retainRevocation)
        } catch (_: RappBindingException) {
            vault.revokeDeviceOnly(record.metadata().pairId, RappClock.wallMs())
        } finally {
            record.close()
        }
    }
}
