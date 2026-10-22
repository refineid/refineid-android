// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappPairVault
import java.util.concurrent.ConcurrentHashMap

/** A pair vault in memory with revocation tombstones, for bridge tests. */
@OptIn(ExperimentalStdlibApi::class)
internal class RappMemoryVault : RappPairVault {
    private val pairs = ConcurrentHashMap<String, ByteArray>()
    private val revoked = ConcurrentHashMap<String, ULong>()

    override fun insertDeviceOnly(
        pairId: ByteArray,
        record: ByteArray,
    ) {
        pairs[pairId.toHexString()] = record.copyOf()
    }

    override fun replaceDeviceOnly(
        pairId: ByteArray,
        record: ByteArray,
    ) {
        pairs[pairId.toHexString()] = record.copyOf()
    }

    override fun loadDeviceOnly(pairId: ByteArray): ByteArray? = pairs[pairId.toHexString()]?.copyOf()

    override fun revokeDeviceOnly(
        pairId: ByteArray,
        revokedAtMs: ULong,
    ) {
        pairs.remove(pairId.toHexString())
        revoked[pairId.toHexString()] = revokedAtMs
    }

    override fun isRevoked(pairId: ByteArray): Boolean = revoked.containsKey(pairId.toHexString())
}
