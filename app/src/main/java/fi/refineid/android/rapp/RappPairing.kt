// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairMetadata
import uniffi.refineid_rapp.RappPairRecord

/**
 * A pair identifier: the first 16 bytes of the SHA-512 digest that names a
 * pairing (RAPP v26.10.29 section 4.3 item 2).
 */
internal class RappPairId private constructor(
    private val bytes: ByteArray,
) {
    /** Lowercase hexadecimal: the pairing's key in the catalog. */
    @OptIn(ExperimentalStdlibApi::class)
    val key: String
        get() = bytes.toHexString()

    /** The identifier as the binding and the vault take it. */
    fun toWire(): ByteArray = bytes.copyOf()

    override fun equals(other: Any?): Boolean = other is RappPairId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "RappPairId($key)"

    companion object {
        /** Bytes of a pair identifier (section 4.3 item 2). */
        const val SIZE = 16

        /** The identifier the binding reported, or null when it is not an identifier's size. */
        fun fromWire(wire: ByteArray): RappPairId? = if (wire.size == SIZE) RappPairId(wire.copyOf()) else null

        /** The identifier a catalog [key] names, or null when the key is not one identifier in hexadecimal. */
        @OptIn(ExperimentalStdlibApi::class)
        fun fromKey(key: String): RappPairId? =
            try {
                fromWire(key.hexToByteArray())
            } catch (_: IllegalArgumentException) {
                null
            }
    }
}

/** Where a stored pairing stands (RAPP v26.10.29 sections 4.3 and 4.6). */
internal sealed interface RappPairState {
    /** Stored before the peer confirmed storing its own; it serves nothing (section 4.3 item 4). */
    data object Unconfirmed : RappPairState

    /** Confirmed by both endpoints and serving. */
    data object Active : RappPairState

    /**
     * The local user forgot it at [atMs], milliseconds since the Unix epoch;
     * it serves nothing and waits to deliver the `pairing_revoked` close
     * (section 4.6 item 2).
     */
    class Forgotten(
        val atMs: Long,
    ) : RappPairState
}

/** A stored pairing as this app consults it: its identifier, this phone's role, and its state. */
internal class RappPairing private constructor(
    val id: RappPairId,
    val role: RappEndpointRole,
    val state: RappPairState,
) {
    companion object {
        /**
         * The pairing [metadata] describes. Fails on a malformed identifier,
         * or on an unconfirmed record marked forgotten, which the core never
         * produces.
         */
        fun of(metadata: RappPairMetadata): RappPairing {
            val forgottenAtMs = metadata.forgottenAtMs
            val state =
                when {
                    !metadata.storageConfirmed -> {
                        check(forgottenAtMs == null)
                        RappPairState.Unconfirmed
                    }

                    forgottenAtMs != null -> {
                        RappPairState.Forgotten(forgottenAtMs.toLong())
                    }

                    else -> {
                        RappPairState.Active
                    }
                }
            return RappPairing(checkNotNull(RappPairId.fromWire(metadata.pairId)), metadata.role, state)
        }
    }
}

/** This record's pairing, read through the one border that types its metadata. */
internal fun RappPairRecord.pairing(): RappPairing = RappPairing.of(metadata())
