// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.rappBleSarPayloadCapacity
import java.util.UUID

/** The `fi.refineid.rapp.ble` GATT profile (RAPP v26.10.29 sections 2.2, 5.1 and 5.3). */
internal object RappBleGattProfile {
    /** The registered transport profile name (section 2.2). */
    const val PROFILE_NAME = "fi.refineid.rapp.ble"

    /** The primary service, the one UUID the advertisement carries (sections 4.1, 5.1). */
    val SERVICE_UUID: UUID = UUID.fromString("7E39FD01-A6B5-4D78-9E11-37E28E9545F1")

    /** The channel characteristic: write and indicate (section 5.1). */
    val CHANNEL_UUID: UUID = UUID.fromString("7E39FD02-A6B5-4D78-9E11-37E28E9545F1")

    /** The bootstrap characteristic: read, carrying the pairing offer (section 5.1). */
    val BOOTSTRAP_UUID: UUID = UUID.fromString("7E39FD03-A6B5-4D78-9E11-37E28E9545F1")

    /**
     * The Client Characteristic Configuration descriptor: assigned number
     * 0x2902 on the Bluetooth Base UUID (Bluetooth Core v5.4, Vol 3, Part B,
     * 2.5.1; Part G, 3.3.3.3).
     */
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")

    /** The ATT MTU of an LE link before any exchange (Bluetooth Core v5.4, Vol 3, Part F, 3.2.8). */
    const val DEFAULT_ATT_MTU = 23

    /** The smallest negotiated ATT MTU the profile serves (section 5.2 step 1). */
    const val MINIMUM_ATT_MTU = 512

    /** How long a frame may take to reassemble after its first fragment (section 5.3 item 1). */
    const val REASSEMBLY_TIMEOUT_MS = 5_000L

    /** How long a link the owner closed may still indicate the frames it queued before the close. */
    const val CLOSE_DRAIN_LIMIT_MS = 2_000L
}

/** Octets of a Client Characteristic Configuration value (Bluetooth Core v5.4, Vol 3, Part G, 3.3.3.3). */
private const val CCCD_SIZE = 2

/** The bit of the configuration value that enables indications (same section). */
private const val CCCD_INDICATION_BIT = 1

/** The configuration bit field with nothing enabled. */
private const val CCCD_NOTHING = 0

/**
 * A Client Characteristic Configuration value the channel accepts: disabled
 * or indications (RAPP v26.10.29 section 5.1). The value is a 16-bit
 * little-endian bit field; notifications, or both, are not permitted.
 */
internal enum class RappBleCccd(
    private val bits: Int,
) {
    DISABLED(CCCD_NOTHING),
    INDICATIONS(1 shl CCCD_INDICATION_BIT),
    ;

    /** The value as the descriptor carries it. */
    fun wire(): ByteArray = ByteArray(CCCD_SIZE) { index -> (bits ushr (index * Byte.SIZE_BITS)).toByte() }

    companion object {
        /** The configuration [value] writes, or null for any value the channel does not permit. */
        fun of(value: ByteArray?): RappBleCccd? =
            value?.takeIf { it.size == CCCD_SIZE }?.let { written ->
                entries.firstOrNull { it.wire().contentEquals(written) }
            }
    }
}

/**
 * The SAR fragment payload capacity of one link, which only an ATT MTU of
 * at least 512 has (RAPP v26.10.29 sections 5.2 and 5.3). The engine
 * computes it.
 */
@JvmInline
internal value class RappBleSarCapacity private constructor(
    val bytes: UInt,
) {
    companion object {
        /** The capacity a link of [attMtu] carries, or null below the profile's minimum. */
        fun forAttMtu(attMtu: Int): RappBleSarCapacity? {
            if (attMtu < RappBleGattProfile.DEFAULT_ATT_MTU) return null
            return try {
                RappBleSarCapacity(rappBleSarPayloadCapacity(attMtu.toUInt(), null))
            } catch (_: RappBindingException) {
                null
            }
        }
    }
}
