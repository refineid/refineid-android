// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappBleSarReassembler
import uniffi.refineid_rapp.rappBleSarSegment

/** One central's link to the GATT server, named by the order links began; it names no device. */
@JvmInline
internal value class RappBleLink(
    val serial: Long,
)

/** Why a link ended. */
internal enum class RappBleLinkFailure {
    /** The central disabled indications or disconnected. */
    DISCONNECTED,

    /** The server's owner closed it. */
    CANCELLED,

    /** The negotiated ATT MTU is below 512 (RAPP v26.10.22 section 5.2 step 1). */
    ATT_MTU_TOO_SMALL,

    /** The routing preamble named no pairing this phone serves now (section 2.2.1). */
    ROUTING_REFUSED,

    /** A fragment broke the SAR rules or its frame timed out (section 5.3). */
    REASSEMBLY_FAILED,

    /** A write the profile does not allow: a write command, a prepared write, or an offset (section 5.2). */
    PROTOCOL_VIOLATION,

    /** The platform refused an indication, or the central did not confirm one. */
    INDICATION_FAILED,

    /** Bluetooth turned off. */
    BLUETOOTH_UNAVAILABLE,
}

/** What the server tells its owner about its links, in the order they happened. */
internal sealed interface RappBleGattEvent {
    /** A central enabled indications; [accepted] is false when [attMtu] is below the profile's minimum. */
    class Subscribed(
        val link: RappBleLink,
        val attMtu: Int,
        val accepted: Boolean,
    ) : RappBleGattEvent

    /** The owner admitted the link's routing preamble. */
    class Routed(
        val link: RappBleLink,
    ) : RappBleGattEvent

    /** One whole frame after the routing preamble. */
    class Frame(
        val link: RappBleLink,
        val frame: ByteArray,
    ) : RappBleGattEvent

    /** The link ended; it refuses writes until its central disables indications. */
    class Closed(
        val link: RappBleLink,
        val failure: RappBleLinkFailure,
    ) : RappBleGattEvent

    /** The central disabled indications or disconnected. */
    class Unsubscribed(
        val link: RappBleLink,
    ) : RappBleGattEvent
}

/** What one channel write yields. */
internal sealed interface RappBleReceipt {
    /** More fragments of the frame are due. */
    data object Partial : RappBleReceipt

    /** The fragment completed [frame]. */
    class Complete(
        val frame: ByteArray,
    ) : RappBleReceipt

    /** The fragment broke the SAR rules; the partial frame is zeroized. */
    data object Refused : RappBleReceipt
}

/**
 * One link's state: whether it serves, its reassembly and its queue of
 * fragments to indicate (RAPP v26.10.22 sections 5.2 and 5.3).
 *
 * A link without a capacity, because its ATT MTU is below the minimum,
 * starts closed. Confined to the server's lane.
 */
internal class RappBleLinkState(
    val link: RappBleLink,
    private val capacity: RappBleSarCapacity?,
) : AutoCloseable {
    /** Where the link stands. */
    enum class Phase {
        /** Takes writes and indicates frames. */
        OPEN,

        /** Indicates the frames queued before its owner closed it; takes no writes. */
        CLOSING,

        /** Takes no writes and indicates nothing. */
        CLOSED,
    }

    var phase: Phase = if (capacity != null) Phase.OPEN else Phase.CLOSED
        private set

    /** Whether the owner admitted the link's routing preamble. */
    var routed: Boolean = false

    private val reassembler = RappBleSarReassembler()
    private val outbound = ArrayDeque<ByteArray>()

    /** Whether no fragment waits to be indicated. */
    val drained: Boolean
        get() = outbound.isEmpty()

    /** Takes one written fragment at the monotonic [nowMs]. */
    fun receive(
        fragment: ByteArray,
        nowMs: ULong,
    ): RappBleReceipt {
        val capacity = capacity ?: return RappBleReceipt.Refused
        return try {
            reassembler.receive(fragment, capacity.bytes, nowMs)?.let { RappBleReceipt.Complete(it) }
                ?: RappBleReceipt.Partial
        } catch (_: RappBindingException) {
            RappBleReceipt.Refused
        }
    }

    /** Whether a frame under reassembly has passed its deadline at [nowMs]. */
    fun reassemblyExpired(nowMs: ULong): Boolean =
        try {
            reassembler.checkTimer(nowMs)
            false
        } catch (_: RappBindingException) {
            true
        }

    /** Queues the fragments that carry [frame]; false when the engine cannot segment it. */
    fun enqueue(frame: ByteArray): Boolean {
        val capacity = capacity ?: return false
        val fragments =
            try {
                rappBleSarSegment(frame, capacity.bytes)
            } catch (_: RappBindingException) {
                return false
            }
        outbound.addAll(fragments)
        return true
    }

    /** The next fragment to indicate, if any. */
    fun nextFragment(): ByteArray? = outbound.removeFirstOrNull()

    /** Indicates what is queued, then ends. */
    fun beginClosing() {
        if (phase == Phase.OPEN) phase = Phase.CLOSING
    }

    /** Ends the link: the partial frame is zeroized and the queue dropped. */
    fun end() {
        phase = Phase.CLOSED
        routed = false
        outbound.clear()
        try {
            reassembler.reset()
        } catch (_: RappBindingException) {
            // A poisoned lock leaves nothing to reset; close() releases it.
        }
    }

    override fun close() {
        end()
        reassembler.close()
    }
}
