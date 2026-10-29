// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.rappStreamProfileName

/** The transport profiles this custodian serves sessions on (RAPP v26.10.29 section 2.2). */
internal enum class RappTransportProfile {
    STREAM,
    BLUETOOTH,
    ;

    /** The registered profile name that routing and the session handshake bind. */
    val profileName: String
        get() =
            when (this) {
                STREAM -> rappStreamProfileName()
                BLUETOOTH -> RappBleGattProfile.PROFILE_NAME
            }
}

/** The connection that carries the session this phone serves. */
internal sealed interface RappServedTransport {
    val profile: RappTransportProfile

    /** The stream listener's one connection. */
    data object Stream : RappServedTransport {
        override val profile: RappTransportProfile = RappTransportProfile.STREAM
    }

    /** One central's GATT link. */
    data class Bluetooth(
        val link: RappBleLink,
    ) : RappServedTransport {
        override val profile: RappTransportProfile = RappTransportProfile.BLUETOOTH
    }
}

/**
 * Whether a dial routed to a pairing may open a session on this phone, which
 * serves one session at a time whatever transport carries it (STPA CC-67).
 *
 * A busy session, one coming up or carrying an operation, is never
 * displaced, so a dial on the other transport never cuts an operation
 * (UCA-66). An idle session is handed over at once to a dial of its own
 * pairing, the same computer coming back on another transport, and to
 * another pairing's dial only once it has idled for [CROSS_PEER_HOLD_MS],
 * so computers do not take the phone from each other between operations.
 */
internal enum class RappSessionAdmission {
    /** No session is open, or the open one is handed over. */
    ADMIT,

    /** The open session is coming up or carries an operation. */
    REFUSE_BUSY,

    /** The open session is another pairing's and has idled less than the hold. */
    REFUSE_HELD,
    ;

    /** Whether the dial gets the session. */
    val admits: Boolean
        get() = this == ADMIT

    companion object {
        /** How long a session must idle before another pairing's dial takes the phone. */
        const val CROSS_PEER_HOLD_MS = 5_000L

        /**
         * The verdict for a dial routed to [incoming] while the open session
         * serves [serving] (null while none is open) and has idled since the
         * monotonic [idleSinceMs] (null while it is coming up or busy).
         */
        fun decide(
            incoming: RappPairId,
            serving: RappPairId?,
            idleSinceMs: Long?,
            nowMs: Long,
        ): RappSessionAdmission =
            when {
                serving == null -> ADMIT
                idleSinceMs == null -> REFUSE_BUSY
                serving == incoming -> ADMIT
                nowMs - idleSinceMs >= CROSS_PEER_HOLD_MS -> ADMIT
                else -> REFUSE_HELD
            }
    }
}

/** Why a dial got no session, for the debug trace. */
internal enum class RappDialRefusal {
    /** Remote Access is off or being withdrawn, or the server that took the dial was replaced. */
    NOT_SERVING,

    /** Within the pre-authentication spacing (RAPP v26.10.29 section 3.3 item 6). */
    RATE_LIMITED,

    /** The preamble named no pairing this phone serves, or was replayed (section 2.2.1). */
    NO_PAIRING,

    /** The open session is coming up or carries an operation (CC-67). */
    BUSY,

    /** The open session is another pairing's and has not idled for the hold. */
    HELD,

    /** The routed link did not complete its handshake in time. */
    HANDSHAKE_DEADLINE,
}
