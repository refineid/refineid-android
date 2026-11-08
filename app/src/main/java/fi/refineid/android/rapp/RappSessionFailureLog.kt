// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappRequesterSessionEnd

/**
 * One dev-log line for a failed or closed RAPP session: the cause, the
 * paired device it belonged to, and the transport that carried it, as in
 * `session closed: handshake protocol failure, macOS - pk-mac, Bluetooth`.
 *
 * The name is the pair record's `peer_display_name` (RAPP v26.11.2 section
 * 4.3 items 3 and 4), refreshed every session: a device label (host name or
 * phone model), never the card holder's name. No new protocol or record
 * field is added; the routing tag in the preamble already names the pairing
 * before the handshake, so even a handshake failure has a pair record. When
 * the record cannot be read, the line says [UNKNOWN_PAIRING].
 */
internal object RappSessionFailureLog {
    /** Reported where the pair record cannot be read. */
    const val UNKNOWN_PAIRING = "unknown pairing"

    /** Reported for the stream transport. */
    const val NETWORK_TRANSPORT = "network"

    /** Reported for the Bluetooth transport. */
    const val BLUETOOTH_TRANSPORT = "Bluetooth"

    /** The handshake did not complete or authenticate. */
    const val HANDSHAKE_PROTOCOL_FAILURE = "handshake protocol failure"

    /** A frame failed authentication, or an authenticated close says so. */
    const val PROTOCOL_VIOLATION = "protocol violation"

    /** The transport went away under the session. */
    const val TRANSPORT_CLOSED = "transport closed"

    /** The session bridge could not begin after the dial was admitted. */
    const val SESSION_OPEN_FAILED = "session open failed"

    /** An idle session gave way to a new dial. */
    const val SUPERSEDED = "superseded by new session"

    /** A dial reached its bound without opening a session. */
    const val DIAL_TIMED_OUT = "dial timed out"

    /** The label logged for [profile]. */
    fun transportLabel(profile: RappTransportProfile): String =
        when (profile) {
            RappTransportProfile.STREAM -> NETWORK_TRANSPORT
            RappTransportProfile.BLUETOOTH -> BLUETOOTH_TRANSPORT
        }

    /**
     * The peer label [record] stores, or [UNKNOWN_PAIRING] when there is no
     * record, it cannot be read, or it holds no name.
     */
    fun peerName(record: RappPairRecord?): String {
        if (record == null) return UNKNOWN_PAIRING
        return try {
            record.metadata().peerDisplayName.ifBlank { UNKNOWN_PAIRING }
        } catch (_: Exception) {
            UNKNOWN_PAIRING
        }
    }

    /** A peer's authenticated close carries [reason]. */
    fun peerClose(reason: RappCloseReason): String = "peer close: $reason"

    /** The session ended as [end] says (RAPP v26.11.2 section 4.5 item 6). */
    fun sessionEnd(end: RappRequesterSessionEnd): String = "session end: $end"

    /** The full line: cause, peer, and transport. */
    fun line(
        cause: String,
        peer: String,
        transport: String,
    ): String = "session closed: $cause, $peer, $transport"

    /** The full line for the session [record] routed on [profile]. */
    fun line(
        cause: String,
        record: RappPairRecord?,
        profile: RappTransportProfile,
    ): String = line(cause, peerName(record), transportLabel(profile))
}
