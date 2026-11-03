// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridgeInterface
import uniffi.refineid_rapp.RappPeerHello
import uniffi.refineid_rapp.rappPairingBusyRetryAfterMs

/**
 * Whether [frame] answers a pairing connection with `pairing-busy`: the
 * bootstrap answer, or the frame in place of CPace step 2 on the stream
 * transport (RAPP v26.11.2 section 4.2, "Busy Refusal").
 */
internal fun isPairingBusy(frame: ByteArray): Boolean =
    try {
        rappPairingBusyRetryAfterMs(frame)
        true
    } catch (_: RappBindingException) {
        false
    }

/**
 * The requester's side of one pairing ceremony over one connected
 * candidate, after the offer bootstrap, in the order RAPP v26.11.2
 * sections 4.3 and 6.1.3 fix:
 *
 * 1. send the requester's Y_A, read Y_B and T_B, which verifies the
 *    custodian holds the code;
 * 2. send T_A and Noise message 1, read message 2;
 * 3. send message 3 and enter the authenticated pairing channel;
 * 4. send this hello, read the custodian's hello;
 * 5. read the custodian's grant, echo it, store the unconfirmed record
 *    through [persistUnconfirmed], and answer with this side's
 *    `pairing.stored`;
 * 6. read the custodian's `pairing.stored` and activate the pairing, which
 *    yields the confirmed record the caller stores over the unconfirmed one.
 *
 * The class holds no Android types, so the whole ceremony runs against a
 * custodian bridge in a JVM test. The bridge rejects any frame out of this
 * order; a rejection ends the ceremony. A wrong code fails at step 1, which
 * the caller reports through the search ledger; any later failure ends the
 * whole search. A ceremony that ends after step 5 without reaching step 6
 * leaves [storedRecord] for the caller to revoke.
 */
internal class RappRequesterPairingCeremony(
    private val bridge: RappPairingBridgeInterface,
    private val pairingCode: String,
    private val candidateId: String,
    private val displayName: RappDisplayName,
    private val platform: String,
    private val monotonicMs: () -> ULong,
    private val wallMs: () -> ULong,
    private val random64: () -> ByteArray,
    private val persistUnconfirmed: (RappPairRecord) -> Unit,
) {
    /** The next frame this requester expects. */
    enum class Step {
        AWAITING_STEP_TWO,
        AWAITING_HANDSHAKE_TWO,
        AWAITING_PEER_HELLO,
        AWAITING_CONFIRMATION,
        AWAITING_STORED,
        COMPLETED,
    }

    /** What the caller does after one received frame. */
    sealed interface Outcome {
        /** Send these frames, in order, then wait for the next frame. */
        data class Send(
            val frames: List<ByteArray>,
        ) : Outcome

        /**
         * The ceremony completed; [record] is the confirmed record, which the
         * caller stores over the unconfirmed one.
         */
        data class Paired(
            val record: RappPairRecord,
            val peer: RappPeerHello,
        ) : Outcome
    }

    var step: Step = Step.AWAITING_STEP_TWO
        private set

    private var peer: RappPeerHello? = null

    /**
     * The unconfirmed record this side stored and announced with
     * `pairing.stored`, until the custodian's confirmation activates it.
     * Null before step 5 and after step 6.
     */
    var storedRecord: RappPairRecord? = null
        private set

    /**
     * Whether T_B verified, so the custodian proved it holds the code and a
     * later failure ends the search instead of trying the next custodian.
     */
    val isPastOfferPhase: Boolean
        get() = step != Step.AWAITING_STEP_TWO

    /**
     * Starts CPace with the typed code and returns the step 1 frame to
     * send.
     *
     * @throws uniffi.refineid_rapp.RappBindingException when the bridge
     *   rejects the code or the offer is gone.
     */
    fun start(): ByteArray {
        val now = monotonicMs()
        val random = random64()
        try {
            bridge.beginCpace(candidateId, pairingCode, random, now)
        } finally {
            random.fill(0)
        }
        return bridge.writeCpaceFrame(now)
    }

    /**
     * Consumes one frame from the custodian.
     *
     * @throws uniffi.refineid_rapp.RappBindingException when the bridge
     *   rejects the frame, including a wrong code, an expired offer, a frame
     *   out of order, or a `pairing.stored` naming another pairing.
     */
    fun receive(frame: ByteArray): Outcome {
        val now = monotonicMs()
        return when (step) {
            Step.AWAITING_STEP_TWO -> {
                bridge.readCpaceFrame(frame, now)
                val stepThree = bridge.writeCpaceFrame(now)
                val handshakeOne = bridge.writeHandshakeFrame(now)
                step = Step.AWAITING_HANDSHAKE_TWO
                Outcome.Send(listOf(stepThree, handshakeOne))
            }

            Step.AWAITING_HANDSHAKE_TWO -> {
                bridge.readHandshakeFrame(frame, now)
                val handshakeThree = bridge.writeHandshakeFrame(now)
                check(bridge.handshakeComplete(now)) { "handshake incomplete after message 3" }
                bridge.enterConfirmation(now)
                val ownHello =
                    bridge.sendHello(displayName = displayName.text, platform = platform, nowMonotonicMs = now)
                step = Step.AWAITING_PEER_HELLO
                Outcome.Send(listOf(handshakeThree, ownHello))
            }

            Step.AWAITING_PEER_HELLO -> {
                peer = bridge.receiveHello(frame, now)
                step = Step.AWAITING_CONFIRMATION
                Outcome.Send(emptyList())
            }

            Step.AWAITING_CONFIRMATION -> {
                val granted = bridge.receiveConfirmation(frame, now)
                val echo = bridge.sendConfirmation(granted, now)
                val unconfirmed = bridge.buildPairRecord(wallMs(), now)
                persistUnconfirmed(unconfirmed)
                storedRecord = unconfirmed
                val stored = bridge.sendStored(now)
                step = Step.AWAITING_STORED
                Outcome.Send(listOf(echo, stored))
            }

            Step.AWAITING_STORED -> {
                bridge.receiveStored(frame, now)
                val confirmed =
                    checkNotNull(bridge.activatePairing(now)) { "both storage confirmations exchanged" }
                storedRecord?.close()
                storedRecord = null
                step = Step.COMPLETED
                Outcome.Paired(confirmed, checkNotNull(peer))
            }

            Step.COMPLETED -> {
                error("pairing ceremony already completed")
            }
        }
    }
}
