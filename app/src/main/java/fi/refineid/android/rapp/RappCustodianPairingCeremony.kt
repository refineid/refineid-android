// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridgeInterface
import uniffi.refineid_rapp.RappPeerHello

/**
 * The custodian's side of one pairing ceremony over one connected candidate,
 * after the offer bootstrap, in the order RAPP v26.10.18 sections 4.3 and
 * 6.1.3 fix:
 *
 * 1. read the requester's Y_A, answer with Y_B and T_B;
 * 2. read T_A, which consumes the offer and starts Noise_XXpsk3;
 * 3. read Noise message 1, answer with message 2;
 * 4. read message 3 and enter the authenticated pairing channel;
 * 5. read the requester's hello, answer with this hello and the grant;
 * 6. read the requester's echo of the grant, store the unconfirmed record
 *    through [persistUnconfirmed], and answer with this side's
 *    `pairing.stored`;
 * 7. read the requester's `pairing.stored` and activate the pairing, which
 *    yields the confirmed record the caller stores over the unconfirmed one.
 *
 * The class holds no Android types, so the whole ceremony runs against a
 * requester bridge in a JVM test. The bridge rejects any frame out of this
 * order; a rejection ends the ceremony. A ceremony that ends after step 6
 * without reaching step 7 leaves [storedRecord] for the caller to revoke.
 */
internal class RappCustodianPairingCeremony(
    private val bridge: RappPairingBridgeInterface,
    private val offeredProfiles: List<String>,
    private val displayName: String,
    private val platform: String,
    private val monotonicMs: () -> ULong,
    private val wallMs: () -> ULong,
    private val persistUnconfirmed: (RappPairRecord) -> Unit,
) {
    /** The next frame this custodian expects. */
    enum class Step {
        AWAITING_STEP_ONE,
        AWAITING_STEP_THREE,
        AWAITING_HANDSHAKE_ONE,
        AWAITING_HANDSHAKE_THREE,
        AWAITING_HELLO,
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

    var step: Step = Step.AWAITING_STEP_ONE
        private set

    private var peer: RappPeerHello? = null

    /**
     * The unconfirmed record this side stored and announced with
     * `pairing.stored`, until the requester's confirmation activates it.
     * Null before step 6 and after step 7.
     */
    var storedRecord: RappPairRecord? = null
        private set

    /**
     * Whether T_A verified and consumed the offer, so a lost peer fails the
     * ceremony instead of returning the candidate to the offer.
     */
    val isPastOfferPhase: Boolean
        get() = step != Step.AWAITING_STEP_ONE && step != Step.AWAITING_STEP_THREE

    /**
     * Consumes one frame from the requester.
     *
     * @throws uniffi.refineid_rapp.RappBindingException when the bridge
     *   rejects the frame, including a wrong code, an expired offer, a frame
     *   out of order, or a `pairing.stored` naming another pairing.
     */
    fun receive(frame: ByteArray): Outcome {
        val now = monotonicMs()
        return when (step) {
            Step.AWAITING_STEP_ONE -> {
                bridge.readCpaceFrame(frame, now)
                val stepTwo = bridge.writeCpaceFrame(now)
                step = Step.AWAITING_STEP_THREE
                Outcome.Send(listOf(stepTwo))
            }

            Step.AWAITING_STEP_THREE -> {
                bridge.readCpaceFrame(frame, now)
                step = Step.AWAITING_HANDSHAKE_ONE
                Outcome.Send(emptyList())
            }

            Step.AWAITING_HANDSHAKE_ONE -> {
                bridge.readHandshakeFrame(frame, now)
                val handshakeTwo = bridge.writeHandshakeFrame(now)
                step = Step.AWAITING_HANDSHAKE_THREE
                Outcome.Send(listOf(handshakeTwo))
            }

            Step.AWAITING_HANDSHAKE_THREE -> {
                bridge.readHandshakeFrame(frame, now)
                check(bridge.handshakeComplete(now)) { "handshake incomplete after message 3" }
                bridge.enterConfirmation(now)
                step = Step.AWAITING_HELLO
                Outcome.Send(emptyList())
            }

            Step.AWAITING_HELLO -> {
                val hello = bridge.receiveHello(frame, now)
                peer = hello
                val requested = hello.requestedProfiles.orEmpty()
                val granted = offeredProfiles.filter { it in requested }
                val ownHello = bridge.sendHello(displayName = displayName, platform = platform, nowMonotonicMs = now)
                val grant = bridge.sendConfirmation(granted, now)
                step = Step.AWAITING_CONFIRMATION
                Outcome.Send(listOf(ownHello, grant))
            }

            Step.AWAITING_CONFIRMATION -> {
                bridge.receiveConfirmation(frame, now)
                val unconfirmed = bridge.buildPairRecord(wallMs(), now)
                persistUnconfirmed(unconfirmed)
                storedRecord = unconfirmed
                val stored = bridge.sendStored(now)
                step = Step.AWAITING_STORED
                Outcome.Send(listOf(stored))
            }

            Step.AWAITING_STORED -> {
                bridge.receiveStored(frame, now)
                val confirmed =
                    checkNotNull(bridge.activatePairing(now)) { "both storage confirmations exchanged" }
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
