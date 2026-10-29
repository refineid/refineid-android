// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBridgeInterface
import uniffi.refineid_rapp.RappPreAuthenticationLimiterInterface
import uniffi.refineid_rapp.rappPairingBusyRetryAfterMs
import uniffi.refineid_rapp.rappPairingPreamble

/**
 * The custodian's answer to a pairing connection on one transport (RAPP
 * v26.10.29 section 3.3 item 6; section 4.2, "Bootstrap Read Flow" and
 * "Busy Refusal").
 *
 * The connection's routing preamble is read first, and only a pairing
 * preamble for [profileName] is answered. The connection-accept [limiter]
 * applies next: a connection it refuses is answered with `pairing-busy`
 * carrying the larger of the limiter's wait and the offer's own. An
 * admitted connection gets the offer's bootstrap answer, which is itself
 * `pairing-busy` while an attempt holds the offer or its spacing has not
 * passed. A busy answer admits nothing and evaluates no code material; the
 * caller sends it and closes the connection, and shows the holder nothing.
 * Without a live offer every connection is closed unanswered.
 */
internal class RappPairingBootstrap(
    private val bridge: RappPairingBridgeInterface,
    private val limiter: RappPreAuthenticationLimiterInterface,
    profileName: String,
) {
    /** What the custodian does with a pairing connection. */
    sealed interface Answer {
        /** Close the connection unanswered. */
        data object Close : Answer

        /** Send [frame], the `pairing-offer`, and begin CPace. */
        class Offer(
            val frame: ByteArray,
        ) : Answer

        /** Send [frame], a `pairing-busy`, and close the connection. */
        class Busy(
            val frame: ByteArray,
        ) : Answer
    }

    private companion object {
        /** The wait added to the offer's own when no platform limiter refused the connection. */
        const val NO_PLATFORM_WAIT_MS = 0UL
    }

    private val pairingPreamble = rappPairingPreamble(profileName)

    /** The first frame of a connection that holds the transport: the offer or a busy answer. */
    fun answer(
        preamble: ByteArray,
        nowMonotonicMs: ULong,
    ): Answer =
        closingWithoutOffer {
            when {
                !preamble.contentEquals(pairingPreamble) -> Answer.Close
                !limiter.admit(nowMonotonicMs) -> busy(nowMonotonicMs, limiter.waitMs(nowMonotonicMs))
                else -> bootstrap(bridge.bootstrapBytes(nowMonotonicMs))
            }
        }

    /**
     * The answer to a pairing connection that arrives while another
     * connection holds the transport: always busy, since only the holding
     * connection runs an attempt. It does not count against the limiter.
     */
    fun answerWhileHeld(
        preamble: ByteArray,
        nowMonotonicMs: ULong,
    ): Answer =
        closingWithoutOffer {
            if (preamble.contentEquals(pairingPreamble)) {
                busy(nowMonotonicMs, limiter.waitMs(nowMonotonicMs))
            } else {
                Answer.Close
            }
        }

    /**
     * The answer in place of CPace step 2 on a connection whose CPace start
     * the offer refused with `RateLimited` or `WrongPhase`.
     */
    fun answerInPlaceOfStepTwo(nowMonotonicMs: ULong): Answer =
        closingWithoutOffer { busy(nowMonotonicMs, NO_PLATFORM_WAIT_MS) }

    private fun busy(
        nowMonotonicMs: ULong,
        platformWaitMs: ULong,
    ): Answer = Answer.Busy(bridge.busyBytes(nowMonotonicMs, platformWaitMs))

    private fun bootstrap(frame: ByteArray): Answer = if (isBusy(frame)) Answer.Busy(frame) else Answer.Offer(frame)

    private fun isBusy(frame: ByteArray): Boolean =
        try {
            rappPairingBusyRetryAfterMs(frame)
            true
        } catch (_: RappBindingException) {
            false
        }

    private inline fun closingWithoutOffer(answer: () -> Answer): Answer =
        try {
            answer()
        } catch (_: RappBindingException) {
            Answer.Close
        }
}
