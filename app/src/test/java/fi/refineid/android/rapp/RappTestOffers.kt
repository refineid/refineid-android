// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridge
import java.security.SecureRandom

/**
 * Builds the two bridges of one pairing the way RAPP v26.10.10 section 4.2
 * does: the custodian creates a random offer, and the requester decodes the
 * bootstrap bytes the custodian serves over the stream transport.
 */
internal object RappTestOffers {
    const val STREAM_PROFILE = "fi.refineid.stream.v1"
    const val STREAM_CANDIDATE_ID = "stream-1"
    private const val OFFER_ID_BYTES = 32
    private const val CPACE_RANDOM_BYTES = 64
    private const val WALL_MS = 1_700_000_000_000UL

    /** The custodian bridge and a requester bridge built from its bootstrap. */
    fun custodianAndRequester(
        profiles: List<String>,
        startedAtMonotonicMs: ULong,
    ): Pair<RappPairingBridge, RappPairingBridge> {
        val offerId = ByteArray(OFFER_ID_BYTES).also { SecureRandom().nextBytes(it) }
        val custodian =
            RappPairingBridge.createCustodianOffer(offerId, profiles, listOf(STREAM_PROFILE), startedAtMonotonicMs)
        val requester =
            RappPairingBridge.fromBootstrap(
                custodian.bootstrapBytes(startedAtMonotonicMs),
                STREAM_PROFILE,
                startedAtMonotonicMs,
            )
        return custodian to requester
    }

    private fun random(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    /** A completed pairing: the requester's record and the custodian's. */
    fun pairRecords(
        profiles: List<String>,
        now: ULong,
    ): Pair<RappPairRecord, RappPairRecord> {
        val code = RappPairingCode.generate()
        val (custodian, requester) = custodianAndRequester(profiles, now)
        requester.beginCpace(STREAM_CANDIDATE_ID, code, random(CPACE_RANDOM_BYTES), now)
        custodian.beginCpace(STREAM_CANDIDATE_ID, code, random(CPACE_RANDOM_BYTES), now)
        custodian.readCpaceFrame(requester.writeCpaceFrame(now), now)
        requester.readCpaceFrame(custodian.writeCpaceFrame(now), now)
        custodian.readCpaceFrame(requester.writeCpaceFrame(now), now)
        custodian.readHandshakeFrame(requester.writeHandshakeFrame(now), now)
        requester.readHandshakeFrame(custodian.writeHandshakeFrame(now), now)
        custodian.readHandshakeFrame(requester.writeHandshakeFrame(now), now)
        requester.enterConfirmation(now)
        custodian.enterConfirmation(now)
        custodian.receiveHello(requester.sendHello("Workstation", "Windows", now), now)
        requester.receiveHello(custodian.sendHello("Phone", "Android", now), now)
        requester.receiveConfirmation(custodian.sendConfirmation(profiles, now), now)
        custodian.receiveConfirmation(requester.sendConfirmation(profiles, now), now)
        return requester.finishPairing(WALL_MS, now) to custodian.finishPairing(WALL_MS, now)
    }
}
