// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.SecureRandom

/**
 * Builds the two bridges of one pairing the way RAPP v26.10.21 section 4.2
 * does: the custodian creates a random offer, and the requester decodes the
 * bootstrap bytes the custodian serves over the stream transport.
 */
internal object RappTestOffers {
    /** The stream transport profile and its candidate identifier, as section 2.2 registers them. */
    const val STREAM_PROFILE = "fi.refineid.stream"
    const val STREAM_CANDIDATE_ID = "stream"
    private val OFFER_ID_BYTES = rappRandomByteCounts().offerId.toInt()
    private val CPACE_RANDOM_BYTES = rappRandomByteCounts().cpaceRandom.toInt()
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

    /**
     * A completed pairing: the requester's confirmed record and the
     * custodian's, after both storage confirmations were exchanged (section
     * 4.3 item 4). The unconfirmed records a platform would persist first are
     * built and released; the confirmed ones are returned.
     */
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
        return confirmStorage(requester, custodian, now)
    }

    /**
     * Runs the storage confirmation of both sides and returns the confirmed
     * records, requester first.
     */
    fun confirmStorage(
        requester: RappPairingBridge,
        custodian: RappPairingBridge,
        now: ULong,
    ): Pair<RappPairRecord, RappPairRecord> {
        requester.buildPairRecord(WALL_MS, now).close()
        custodian.buildPairRecord(WALL_MS, now).close()
        val requesterStored = requester.sendStored(now)
        val custodianStored = custodian.sendStored(now)
        custodian.receiveStored(requesterStored, now)
        requester.receiveStored(custodianStored, now)
        return checkNotNull(requester.activatePairing(now)) to checkNotNull(custodian.activatePairing(now))
    }
}
