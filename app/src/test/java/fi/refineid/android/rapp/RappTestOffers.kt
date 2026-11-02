// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.SecureRandom

/**
 * Builds the two bridges of one pairing the way RAPP v26.11.2 section 4.2
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
    private val READY_NONCE_BYTES = rappRandomByteCounts().sessionReadyNonce.toInt()

    /** The synthetic names the two test endpoints give themselves (section 4.3 item 3). */
    const val COMPUTER_NAME = "Workstation"
    const val COMPUTER_PLATFORM = "Windows"
    const val PHONE_NAME = "Phone"
    const val PHONE_PLATFORM = "Android"

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
        custodian.receiveHello(requester.sendHello(COMPUTER_NAME, COMPUTER_PLATFORM, now), now)
        requester.receiveHello(custodian.sendHello(PHONE_NAME, PHONE_PLATFORM, now), now)
        requester.receiveConfirmation(custodian.sendConfirmation(profiles, now), now)
        custodian.receiveConfirmation(requester.sendConfirmation(profiles, now), now)
        return confirmStorage(requester, custodian, now)
    }

    /**
     * Opens the session of two authenticated session bridges (section 7.1
     * items 5 and 6): the custodian's `session.ready` naming the phone, the
     * requester's `session.hello` naming the computer, which the custodian's
     * operation bridge reads before anything else. Returns the requester's
     * operation bridge and the custodian's.
     */
    fun establish(
        requester: RappSessionBridge,
        custodian: RappSessionBridge,
        lifetimeMs: ULong,
        now: ULong,
    ): Pair<RappOperationBridge, RappOperationBridge> {
        val ready = custodian.sendReady(random(READY_NONCE_BYTES), PHONE_NAME)
        custodian.enterEstablished()
        val greeted = RappBridgeOutcome.from(requester.receiveReady(ready, now, COMPUTER_NAME))
        check(greeted is RappBridgeOutcome.Greeted && greeted.custodianName.text == PHONE_NAME)
        requester.enterEstablished()
        val requesterBridge = RappOperationBridge.beginRequester(requester, lifetimeMs, now)
        val custodianBridge = RappOperationBridge.beginProxy(custodian, lifetimeMs, now)
        val named = RappBridgeOutcome.from(custodianBridge.receiveFrame(greeted.hello, now))
        check(named is RappBridgeOutcome.PeerNamed && named.name.text == COMPUTER_NAME)
        return requesterBridge to custodianBridge
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
