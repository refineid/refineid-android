// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappPairingBridge
import java.security.SecureRandom

/**
 * Builds the two bridges of one pairing the way RAPP v26.10.9 section 4.2
 * does: the custodian creates a random offer, and the requester decodes the
 * bootstrap bytes the custodian serves over the stream transport.
 */
internal object RappTestOffers {
    const val STREAM_PROFILE = "fi.refineid.stream.v1"
    const val STREAM_CANDIDATE_ID = "stream-1"
    private const val OFFER_ID_BYTES = 32

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
}
