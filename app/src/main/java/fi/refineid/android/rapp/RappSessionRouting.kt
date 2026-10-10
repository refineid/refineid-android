// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappRoute
import uniffi.refineid_rapp.RappSessionRouter
import uniffi.refineid_rapp.rappStreamProfileName

/**
 * Routes a session connection by its routing preamble (RAPP v26.10.10
 * section 2.2.1).
 *
 * The one session listener serves every stored custodian pairing. A
 * preamble names its pairing only through a routing tag keyed from that
 * pairing's static agreement over a fresh nonce, and the router refuses a
 * nonce it already routed. One instance lives as long as its listener.
 */
internal class RappSessionRouting(
    private val router: RappSessionRouter = RappSessionRouter(),
) : AutoCloseable {
    /**
     * The custodian pairing whose session preamble [preamble] is, or null
     * for a pairing preamble, an unknown or replayed tag, or any other
     * frame, which the caller refuses without changing stored state.
     */
    fun route(
        preamble: ByteArray,
        pairs: List<RappPairRecord>,
    ): RappPairRecord? {
        val custodianPairs = pairs.filter { it.metadata().role == RappEndpointRole.PROXY }
        return when (val route = router.route(rappStreamProfileName(), preamble, custodianPairs)) {
            is RappRoute.Session -> custodianPairs.getOrNull(route.index.toInt())
            RappRoute.Pairing, RappRoute.Refuse -> null
        }
    }

    override fun close() {
        router.close()
    }
}
