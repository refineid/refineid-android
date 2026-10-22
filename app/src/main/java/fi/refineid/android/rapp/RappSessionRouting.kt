// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappRoute
import uniffi.refineid_rapp.RappSessionRouter

/**
 * Routes a session connection by its routing preamble (RAPP v26.10.22
 * section 2.2.1).
 *
 * The custodian serves every stored custodian pairing on each transport. A
 * preamble names its pairing only through a routing tag keyed from that
 * pairing's static agreement, the transport's preamble domain and a fresh
 * nonce, and the router refuses a nonce it already routed on either
 * transport. One instance lives as long as the custodian serves; routing and
 * closing may come from different threads.
 */
internal class RappSessionRouting(
    private val router: RappSessionRouter = RappSessionRouter(),
) : AutoCloseable {
    private var isClosed = false

    /**
     * The custodian pairing whose session preamble [preamble] is on the
     * transport [profile], or null for a pairing preamble, another
     * transport's preamble, an unknown or replayed tag, or any other frame,
     * which the caller refuses without changing stored state.
     */
    @Synchronized
    fun route(
        profile: RappTransportProfile,
        preamble: ByteArray,
        pairs: List<RappPairRecord>,
    ): RappPairRecord? {
        if (isClosed) return null
        val custodianPairs = pairs.filter { it.pairing().role == RappEndpointRole.PROXY }
        return when (val route = router.route(profile.profileName, preamble, custodianPairs)) {
            is RappRoute.Session -> custodianPairs.getOrNull(route.index.toInt())
            RappRoute.Pairing, RappRoute.Refuse -> null
        }
    }

    @Synchronized
    override fun close() {
        if (isClosed) return
        isClosed = true
        router.close()
    }
}
