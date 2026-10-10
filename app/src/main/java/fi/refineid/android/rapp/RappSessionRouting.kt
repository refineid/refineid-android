// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.rappStreamSessionPreamble

/**
 * Routes a session connection by its routing preamble (RAPP v26.10.9
 * section 2.2.1).
 *
 * The one session listener serves every stored custodian pairing; the
 * preamble's rendezvous token is the only thing that names one.
 */
internal object RappSessionRouting {
    /**
     * The custodian pairing whose session preamble [preamble] is, or null
     * for an unknown token or any other frame, which the caller refuses
     * without changing stored state.
     */
    fun route(
        preamble: ByteArray,
        pairs: List<RappPairRecord>,
    ): RappPairRecord? =
        pairs.firstOrNull { record ->
            val metadata = record.metadata()
            metadata.role == RappEndpointRole.PROXY &&
                preamble.contentEquals(rappStreamSessionPreamble(metadata.rendezvousToken))
        }
}
