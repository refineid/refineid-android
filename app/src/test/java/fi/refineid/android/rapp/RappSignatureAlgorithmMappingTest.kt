// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.QualifiedSigningAlgorithm
import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappSignatureAlgorithm

/** Each requested algorithm maps exactly onto what the card's key serves, or onto nothing. */
class RappSignatureAlgorithmMappingTest {
    @Test
    fun qualifiedSigningServesOnlyTheCardsOwnAlgorithm() {
        val served =
            mapOf(
                (RappCardKeyProfile.ECDSA_P384 to RappSignatureAlgorithm.ECDSA_SHA384) to
                    QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                (RappCardKeyProfile.RSA3072 to RappSignatureAlgorithm.RSA_PKCS1_SHA384) to
                    QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
            )
        for (keyProfile in RappCardKeyProfile.entries) {
            for (algorithm in RappSignatureAlgorithm.entries) {
                assertEquals(
                    "$keyProfile $algorithm",
                    served[keyProfile to algorithm],
                    qualifiedSigningAlgorithmFor(keyProfile, algorithm),
                )
            }
        }
    }
}
