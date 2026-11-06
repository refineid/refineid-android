// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningAlgorithm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappSignatureAlgorithm

/** Each requested algorithm maps exactly onto what the card's key serves, or onto nothing. */
class RappSignatureAlgorithmMappingTest {
    @Test
    fun authenticationServesEachSupportedAlgorithmAndRefusesTheRest() {
        val served =
            mapOf(
                RappSignatureAlgorithm.ECDSA_SHA256 to AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
                RappSignatureAlgorithm.ECDSA_SHA384 to AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
                RappSignatureAlgorithm.RSA_PKCS1_SHA256 to AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                RappSignatureAlgorithm.RSA_PKCS1_SHA384 to AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
                RappSignatureAlgorithm.RSA_PKCS1_SHA512 to AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
                RappSignatureAlgorithm.RSA_PSS_SHA256 to AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            )
        for (algorithm in RappSignatureAlgorithm.entries) {
            assertEquals(algorithm.name, served[algorithm], authenticationSigningAlgorithmFor(algorithm))
        }
        assertNull(authenticationSigningAlgorithmFor(RappSignatureAlgorithm.ECDSA_SHA224))
        assertNull(authenticationSigningAlgorithmFor(RappSignatureAlgorithm.ECDSA_SHA512))
    }

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
