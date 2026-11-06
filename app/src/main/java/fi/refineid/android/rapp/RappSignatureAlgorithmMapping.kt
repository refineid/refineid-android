// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.QualifiedSigningAlgorithm
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappSignatureAlgorithm

/**
 * The qualified signing algorithm that serves a section 9.3 request for
 * [algorithm] with a [keyProfile] key, or null when the card's qualified
 * key cannot serve it: the card signs ECDSA over SHA-384 with a P-384 key
 * and RSA PKCS#1 v1.5 over SHA-384 with an RSA-3072 key, nothing else. A
 * null ends the operation as unsupported before any PIN 2 prompt.
 */
internal fun qualifiedSigningAlgorithmFor(
    keyProfile: RappCardKeyProfile,
    algorithm: RappSignatureAlgorithm,
): QualifiedSigningAlgorithm? =
    when (algorithm) {
        RappSignatureAlgorithm.ECDSA_SHA384 -> {
            QualifiedSigningAlgorithm.ECDSA_P384_SHA384.takeIf { keyProfile == RappCardKeyProfile.ECDSA_P384 }
        }

        RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> {
            QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.takeIf { keyProfile == RappCardKeyProfile.RSA3072 }
        }

        RappSignatureAlgorithm.ECDSA_SHA224,
        RappSignatureAlgorithm.ECDSA_SHA256,
        RappSignatureAlgorithm.ECDSA_SHA512,
        RappSignatureAlgorithm.RSA_PKCS1_SHA256,
        RappSignatureAlgorithm.RSA_PKCS1_SHA512,
        RappSignatureAlgorithm.RSA_PSS_SHA256,
        -> {
            null
        }
    }
