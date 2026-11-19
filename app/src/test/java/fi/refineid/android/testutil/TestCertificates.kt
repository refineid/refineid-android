// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.testutil

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Ephemeral X.509 certificates for tests. Every key pair is generated at
 * test time and dies with the JVM; no private key, certificate, or key
 * identifier from these fixtures may be written to disk, committed, or
 * reused across runs. Static CA-looking bytes in the repository invite
 * confusion with real trust material: a persisted test CA whose key
 * later leaks would mint certificates for any store that ever trusted
 * it. Keep test trust rooted in nothing but fresh randomness.
 */
internal object TestCertificates {
    /** A fresh P-256 key pair; the private half never leaves memory. */
    fun keyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(EC_ALGORITHM)
        generator.initialize(ECGenParameterSpec(EC_CURVE))
        return generator.generateKeyPair()
    }

    /**
     * A minimal v3 certificate for [subjectCommonName], signed by
     * [issuerKey]. Validity is caller-chosen GeneralizedTime
     * (`yyyyMMddHHmmss'Z'`), so expired certificates are built the same
     * way as current ones. A [certificateAuthority] carries critical
     * basicConstraints CA:TRUE with keyCertSign; anything else carries
     * critical CA:FALSE with digitalSignature.
     */
    fun certificate(
        subjectCommonName: String,
        subjectKey: KeyPair,
        issuerCommonName: String,
        issuerKey: KeyPair,
        serialNumber: Int,
        notBefore: String,
        notAfter: String,
        certificateAuthority: Boolean,
    ): ByteArray {
        val algorithm = TestDerEncoder.sequence(listOf(TestDerEncoder.objectIdentifier(ECDSA_WITH_SHA384_OID)))
        val issuerName = distinguishedName(issuerCommonName)
        val subjectName = distinguishedName(subjectCommonName)
        val validity =
            TestDerEncoder.sequence(
                listOf(
                    TestDerEncoder.tlv(TestDerValues.TAG_GENERALIZED_TIME, notBefore.encodeToByteArray()),
                    TestDerEncoder.tlv(TestDerValues.TAG_GENERALIZED_TIME, notAfter.encodeToByteArray()),
                ),
            )
        val extensions =
            TestDerEncoder.tlv(
                TestDerValues.TAG_CONTEXT_3_CONSTRUCTED,
                TestDerEncoder.sequence(extensions(certificateAuthority)),
            )
        val tbsCertificate =
            TestDerEncoder.sequence(
                listOf(
                    TestDerEncoder.tlv(
                        TestDerValues.TAG_CONTEXT_0_CONSTRUCTED,
                        TestDerEncoder.integer(X509_VERSION_THREE),
                    ),
                    TestDerEncoder.integer(serialNumber),
                    algorithm,
                    issuerName,
                    validity,
                    subjectName,
                    subjectKey.public.encoded,
                    extensions,
                ),
            )
        val signatureBytes =
            Signature
                .getInstance(JCA_ECDSA_WITH_SHA384)
                .apply {
                    initSign(issuerKey.private)
                    update(tbsCertificate)
                }.sign()
        return TestDerEncoder.sequence(
            listOf(
                tbsCertificate,
                algorithm,
                TestDerEncoder.tlv(
                    TestDerValues.TAG_BIT_STRING,
                    byteArrayOf(NO_UNUSED_BITS) + signatureBytes,
                ),
            ),
        )
    }

    private fun distinguishedName(commonName: String): ByteArray =
        TestDerEncoder.sequence(
            listOf(
                TestDerEncoder.setOf(
                    listOf(
                        TestDerEncoder.sequence(
                            listOf(
                                TestDerEncoder.objectIdentifier(COMMON_NAME_OID),
                                TestDerEncoder.tlv(
                                    TestDerValues.TAG_UTF8_STRING,
                                    commonName.encodeToByteArray(),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

    private fun extensions(certificateAuthority: Boolean): List<ByteArray> {
        val constraintsValue =
            if (certificateAuthority) {
                TestDerEncoder.sequence(listOf(TestDerEncoder.booleanTrue()))
            } else {
                TestDerEncoder.sequence(emptyList())
            }
        val keyUsageBits =
            if (certificateAuthority) {
                byteArrayOf(KEY_CERT_SIGN_UNUSED_BITS, KEY_CERT_SIGN_ASSERTED)
            } else {
                byteArrayOf(DIGITAL_SIGNATURE_UNUSED_BITS, DIGITAL_SIGNATURE_ASSERTED)
            }
        return listOf(
            extension(BASIC_CONSTRAINTS_OID, constraintsValue),
            extension(
                KEY_USAGE_OID,
                TestDerEncoder.tlv(TestDerValues.TAG_BIT_STRING, keyUsageBits),
            ),
        )
    }

    private fun extension(
        oid: String,
        value: ByteArray,
    ): ByteArray =
        TestDerEncoder.sequence(
            listOf(
                TestDerEncoder.objectIdentifier(oid),
                TestDerEncoder.booleanTrue(),
                TestDerEncoder.octetString(value),
            ),
        )

    private const val EC_ALGORITHM = "EC"
    private const val EC_CURVE = "secp256r1"
    private const val JCA_ECDSA_WITH_SHA384 = "SHA384withECDSA"
    private const val ECDSA_WITH_SHA384_OID = "1.2.840.10045.4.3.3"
    private const val COMMON_NAME_OID = "2.5.4.3"
    private const val BASIC_CONSTRAINTS_OID = "2.5.29.19"
    private const val KEY_USAGE_OID = "2.5.29.15"
    private const val X509_VERSION_THREE = 2
    private const val NO_UNUSED_BITS: Byte = 0

    /** keyUsage bit 5 (keyCertSign) set: six bits used, two padding bits. */
    private const val KEY_CERT_SIGN_UNUSED_BITS: Byte = 2
    private const val KEY_CERT_SIGN_ASSERTED: Byte = 0x04

    /** keyUsage bit 0 (digitalSignature) set: one bit used, seven padding bits. */
    private const val DIGITAL_SIGNATURE_UNUSED_BITS: Byte = 7
    private const val DIGITAL_SIGNATURE_ASSERTED: Byte = -0x80
}
