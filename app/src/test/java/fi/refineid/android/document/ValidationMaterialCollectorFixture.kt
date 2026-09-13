// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant

/** Ephemeral certificates and CRLs for validation-material collector tests. */
internal class ValidationMaterialCollectorFixture private constructor(
    val issuerCertificate: ByteArray,
    val documentSignerCertificate: ByteArray,
    val timestampAuthorityCertificate: ByteArray,
    private val statusEvidence: FixtureStatusEvidence,
    val currentTime: Instant,
) : AutoCloseable {
    val goodOcspResponse: ByteArray
        get() = statusEvidence.goodOcspResponse

    val goodRevocationList: ByteArray
        get() = statusEvidence.goodRevocationList

    val revokedRevocationList: ByteArray
        get() = statusEvidence.revokedRevocationList

    override fun close() {
        issuerCertificate.fill(ZERO_BYTE)
        documentSignerCertificate.fill(ZERO_BYTE)
        timestampAuthorityCertificate.fill(ZERO_BYTE)
        statusEvidence.close()
    }

    companion object {
        const val ISSUER_ADDRESS = "https://issuer.example/certificate.der"
        const val OCSP_ADDRESS = "http://status.example/ocsp"
        const val REVOCATION_LIST_ADDRESS = "https://issuer.example/current.crl"

        fun create(): ValidationMaterialCollectorFixture {
            val issuerKey = keyPair()
            val documentKey = keyPair()
            val timestampKey = keyPair()
            val issuerName = name(ISSUER_COMMON_NAME)
            val issuerCertificate =
                certificate(
                    description =
                        CertificateDescription(
                            subjectCommonName = ISSUER_COMMON_NAME,
                            issuerName = issuerName,
                            serialNumber = byteArrayOf(ISSUER_SERIAL_NUMBER),
                            publicKey = issuerKey,
                            signer = issuerKey,
                            certificateAuthority = true,
                            timestampAuthority = false,
                        ),
                )
            val documentSignerCertificate =
                certificate(
                    description =
                        CertificateDescription(
                            subjectCommonName = DOCUMENT_SIGNER_COMMON_NAME,
                            issuerName = issuerName,
                            serialNumber = byteArrayOf(DOCUMENT_SIGNER_SERIAL_NUMBER),
                            publicKey = documentKey,
                            signer = issuerKey,
                            certificateAuthority = false,
                            timestampAuthority = false,
                        ),
                )
            val timestampAuthorityCertificate =
                certificate(
                    description =
                        CertificateDescription(
                            subjectCommonName = TIMESTAMP_AUTHORITY_COMMON_NAME,
                            issuerName = issuerName,
                            serialNumber = byteArrayOf(TIMESTAMP_AUTHORITY_SERIAL_NUMBER),
                            publicKey = timestampKey,
                            signer = issuerKey,
                            certificateAuthority = false,
                            timestampAuthority = true,
                        ),
                )
            val ocspNonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { OCSP_NONCE_FILL_BYTE }
            val goodOcspResponse =
                try {
                    ocspResponse(
                        certificate = documentSignerCertificate,
                        issuerCertificate = issuerCertificate,
                        issuerName = issuerName,
                        issuerKey = issuerKey,
                        nonce = ocspNonce,
                    )
                } finally {
                    ocspNonce.fill(ZERO_BYTE)
                }
            return ValidationMaterialCollectorFixture(
                issuerCertificate = issuerCertificate,
                documentSignerCertificate = documentSignerCertificate,
                timestampAuthorityCertificate = timestampAuthorityCertificate,
                statusEvidence =
                    FixtureStatusEvidence(
                        goodOcspResponse = goodOcspResponse,
                        goodRevocationList = revocationList(issuerName, issuerKey, emptyList()),
                        revokedRevocationList =
                            revocationList(
                                issuerName = issuerName,
                                issuerKey = issuerKey,
                                revokedSerialNumbers =
                                    listOf(
                                        byteArrayOf(DOCUMENT_SIGNER_SERIAL_NUMBER),
                                        byteArrayOf(TIMESTAMP_AUTHORITY_SERIAL_NUMBER),
                                    ),
                            ),
                    ),
                currentTime = CURRENT_TIME,
            )
        }

        private fun ocspResponse(
            certificate: ByteArray,
            issuerCertificate: ByteArray,
            issuerName: ByteArray,
            issuerKey: KeyPair,
            nonce: ByteArray,
        ): ByteArray {
            val certificateFacts = checkNotNull(CertificateFacts.parse(certificate))
            val issuerFacts = checkNotNull(CertificateFacts.parse(issuerCertificate))
            try {
                val certificateId =
                    certificateFacts.useOcspIdentity { exactIssuerName, serialNumber ->
                        issuerFacts.usePublicKeyBits { issuerKeyBits ->
                            val nameHash = sha1(exactIssuerName)
                            val keyHash = sha1(issuerKeyBits)
                            try {
                                DerEncoder.sequence(
                                    listOf(
                                        sha1AlgorithmIdentifier(),
                                        DerEncoder.octetString(nameHash),
                                        DerEncoder.octetString(keyHash),
                                        DerEncoder.tlv(DerValues.TAG_INTEGER, serialNumber),
                                    ),
                                )
                            } finally {
                                nameHash.fill(ZERO_BYTE)
                                keyHash.fill(ZERO_BYTE)
                            }
                        }
                    }
                val singleResponse =
                    DerEncoder.sequence(
                        listOf(
                            certificateId,
                            DerEncoder.tlv(DerValues.TAG_CONTEXT_0_PRIMITIVE, byteArrayOf()),
                            generalizedTime(OCSP_THIS_UPDATE),
                            DerEncoder.tlv(
                                DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                                generalizedTime(OCSP_NEXT_UPDATE),
                            ),
                        ),
                    )
                val responseData =
                    DerEncoder.sequence(
                        listOf(
                            DerEncoder.tlv(DerValues.TAG_CONTEXT_1_CONSTRUCTED, issuerName),
                            generalizedTime(OCSP_PRODUCED_AT),
                            DerEncoder.sequence(listOf(singleResponse)),
                            responseNonceExtension(nonce),
                        ),
                    )
                val basicResponse =
                    DerEncoder.sequence(
                        listOf(
                            responseData,
                            signatureAlgorithmIdentifier(),
                            bitString(sign(responseData, issuerKey)),
                        ),
                    )
                val responseBytes =
                    DerEncoder.sequence(
                        listOf(
                            DerEncoder.objectIdentifier(OcspOids.BASIC_RESPONSE),
                            DerEncoder.octetString(basicResponse),
                        ),
                    )
                return DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(
                            DerValues.TAG_ENUMERATED,
                            byteArrayOf(SUCCESSFUL_OCSP_RESPONSE_STATUS),
                        ),
                        DerEncoder.tlv(DerValues.TAG_CONTEXT_0_CONSTRUCTED, responseBytes),
                    ),
                )
            } finally {
                certificateFacts.close()
                issuerFacts.close()
            }
        }

        private fun responseNonceExtension(nonce: ByteArray): ByteArray {
            val extension =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(CertificateOids.OCSP_NONCE),
                        DerEncoder.octetString(DerEncoder.octetString(nonce)),
                    ),
                )
            return DerEncoder.tlv(
                DerValues.TAG_CONTEXT_1_CONSTRUCTED,
                DerEncoder.sequence(listOf(extension)),
            )
        }

        private fun sha1AlgorithmIdentifier(): ByteArray =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(CertificateOids.SHA1),
                    DerEncoder.nullValue(),
                ),
            )

        private fun sha1(value: ByteArray): ByteArray = MessageDigest.getInstance(SHA1_JAVA_NAME).digest(value)

        private fun certificate(description: CertificateDescription): ByteArray {
            val algorithm = signatureAlgorithmIdentifier()
            val tbs =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(
                            DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                            DerEncoder.integer(CERTIFICATE_VERSION_THREE),
                        ),
                        DerEncoder.unsignedInteger(description.serialNumber),
                        algorithm,
                        description.issuerName,
                        validity(),
                        name(description.subjectCommonName),
                        description.publicKey.public.encoded,
                        DerEncoder.tlv(
                            DerValues.TAG_CONTEXT_3_CONSTRUCTED,
                            certificateExtensions(
                                certificateAuthority = description.certificateAuthority,
                                timestampAuthority = description.timestampAuthority,
                            ),
                        ),
                    ),
                )
            return DerEncoder.sequence(
                listOf(
                    tbs,
                    algorithm,
                    bitString(sign(tbs, description.signer)),
                ),
            )
        }

        private fun revocationList(
            issuerName: ByteArray,
            issuerKey: KeyPair,
            revokedSerialNumbers: List<ByteArray>,
        ): ByteArray {
            val algorithm = signatureAlgorithmIdentifier()
            val fields =
                mutableListOf(
                    DerEncoder.integer(REVOCATION_LIST_VERSION_TWO),
                    algorithm,
                    issuerName,
                    generalizedTime(REVOCATION_LIST_THIS_UPDATE),
                    generalizedTime(REVOCATION_LIST_NEXT_UPDATE),
                )
            if (revokedSerialNumbers.isNotEmpty()) {
                fields +=
                    DerEncoder.sequence(
                        revokedSerialNumbers.map { serialNumber ->
                            DerEncoder.sequence(
                                listOf(
                                    DerEncoder.unsignedInteger(serialNumber),
                                    generalizedTime(REVOCATION_TIME),
                                ),
                            )
                        },
                    )
            }
            val tbs = DerEncoder.sequence(fields)
            return DerEncoder.sequence(
                listOf(
                    tbs,
                    algorithm,
                    bitString(sign(tbs, issuerKey)),
                ),
            )
        }

        private fun certificateExtensions(
            certificateAuthority: Boolean,
            timestampAuthority: Boolean,
        ): ByteArray {
            val constraints =
                if (certificateAuthority) {
                    DerEncoder.sequence(listOf(DerEncoder.booleanTrue()))
                } else {
                    DerEncoder.sequence(emptyList())
                }
            val usage =
                if (certificateAuthority) {
                    byteArrayOf(ONE_UNUSED_BIT, CERTIFICATE_AND_REVOCATION_LIST_SIGNING_BITS)
                } else {
                    byteArrayOf(SEVEN_UNUSED_BITS, DIGITAL_SIGNATURE_BIT)
                }
            val extensions =
                mutableListOf(
                    extension(
                        identifier = BASIC_CONSTRAINTS_IDENTIFIER,
                        critical = true,
                        value = constraints,
                    ),
                    extension(
                        identifier = KEY_USAGE_IDENTIFIER,
                        critical = true,
                        value = DerEncoder.tlv(DerValues.TAG_BIT_STRING, usage),
                    ),
                )
            if (!certificateAuthority) {
                extensions += authorityInformationAccessExtension()
                extensions += revocationListExtension()
            }
            if (timestampAuthority) {
                extensions +=
                    extension(
                        identifier = EXTENDED_KEY_USAGE_IDENTIFIER,
                        critical = true,
                        value =
                            DerEncoder.sequence(
                                listOf(DerEncoder.objectIdentifier(TIMESTAMPING_KEY_PURPOSE_IDENTIFIER)),
                            ),
                    )
            }
            return DerEncoder.sequence(extensions)
        }

        private fun authorityInformationAccessExtension(): ByteArray =
            extension(
                identifier = AUTHORITY_INFORMATION_ACCESS_IDENTIFIER,
                critical = false,
                value =
                    DerEncoder.sequence(
                        listOf(
                            accessDescription(OCSP_ACCESS_METHOD_IDENTIFIER, OCSP_ADDRESS),
                            accessDescription(CA_ISSUERS_ACCESS_METHOD_IDENTIFIER, ISSUER_ADDRESS),
                        ),
                    ),
            )

        private fun accessDescription(
            method: String,
            address: String,
        ): ByteArray =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(method),
                    DerEncoder.tlv(DerValues.TAG_CONTEXT_6_PRIMITIVE, address.encodeToByteArray()),
                ),
            )

        private fun revocationListExtension(): ByteArray {
            val names =
                DerEncoder.tlv(
                    DerValues.TAG_CONTEXT_6_PRIMITIVE,
                    REVOCATION_LIST_ADDRESS.encodeToByteArray(),
                )
            val pointName =
                DerEncoder.tlv(
                    DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                    DerEncoder.tlv(DerValues.TAG_CONTEXT_0_CONSTRUCTED, names),
                )
            return extension(
                identifier = CRL_DISTRIBUTION_POINTS_IDENTIFIER,
                critical = false,
                value = DerEncoder.sequence(listOf(DerEncoder.sequence(listOf(pointName)))),
            )
        }

        private fun extension(
            identifier: String,
            critical: Boolean,
            value: ByteArray,
        ): ByteArray {
            val fields = mutableListOf(DerEncoder.objectIdentifier(identifier))
            if (critical) {
                fields += DerEncoder.booleanTrue()
            }
            fields += DerEncoder.octetString(value)
            return DerEncoder.sequence(fields)
        }

        private fun validity(): ByteArray =
            DerEncoder.sequence(
                listOf(
                    generalizedTime(CERTIFICATE_NOT_BEFORE),
                    generalizedTime(CERTIFICATE_NOT_AFTER),
                ),
            )

        private fun name(commonName: String): ByteArray =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.setOf(
                        listOf(
                            DerEncoder.sequence(
                                listOf(
                                    DerEncoder.objectIdentifier(COMMON_NAME_IDENTIFIER),
                                    DerEncoder.tlv(DerValues.TAG_UTF8_STRING, commonName.encodeToByteArray()),
                                ),
                            ),
                        ),
                    ),
                ),
            )

        private fun generalizedTime(value: String): ByteArray =
            DerEncoder.tlv(DerValues.TAG_GENERALIZED_TIME, value.encodeToByteArray())

        private fun signatureAlgorithmIdentifier(): ByteArray =
            DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(ECDSA_WITH_SHA256_IDENTIFIER)))

        private fun bitString(value: ByteArray): ByteArray =
            DerEncoder.tlv(DerValues.TAG_BIT_STRING, byteArrayOf(NO_UNUSED_BITS) + value)

        private fun sign(
            value: ByteArray,
            keyPair: KeyPair,
        ): ByteArray =
            Signature.getInstance(ECDSA_WITH_SHA256_JAVA_NAME).run {
                initSign(keyPair.private)
                update(value)
                sign()
            }

        private fun keyPair(): KeyPair =
            KeyPairGenerator.getInstance(EC_KEY_ALGORITHM).run {
                initialize(ECGenParameterSpec(P256_CURVE_NAME))
                generateKeyPair()
            }

        private data class CertificateDescription(
            val subjectCommonName: String,
            val issuerName: ByteArray,
            val serialNumber: ByteArray,
            val publicKey: KeyPair,
            val signer: KeyPair,
            val certificateAuthority: Boolean,
            val timestampAuthority: Boolean,
        )

        private class FixtureStatusEvidence(
            val goodOcspResponse: ByteArray,
            val goodRevocationList: ByteArray,
            val revokedRevocationList: ByteArray,
        ) : AutoCloseable {
            override fun close() {
                goodOcspResponse.fill(ZERO_BYTE)
                goodRevocationList.fill(ZERO_BYTE)
                revokedRevocationList.fill(ZERO_BYTE)
            }
        }

        private const val EC_KEY_ALGORITHM = "EC"
        private const val P256_CURVE_NAME = "secp256r1"
        private const val ECDSA_WITH_SHA256_JAVA_NAME = "SHA256withECDSA"
        private const val SHA1_JAVA_NAME = "SHA-1"
        private const val ECDSA_WITH_SHA256_IDENTIFIER = "1.2.840.10045.4.3.2"
        private const val COMMON_NAME_IDENTIFIER = "2.5.4.3"
        private const val BASIC_CONSTRAINTS_IDENTIFIER = "2.5.29.19"
        private const val KEY_USAGE_IDENTIFIER = "2.5.29.15"
        private const val EXTENDED_KEY_USAGE_IDENTIFIER = "2.5.29.37"
        private const val TIMESTAMPING_KEY_PURPOSE_IDENTIFIER = "1.3.6.1.5.5.7.3.8"
        private const val AUTHORITY_INFORMATION_ACCESS_IDENTIFIER = "1.3.6.1.5.5.7.1.1"
        private const val OCSP_ACCESS_METHOD_IDENTIFIER = "1.3.6.1.5.5.7.48.1"
        private const val CA_ISSUERS_ACCESS_METHOD_IDENTIFIER = "1.3.6.1.5.5.7.48.2"
        private const val CRL_DISTRIBUTION_POINTS_IDENTIFIER = "2.5.29.31"

        private const val ISSUER_COMMON_NAME = "RefineID synthetic collector issuer"
        private const val DOCUMENT_SIGNER_COMMON_NAME = "RefineID synthetic document signer"
        private const val TIMESTAMP_AUTHORITY_COMMON_NAME = "RefineID synthetic timestamp authority"
        private const val CERTIFICATE_NOT_BEFORE = "20250101000000Z"
        private const val CERTIFICATE_NOT_AFTER = "20300101000000Z"
        private const val REVOCATION_LIST_THIS_UPDATE = "20260801000000Z"
        private const val REVOCATION_LIST_NEXT_UPDATE = "20260901000000Z"
        private const val REVOCATION_TIME = "20260801000000Z"
        private const val OCSP_PRODUCED_AT = "20260815120000Z"
        private const val OCSP_THIS_UPDATE = "20260815120000Z"
        private const val OCSP_NEXT_UPDATE = "20260901000000Z"
        private const val CURRENT_TIME_TEXT = "2026-08-15T12:00:00Z"

        private const val CERTIFICATE_VERSION_THREE = 2
        private const val REVOCATION_LIST_VERSION_TWO = 1
        private const val ISSUER_SERIAL_NUMBER: Byte = 1
        private const val DOCUMENT_SIGNER_SERIAL_NUMBER: Byte = 2
        private const val TIMESTAMP_AUTHORITY_SERIAL_NUMBER: Byte = 3
        private const val ONE_UNUSED_BIT: Byte = 1
        private const val CERTIFICATE_AND_REVOCATION_LIST_SIGNING_BITS: Byte = 6
        private const val SEVEN_UNUSED_BITS: Byte = 7
        private const val DIGITAL_SIGNATURE_BIT: Byte = -128
        private const val NO_UNUSED_BITS: Byte = 0
        private const val SUCCESSFUL_OCSP_RESPONSE_STATUS: Byte = 0
        const val OCSP_NONCE_FILL_BYTE: Byte = 0x5A
        private const val ZERO_BYTE: Byte = 0
        private val CURRENT_TIME = Instant.parse(CURRENT_TIME_TEXT)
    }
}
