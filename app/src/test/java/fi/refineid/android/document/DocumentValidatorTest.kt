// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.network.SigningNetworkBasicCredentials
import fi.refineid.android.network.SigningNetworkEndpoint
import fi.refineid.android.network.SigningNetworkLimits
import fi.refineid.android.network.SigningNetworkTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * End-to-end proof: build a real self-signed P-384 certificate, wrap a
 * detached CMS signature over a byte range into a minimal PDF, and
 * confirm the independent validator accepts it, rejects a tampered
 * body, distrusts an unknown anchor, unescapes RFC2253 strings, and reports an unsigned file.
 */
class DocumentValidatorTest {
    @Test
    fun acceptsAnIntactSignatureFromATrustedSigner() {
        val fixture = SignedPdfFixture.build()
        val validator = DocumentValidator(trustAnchors = listOf(fixture.certificate), checkRevocation = false)

        val result = validator.validate(fixture.pdf) as DocumentValidationResult.Completed

        val verdict = result.signatures.single()
        assertTrue(result.isValid)
        assertTrue(verdict.digestMatches)
        assertTrue(verdict.signatureValid)
        assertTrue(verdict.chainTrusted)
        assertTrue(verdict.coversWholeDocument)
        assertEquals(SIGNER_COMMON_NAME, verdict.signerCommonName)
    }

    @Test
    fun unescapesSpecialCharactersInSignerCommonName() {
        val fixture = SignedPdfFixture.build(commonName = "Sectigo Qualified Time Stamping Signer #3")
        val validator = DocumentValidator(trustAnchors = listOf(fixture.certificate), checkRevocation = false)

        val result = validator.validate(fixture.pdf) as DocumentValidationResult.Completed
        assertEquals("Sectigo Qualified Time Stamping Signer #3", result.signatures.single().signerCommonName)
    }

    @Test
    fun rejectsATamperedBody() {
        val fixture = SignedPdfFixture.build()
        val tampered = fixture.pdf.copyOf()
        tampered[TAMPER_OFFSET] = (tampered[TAMPER_OFFSET] + 1).toByte()
        val validator = DocumentValidator(trustAnchors = listOf(fixture.certificate), checkRevocation = false)

        val result = validator.validate(tampered) as DocumentValidationResult.Completed

        assertFalse(result.isValid)
        assertFalse(result.signatures.single().digestMatches)
    }

    @Test
    fun distrustsAnUnknownAnchor() {
        val fixture = SignedPdfFixture.build()
        val other = SignedPdfFixture.build()
        val validator = DocumentValidator(trustAnchors = listOf(other.certificate), checkRevocation = false)

        val result = validator.validate(fixture.pdf) as DocumentValidationResult.Completed

        assertFalse(result.isValid)
        val verdict = result.signatures.single()
        assertTrue(verdict.signatureValid)
        assertFalse(verdict.chainTrusted)
    }

    @Test
    fun acceptsMultiRevisionPadesWithDocumentTimeStamp() {
        val fixture = SignedPdfFixture.buildTimestamped()
        val validator = DocumentValidator(trustAnchors = listOf(fixture.certificate), checkRevocation = false)

        val result = validator.validate(fixture.pdf) as DocumentValidationResult.Completed

        assertTrue(result.isValid)
        assertEquals(2, result.signatures.size)

        val signerVerdict = result.signatures[0]
        assertTrue(signerVerdict.isValid)
        assertTrue(signerVerdict.digestMatches)
        assertTrue(signerVerdict.signatureValid)
        assertTrue(signerVerdict.chainTrusted)
        assertTrue(signerVerdict.coversWholeDocument)
        assertFalse(signerVerdict.isDocumentTimestamp)
        assertEquals(SIGNER_COMMON_NAME, signerVerdict.signerCommonName)

        val timestampVerdict = result.signatures[1]
        assertTrue(timestampVerdict.isValid)
        assertTrue(timestampVerdict.digestMatches)
        assertTrue(timestampVerdict.signatureValid)
        assertTrue(timestampVerdict.coversWholeDocument)
        assertTrue(timestampVerdict.isDocumentTimestamp)
    }

    @Test
    fun rejectsMultiRevisionPadesWhenTimestampImprintTampered() {
        val fixture = SignedPdfFixture.buildTimestamped()
        val tampered = fixture.pdf.copyOf()
        // Tamper with the byte range of the PDF
        tampered[TAMPER_OFFSET] = (tampered[TAMPER_OFFSET] + 1).toByte()
        val validator = DocumentValidator(trustAnchors = listOf(fixture.certificate), checkRevocation = false)

        val result = validator.validate(tampered) as DocumentValidationResult.Completed

        assertFalse(result.isValid)
        assertFalse(result.signatures[0].digestMatches)
        assertFalse(result.signatures[1].digestMatches)
    }

    @Test
    fun reportsAnUnsignedDocument() {
        val validator = DocumentValidator(trustAnchors = emptyList(), checkRevocation = false)
        assertEquals(
            DocumentValidationResult.Unsigned,
            validator.validate("%PDF-1.7 no signature here %%EOF".encodeToByteArray()),
        )
    }

    @Test
    fun neverFetchesRevocationForAnUntrustedDocumentTimestamp() {
        val fixture = SignedPdfFixture.buildTimestamped()
        val transport = RevocationTransport()
        val result =
            DocumentValidator(
                trustAnchors = listOf(fixture.certificate),
                transport = transport,
            ).validate(fixture.pdf) as DocumentValidationResult.Completed
        assertTrue(result.signatures.last().isDocumentTimestamp)
        assertTrue(transport.addresses.isEmpty())
    }

    @Test
    fun routesTrustedSignerOcspThroughBoundedCertificateMaterialTransport() {
        val fixture = SignedPdfFixture.build(ocspAddress = SYNTHETIC_OCSP_ADDRESS)
        val transport = RevocationTransport()
        DocumentValidator(
            trustAnchors = listOf(fixture.certificate),
            transport = transport,
        ).validate(fixture.pdf)
        assertEquals(listOf(SYNTHETIC_OCSP_ADDRESS), transport.addresses)
    }

    @Test
    fun neverFetchesRevocationForAnUnknownSigner() {
        val fixture =
            SignedPdfFixture.build(
                ocspAddress = SYNTHETIC_OCSP_ADDRESS,
                revocationListAddress = SYNTHETIC_CRL_ADDRESS,
            )
        val transport = RevocationTransport()
        DocumentValidator(trustAnchors = emptyList(), transport = transport).validate(fixture.pdf)
        assertTrue(transport.addresses.isEmpty())
    }

    @Test
    fun routesTrustedSignerCrlThroughBoundedCertificateMaterialTransport() {
        val fixture = SignedPdfFixture.build(revocationListAddress = SYNTHETIC_CRL_ADDRESS)
        val transport = RevocationTransport()
        DocumentValidator(trustAnchors = listOf(fixture.certificate), transport = transport).validate(fixture.pdf)
        assertEquals(listOf(SYNTHETIC_CRL_ADDRESS), transport.addresses)
    }

    @Test
    fun fetchesBothRevocationSourcesForAnExplicitlyTrustedTimestamp() {
        val fixture = SignedPdfFixture.buildTimestamped()
        val transport = RevocationTransport()
        DocumentValidator(
            trustAnchors = listOf(fixture.certificate, checkNotNull(fixture.timestampCertificate)),
            transport = transport,
        ).validate(fixture.pdf)
        assertEquals(listOf(SYNTHETIC_TSA_OCSP_ADDRESS, SYNTHETIC_CRL_ADDRESS), transport.addresses)
    }

    private class RevocationTransport : SigningNetworkTransport {
        val addresses = mutableListOf<String>()

        override fun get(
            address: String,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray {
            addresses += address
            assertEquals(SigningNetworkEndpoint.CERTIFICATE_MATERIAL, endpoint)
            assertEquals(PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES, maximumResponseBytes)
            return "unavailable".encodeToByteArray()
        }

        override fun post(
            body: ByteArray,
            address: String,
            contentType: String,
            credentials: SigningNetworkBasicCredentials?,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray {
            addresses += address
            assertEquals(SigningNetworkEndpoint.CERTIFICATE_MATERIAL, endpoint)
            assertEquals(SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES, maximumResponseBytes)
            assertEquals("application/ocsp-request", contentType)
            assertEquals(null, credentials)
            return "unavailable".encodeToByteArray()
        }
    }

    private companion object {
        const val SYNTHETIC_CRL_ADDRESS = "http://status.example/revocation-list"
        const val SYNTHETIC_TSA_OCSP_ADDRESS = "http://status.example/untrusted-tsa"
        const val SYNTHETIC_OCSP_ADDRESS = "http://status.example/ocsp"
        const val SIGNER_COMMON_NAME = "Test Signer"
        const val TAMPER_OFFSET = 5
    }
}

private class SignedPdfFixture private constructor(
    val pdf: ByteArray,
    val certificate: X509Certificate,
    val timestampCertificate: X509Certificate? = null,
) {
    companion object {
        private const val CERTIFICATE_EXTENSIONS_TAG = 0xA3
        private const val URI_TAG = 0x86
        private const val CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31"
        private const val AIA_OID = "1.3.6.1.5.5.7.1.1"
        private const val OCSP_OID = "1.3.6.1.5.5.7.48.1"
        private const val CN_OID = "2.5.4.3"
        private const val ECDSA_WITH_SHA384_OID = "1.2.840.10045.4.3.3"
        private const val ID_DATA_OID = "1.2.840.113549.1.7.1"
        private const val SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
        private const val CONTENT_TYPE_OID = "1.2.840.113549.1.9.3"
        private const val MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"
        private const val SHA384_OID = "2.16.840.1.101.3.4.2.2"
        private const val ID_CT_TST_INFO_OID = "1.2.840.113549.1.9.16.1.4"
        private const val COMMON_NAME = "Test Signer"
        private const val UTF8_STRING_TAG = 0x0C
        private const val UTC_TIME_TAG = 0x17
        private const val BIT_STRING_TAG = 0x03
        private const val EXPLICIT_0_TAG = 0xA0
        private const val CONTEXT_0_TAG = 0xA0
        private const val CMS_VERSION = 1
        private const val CERT_VERSION_V3 = 2
        private const val SERIAL = 4919
        private const val PLACEHOLDER_WIDTH = 10
        private const val FIXED_HEX_LENGTH = 4096

        fun build(
            commonName: String = COMMON_NAME,
            ocspAddress: String? = null,
            revocationListAddress: String? = null,
        ): SignedPdfFixture {
            val keyPair = generateKeyPair()
            val certificate = selfSignedCertificate(keyPair, commonName, ocspAddress, revocationListAddress)

            // A fixed, oversized Contents placeholder removes the
            // circular dependency between the byte range and the CMS
            // length; the CMS is zero-padded to fill it and the parser
            // reads the outer sequence by its own declared length.
            val tail = ">>\nendobj\n%%EOF".encodeToByteArray()

            fun prefixWith(
                start: Int,
                firstLength: Int,
                secondStart: Int,
                secondLength: Int,
            ): ByteArray =
                (
                    "%PDF-1.7\n1 0 obj<</Type/Sig/ByteRange [" +
                        "${pad(start)} ${pad(firstLength)} ${pad(secondStart)} ${pad(secondLength)}" +
                        "]/Contents "
                ).encodeToByteArray()

            val prefixLength = prefixWith(0, 0, 0, 0).size
            val gapLength = FIXED_HEX_LENGTH + 2 // enclosing < and >
            val secondStart = prefixLength + gapLength
            val prefix = prefixWith(0, prefixLength, secondStart, tail.size)
            check(prefix.size == prefixLength) { "prefix length shifted" }

            val messageDigest = MessageDigest.getInstance("SHA-384").digest(prefix + tail)
            val cms = buildCms(keyPair, certificate, messageDigest)
            val hex = cms.joinToString("") { "%02x".format(it) }
            check(hex.length <= FIXED_HEX_LENGTH) { "CMS larger than the placeholder" }
            val paddedHex = hex.padEnd(FIXED_HEX_LENGTH, '0')

            val pdf = prefix + "<$paddedHex>".encodeToByteArray() + tail
            return SignedPdfFixture(pdf, certificate)
        }

        fun buildTimestamped(): SignedPdfFixture {
            val base = build()
            val keyPair = generateKeyPair()
            val tsaCert =
                selfSignedCertificate(
                    keyPair,
                    "Test TSA",
                    "http://status.example/untrusted-tsa",
                    "http://status.example/revocation-list",
                )

            val basePdf = base.pdf
            val tail = ">>\nendobj\n%%EOF".encodeToByteArray()

            fun prefixWith(
                start: Int,
                firstLength: Int,
                secondStart: Int,
                secondLength: Int,
            ): ByteArray =
                basePdf +
                    (
                        "\n2 0 obj<</Type/DocTimeStamp/ByteRange [" +
                            "${pad(start)} ${pad(firstLength)} ${pad(secondStart)} ${pad(secondLength)}" +
                            "]/Contents "
                    ).encodeToByteArray()

            val prefixLength = prefixWith(0, 0, 0, 0).size
            val gapLength = FIXED_HEX_LENGTH + 2
            val secondStart = prefixLength + gapLength
            val prefix = prefixWith(0, prefixLength, secondStart, tail.size)
            check(prefix.size == prefixLength) { "prefix length shifted" }

            val messageDigest = MessageDigest.getInstance("SHA-384").digest(prefix + tail)
            val cms = buildTimeStampCms(keyPair, tsaCert, messageDigest)
            val hex = cms.joinToString("") { "%02x".format(it) }
            check(hex.length <= FIXED_HEX_LENGTH) { "CMS larger than the placeholder" }
            val paddedHex = hex.padEnd(FIXED_HEX_LENGTH, '0')

            val pdf = prefix + "<$paddedHex>".encodeToByteArray() + tail
            return SignedPdfFixture(pdf, base.certificate, tsaCert)
        }

        private fun pad(value: Int): String = value.toString().padStart(PLACEHOLDER_WIDTH, '0')

        private fun generateKeyPair(): KeyPair {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp384r1"))
            return generator.generateKeyPair()
        }

        private fun selfSignedCertificate(
            keyPair: KeyPair,
            commonName: String = COMMON_NAME,
            ocspAddress: String? = null,
            revocationListAddress: String? = null,
        ): X509Certificate {
            val name =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.setOf(
                            listOf(
                                DerEncoder.sequence(
                                    listOf(
                                        DerEncoder.objectIdentifier(CN_OID),
                                        DerEncoder.tlv(UTF8_STRING_TAG, commonName.encodeToByteArray()),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
            val algorithm = DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(ECDSA_WITH_SHA384_OID)))
            val validity =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(UTC_TIME_TAG, "240101000000Z".encodeToByteArray()),
                        DerEncoder.tlv(UTC_TIME_TAG, "340101000000Z".encodeToByteArray()),
                    ),
                )
            val tbs =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(EXPLICIT_0_TAG, DerEncoder.integer(CERT_VERSION_V3)),
                        DerEncoder.integer(SERIAL),
                        algorithm,
                        name,
                        validity,
                        name,
                        keyPair.public.encoded,
                    ) + listOfNotNull(revocationExtensions(ocspAddress, revocationListAddress)),
                )
            val tbsSignature = sign(keyPair, tbs)
            val certificate =
                DerEncoder.sequence(
                    listOf(
                        tbs,
                        algorithm,
                        DerEncoder.tlv(BIT_STRING_TAG, byteArrayOf(0) + tbsSignature),
                    ),
                )
            return CertificateFactory
                .getInstance("X.509")
                .generateCertificate(certificate.inputStream()) as X509Certificate
        }

        private fun revocationExtensions(
            ocspAddress: String?,
            revocationListAddress: String?,
        ): ByteArray? {
            val extensions =
                listOfNotNull(
                    ocspAddress?.let(::ocspExtension),
                    revocationListAddress?.let(::revocationListExtension),
                )
            return if (extensions.isEmpty()) {
                null
            } else {
                DerEncoder.tlv(CERTIFICATE_EXTENSIONS_TAG, DerEncoder.sequence(extensions))
            }
        }

        private fun ocspExtension(address: String): ByteArray =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(AIA_OID),
                    DerEncoder.octetString(
                        DerEncoder.sequence(
                            listOf(
                                DerEncoder.sequence(
                                    listOf(
                                        DerEncoder.objectIdentifier(OCSP_OID),
                                        DerEncoder.tlv(URI_TAG, address.encodeToByteArray()),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )

        private fun revocationListExtension(address: String): ByteArray {
            val pointName =
                DerEncoder.tlv(
                    CONTEXT_0_TAG,
                    DerEncoder.tlv(CONTEXT_0_TAG, DerEncoder.tlv(URI_TAG, address.encodeToByteArray())),
                )
            return DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(CRL_DISTRIBUTION_POINTS_OID),
                    DerEncoder.octetString(DerEncoder.sequence(listOf(DerEncoder.sequence(listOf(pointName))))),
                ),
            )
        }

        private fun buildTstInfo(messageDigest: ByteArray): ByteArray {
            val version = DerEncoder.integer(1)
            val policy = DerEncoder.objectIdentifier("1.2.3.4.5.6")
            val hashAlgo = DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(SHA384_OID)))
            val messageImprint =
                DerEncoder.sequence(
                    listOf(
                        hashAlgo,
                        DerEncoder.octetString(messageDigest),
                    ),
                )
            val serial = DerEncoder.integer(12345)
            val genTime = DerEncoder.tlv(UTC_TIME_TAG, "260829073000Z".encodeToByteArray())
            return DerEncoder.sequence(
                listOf(
                    version,
                    policy,
                    messageImprint,
                    serial,
                    genTime,
                ),
            )
        }

        private fun buildTimeStampCms(
            keyPair: KeyPair,
            certificate: X509Certificate,
            byteRangeDigest: ByteArray,
        ): ByteArray {
            val tstInfo = buildTstInfo(byteRangeDigest)
            val tstInfoDigest = MessageDigest.getInstance("SHA-384").digest(tstInfo)
            val sha384Algorithm = DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(SHA384_OID)))
            val signedAttributes =
                listOf(
                    attribute(CONTENT_TYPE_OID, DerEncoder.objectIdentifier(ID_CT_TST_INFO_OID)),
                    attribute(MESSAGE_DIGEST_OID, DerEncoder.octetString(tstInfoDigest)),
                )
            val signedAttributesSet = DerEncoder.setOf(signedAttributes)
            val signature = sign(keyPair, signedAttributesSet)
            val issuerAndSerial =
                DerEncoder.sequence(
                    listOf(
                        issuerName(certificate),
                        DerEncoder.integer(SERIAL),
                    ),
                )
            val signerInfo =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.integer(CMS_VERSION),
                        issuerAndSerial,
                        sha384Algorithm,
                        DerEncoder.retagged(signedAttributesSet, CONTEXT_0_TAG),
                        DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(ECDSA_WITH_SHA384_OID))),
                        DerEncoder.octetString(signature),
                    ),
                )
            val encapContentInfo =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(ID_CT_TST_INFO_OID),
                        DerEncoder.tlv(EXPLICIT_0_TAG, DerEncoder.octetString(tstInfo)),
                    ),
                )
            val signedData =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.integer(CMS_VERSION),
                        DerEncoder.setOf(listOf(sha384Algorithm)),
                        encapContentInfo,
                        DerEncoder.retagged(DerEncoder.setOf(listOf(certificate.encoded)), CONTEXT_0_TAG),
                        DerEncoder.setOf(listOf(signerInfo)),
                    ),
                )
            return DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(SIGNED_DATA_OID),
                    DerEncoder.tlv(EXPLICIT_0_TAG, signedData),
                ),
            )
        }

        private fun buildCms(
            keyPair: KeyPair,
            certificate: X509Certificate,
            messageDigest: ByteArray,
        ): ByteArray {
            val sha384Algorithm = DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(SHA384_OID)))
            val signedAttributes =
                listOf(
                    attribute(CONTENT_TYPE_OID, DerEncoder.objectIdentifier(ID_DATA_OID)),
                    attribute(MESSAGE_DIGEST_OID, DerEncoder.octetString(messageDigest)),
                )
            val signedAttributesSet = DerEncoder.setOf(signedAttributes)
            val signature = sign(keyPair, signedAttributesSet)
            val issuerAndSerial =
                DerEncoder.sequence(
                    listOf(
                        issuerName(certificate),
                        DerEncoder.integer(SERIAL),
                    ),
                )
            val signerInfo =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.integer(CMS_VERSION),
                        issuerAndSerial,
                        sha384Algorithm,
                        DerEncoder.retagged(signedAttributesSet, CONTEXT_0_TAG),
                        DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(ECDSA_WITH_SHA384_OID))),
                        DerEncoder.octetString(signature),
                    ),
                )
            val signedData =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.integer(CMS_VERSION),
                        DerEncoder.setOf(listOf(sha384Algorithm)),
                        DerEncoder.sequence(listOf(DerEncoder.objectIdentifier(ID_DATA_OID))),
                        DerEncoder.retagged(DerEncoder.setOf(listOf(certificate.encoded)), CONTEXT_0_TAG),
                        DerEncoder.setOf(listOf(signerInfo)),
                    ),
                )
            return DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(SIGNED_DATA_OID),
                    DerEncoder.tlv(EXPLICIT_0_TAG, signedData),
                ),
            )
        }

        private fun issuerName(certificate: X509Certificate): ByteArray {
            val reader = DerReader(certificate.tbsCertificate)
            val tbs = reader.next() ?: error("no tbs")
            val fields = reader.children(tbs)
            fields.next() // version
            fields.next() // serial
            fields.next() // signature algo
            val issuer = fields.next() ?: error("no issuer")
            return fields.raw(issuer)
        }

        private fun attribute(
            oid: String,
            value: ByteArray,
        ): ByteArray =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.objectIdentifier(oid),
                    DerEncoder.setOf(listOf(value)),
                ),
            )

        private fun sign(
            keyPair: KeyPair,
            content: ByteArray,
        ): ByteArray {
            val signer = Signature.getInstance("SHA384withECDSA")
            signer.initSign(keyPair.private)
            signer.update(content)
            return signer.sign()
        }
    }
}
