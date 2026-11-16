// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.security.GeneralSecurityException
import java.security.cert.CertPathBuilder
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

internal enum class TimestampTokenVerificationFailure {
    MALFORMED,
    INVALID_SIGNATURE,
    SIGNER_CERTIFICATE_MISSING,
    AMBIGUOUS_SIGNER,
    SIGNING_CERTIFICATE_MISMATCH,
    INVALID_TIMESTAMP_CERTIFICATE,
    TSA_NAME_MISMATCH,
    UNTRUSTED_SIGNER,
}

internal class TimestampTokenVerificationException(
    val kind: TimestampTokenVerificationFailure,
) : Exception(kind.name)

internal class VerifiedTimestampCertificatePath internal constructor(
    private val ownedCertificates: List<ByteArray>,
    private val ownedTrustAnchor: ByteArray,
) : AutoCloseable {
    val certificateCount: Int
        get() = ownedCertificates.size

    fun copyCertificates(): List<ByteArray> = ownedCertificates.map(ByteArray::copyOf)

    fun copyTrustAnchor(): ByteArray = ownedTrustAnchor.copyOf()

    override fun close() {
        ownedCertificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
        ownedTrustAnchor.fill(ZERO_BYTE)
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** RFC 3161 token authenticated to one exclusive trust anchor. */
internal class VerifiedTimestampToken internal constructor(
    private val ownedEncoding: ByteArray,
    private val ownedMessageImprint: ByteArray,
    private val ownedSignerCertificate: ByteArray,
    private val ownedEmbeddedCertificates: List<ByteArray>,
    private val ownedCertificatePath: VerifiedTimestampCertificatePath,
    val generatedAt: Instant,
) : AutoCloseable {
    private var isClosed = false

    val encodedLength: Int
        get() = ownedEncoding.size

    val embeddedCertificateCount: Int
        get() = ownedEmbeddedCertificates.size

    val verifiedCertificateCount: Int
        get() = ownedCertificatePath.certificateCount

    fun <T> useEncoding(operation: (ByteArray) -> T): T {
        requireOpen()
        val copy = ownedEncoding.copyOf()
        return try {
            operation(copy)
        } finally {
            copy.fill(ZERO_BYTE)
        }
    }

    fun copyEncoding(): ByteArray {
        requireOpen()
        return ownedEncoding.copyOf()
    }

    fun matchesMessageImprint(expected: ByteArray): Boolean {
        requireOpen()
        return java.security.MessageDigest.isEqual(ownedMessageImprint, expected)
    }

    fun copySignerCertificate(): ByteArray {
        requireOpen()
        return ownedSignerCertificate.copyOf()
    }

    fun copyEmbeddedCertificates(): List<ByteArray> {
        requireOpen()
        return ownedEmbeddedCertificates.map(ByteArray::copyOf)
    }

    fun copyVerifiedCertificateChain(): List<ByteArray> {
        requireOpen()
        return ownedCertificatePath.copyCertificates()
    }

    fun copyTrustedCertificate(): ByteArray {
        requireOpen()
        return ownedCertificatePath.copyTrustAnchor()
    }

    override fun close() {
        if (!isClosed) {
            ownedEncoding.fill(ZERO_BYTE)
            ownedMessageImprint.fill(ZERO_BYTE)
            ownedSignerCertificate.fill(ZERO_BYTE)
            ownedEmbeddedCertificates.forEach { certificate -> certificate.fill(ZERO_BYTE) }
            ownedCertificatePath.close()
            isClosed = true
        }
    }

    override fun toString(): String =
        "VerifiedTimestampToken(length=" + encodedLength +
            ", embeddedCertificates=" + embeddedCertificateCount +
            ", verifiedCertificates=" + verifiedCertificateCount +
            ", generatedAt=" + generatedAt +
            ", closed=" + isClosed + ")"

    private fun requireOpen() {
        check(!isClosed) {
            "verified timestamp token is closed"
        }
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}

/** Promotes a request-bound token only after CMS, TSA-profile, and PKIX verification. */
internal object TimestampTokenVerifier {
    fun verify(
        token: UnverifiedTimestampToken,
        trustedCertificates: List<ByteArray>,
    ): VerifiedTimestampToken {
        if (trustedCertificates.isEmpty()) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        }
        return token.useEncoding { encoding ->
            verifyEncoding(
                encoding = encoding,
                requestBoundGenerationTime = token.generatedAt,
                trustedCertificates = trustedCertificates,
            )
        }
    }

    internal fun certificateProfileIsValid(
        certificateDer: ByteArray,
        generatedAt: Instant,
    ): Boolean =
        parseCertificate(certificateDer)?.let { certificate ->
            TimestampCertificateProfile.isPermittedSigner(certificate, generatedAt)
        } ?: false

    private fun verifyEncoding(
        encoding: ByteArray,
        requestBoundGenerationTime: Instant,
        trustedCertificates: List<ByteArray>,
    ): VerifiedTimestampToken {
        val authenticated = TimestampCmsVerifier.authenticate(encoding)
        try {
            val binding =
                try {
                    Rfc3161TstInfoParser.binding(authenticated.tstInfo)
                } catch (_: Rfc3161TimestampException) {
                    throw failure(TimestampTokenVerificationFailure.MALFORMED)
                }
            try {
                if (binding.generatedAt != requestBoundGenerationTime) {
                    throw failure(TimestampTokenVerificationFailure.MALFORMED)
                }
                TimestampSigningCertificateVerifier.verify(
                    signedAttributesSet = authenticated.signedAttributesSet,
                    signerCertificateDer = authenticated.signerCertificate,
                )
                if (
                    !TimestampCertificateProfile.isPermittedSigner(
                        certificate = authenticated.parsedSignerCertificate,
                        generatedAt = binding.generatedAt,
                    )
                ) {
                    throw failure(TimestampTokenVerificationFailure.INVALID_TIMESTAMP_CERTIFICATE)
                }
                if (
                    !TimestampCertificateProfile.tsaNameMatches(
                        name = binding.tsaName,
                        certificateDer = authenticated.signerCertificate,
                        certificate = authenticated.parsedSignerCertificate,
                    )
                ) {
                    throw failure(TimestampTokenVerificationFailure.TSA_NAME_MISMATCH)
                }
                val path =
                    trustedPath(
                        signer = authenticated.parsedSignerCertificate,
                        embeddedCertificates = authenticated.embeddedCertificates,
                        trustedCertificates = trustedCertificates,
                        generatedAt = binding.generatedAt,
                    )
                try {
                    return VerifiedTimestampToken(
                        ownedEncoding = encoding.copyOf(),
                        ownedMessageImprint = binding.digest.copyOf(),
                        ownedSignerCertificate = authenticated.signerCertificate.copyOf(),
                        ownedEmbeddedCertificates =
                            authenticated.embeddedCertificates.map(ByteArray::copyOf),
                        ownedCertificatePath =
                            VerifiedTimestampCertificatePath(
                                ownedCertificates = path.chain.map(X509Certificate::getEncoded),
                                ownedTrustAnchor = path.anchor.encoded,
                            ),
                        generatedAt = binding.generatedAt,
                    )
                } catch (_: CertificateException) {
                    throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
                }
            } finally {
                binding.close()
            }
        } finally {
            authenticated.close()
        }
    }

    private fun trustedPath(
        signer: X509Certificate,
        embeddedCertificates: List<ByteArray>,
        trustedCertificates: List<ByteArray>,
        generatedAt: Instant,
    ): TrustedPath =
        try {
            buildTrustedPath(
                signer = signer,
                embeddedCertificates = embeddedCertificates,
                trustedCertificates = trustedCertificates,
                generatedAt = generatedAt,
            )
        } catch (failure: TimestampTokenVerificationException) {
            throw failure
        } catch (_: GeneralSecurityException) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        } catch (_: ClassCastException) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        }

    private fun buildTrustedPath(
        signer: X509Certificate,
        embeddedCertificates: List<ByteArray>,
        trustedCertificates: List<ByteArray>,
        generatedAt: Instant,
    ): TrustedPath {
        val anchors = parseTrustedCertificates(trustedCertificates)
        anchors.firstOrNull { anchor -> anchor.encoded.contentEquals(signer.encoded) }?.let { anchor ->
            return TrustedPath(chain = listOf(signer), anchor = anchor)
        }
        val embedded = embeddedCertificates.mapNotNull(::parseCertificate)
        val selector = X509CertSelector().apply { certificate = signer }
        val parameters =
            PKIXBuilderParameters(
                anchors.map { certificate -> TrustAnchor(certificate, null) }.toSet(),
                selector,
            )
        parameters.isRevocationEnabled = false
        parameters.date = Date.from(generatedAt)
        parameters.addCertStore(
            CertStore.getInstance(
                COLLECTION_CERT_STORE_ALGORITHM,
                CollectionCertStoreParameters(embedded + anchors),
            ),
        )
        val result = CertPathBuilder.getInstance(PKIX_ALGORITHM).build(parameters) as PKIXCertPathBuilderResult
        val anchor = result.trustAnchor.trustedCert ?: throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        if (anchors.none { trusted -> trusted.encoded.contentEquals(anchor.encoded) }) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        }
        val chain = result.certPath.certificates.map { certificate -> certificate as X509Certificate }
        if (chain.firstOrNull()?.encoded?.contentEquals(signer.encoded) != true) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        }
        return TrustedPath(
            chain =
                if (chain.lastOrNull()?.encoded?.contentEquals(anchor.encoded) == true) {
                    chain
                } else {
                    chain + anchor
                },
            anchor = anchor,
        )
    }

    private fun parseTrustedCertificates(encoded: List<ByteArray>): List<X509Certificate> {
        val parsed = encoded.map(::parseCertificate)
        if (parsed.any { certificate -> certificate == null }) {
            throw failure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER)
        }
        val distinct = mutableListOf<X509Certificate>()
        for (certificate in parsed.filterNotNull()) {
            if (distinct.none { existing -> existing.encoded.contentEquals(certificate.encoded) }) {
                distinct += certificate
            }
        }
        return distinct
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate? =
        try {
            val certificate =
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(encoded.inputStream()) as? X509Certificate
            certificate?.takeIf { parsed -> parsed.encoded.contentEquals(encoded) }
        } catch (_: CertificateException) {
            null
        } catch (_: RuntimeException) {
            null
        }

    private fun failure(kind: TimestampTokenVerificationFailure): TimestampTokenVerificationException =
        TimestampTokenVerificationException(kind)

    private data class TrustedPath(
        val chain: List<X509Certificate>,
        val anchor: X509Certificate,
    )

    private const val X509_CERTIFICATE_TYPE = "X.509"
    private const val PKIX_ALGORITHM = "PKIX"
    private const val COLLECTION_CERT_STORE_ALGORITHM = "Collection"
}
