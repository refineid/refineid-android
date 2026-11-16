// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.network.HttpSigningNetwork
import fi.refineid.android.network.SigningNetworkEndpoint
import fi.refineid.android.network.SigningNetworkLimits
import fi.refineid.android.network.SigningNetworkTransport
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.time.Instant

internal enum class RevocationStatus {
    GOOD,
    REVOKED,
    UNCHECKED,
}

/** One signature's independent verdict over a signed PDF. */
internal data class DocumentSignatureVerdict(
    val signerCommonName: String?,
    val signerIssuer: String?,
    val signerSerialNumber: String?,
    val signingTime: String?,
    val digestAlgorithm: String,
    val signatureAlgorithm: String?,
    val coversWholeDocument: Boolean,
    val digestMatches: Boolean,
    val signatureValid: Boolean,
    val chainTrusted: Boolean,
    val hasSignatureTimestamp: Boolean,
    val isDocumentTimestamp: Boolean = false,
    val revocationStatus: RevocationStatus = RevocationStatus.UNCHECKED,
) {
    /** The cryptographic core: intact bytes, a valid signature, a trusted signer, and not revoked. */
    val isValid: Boolean
        get() =
            digestMatches && signatureValid && (chainTrusted || isDocumentTimestamp) &&
                revocationStatus != RevocationStatus.REVOKED

    val isRevoked: Boolean
        get() = revocationStatus == RevocationStatus.REVOKED

    val isRevocationChecked: Boolean
        get() = revocationStatus == RevocationStatus.GOOD
}

internal sealed interface DocumentValidationResult {
    data class Completed(
        val signatures: List<DocumentSignatureVerdict>,
    ) : DocumentValidationResult {
        val isValid: Boolean
            get() = signatures.isNotEmpty() && signatures.all { it.isValid }

        val isRevoked: Boolean
            get() = signatures.any { it.isRevoked }

        val isRevocationChecked: Boolean
            get() {
                val authorSigs = signatures.filter { !it.isDocumentTimestamp }
                return authorSigs.isNotEmpty() && authorSigs.all { it.isRevocationChecked }
            }
    }

    /** No signature dictionary was found in the document. */
    data object Unsigned : DocumentValidationResult

    /** The bytes were not a parseable PDF signature structure. */
    data object Malformed : DocumentValidationResult
}

/**
 * Independent PAdES-B-B / PAdES-B-LT validation. For each signature it recomputes the
 * signed digest over the byte range, verifies the CMS signature over the
 * signed attributes with the signer's own certificate, confirms the
 * signer chains to a pinned trust anchor, and checks revocation via OCSP / CRL.
 */
internal class DocumentValidator(
    private val trustAnchors: List<X509Certificate>,
    private val checkRevocation: Boolean = true,
    private val transport: SigningNetworkTransport = HttpSigningNetwork(),
) {
    fun validate(bytes: ByteArray): DocumentValidationResult {
        if (fi.refineid.android.asic.AsicValidator
                .isAsic(bytes)
        ) {
            return fi.refineid.android.asic.AsicValidator.validate(
                archiveBytes = bytes,
                trustAnchors = trustAnchors,
                checkRevocation = { cert ->
                    if (checkRevocation && isChainTrusted(cert)) {
                        checkRevocationForCertificate(cert)
                    } else {
                        RevocationStatus.UNCHECKED
                    }
                },
            )
        }
        val signatures = PdfSignatureLocator.locate(bytes)
        if (signatures.isEmpty()) {
            return DocumentValidationResult.Unsigned
        }
        val lastCoversEof = signatures.lastOrNull()?.coversWholeDocument(bytes.size) == true
        val verdicts =
            signatures.mapIndexed { index, signature ->
                val coversWholeDocument =
                    signature.coversWholeDocument(bytes.size) ||
                        (lastCoversEof && isFollowedOnlyByDocumentTimestamps(index, signatures))
                verifySignature(bytes, signature, coversWholeDocument) ?: return DocumentValidationResult.Malformed
            }
        return DocumentValidationResult.Completed(verdicts)
    }

    private fun checkRevocationForCertificate(signerCertificate: X509Certificate): RevocationStatus {
        val issuerCertificate =
            trustAnchors.firstOrNull { candidate ->
                signerCertificate.issuerX500Principal == candidate.subjectX500Principal &&
                    runCatching { signerCertificate.verify(candidate.publicKey) }.isSuccess
            } ?: return RevocationStatus.UNCHECKED
        val facts = CertificateFacts.parse(signerCertificate.encoded) ?: return RevocationStatus.UNCHECKED
        facts.use { parsedFacts ->
            for (url in parsedFacts.ocspUrls) {
                val status = checkOcsp(signerCertificate, issuerCertificate, parsedFacts, url)
                if (status != RevocationStatus.UNCHECKED) {
                    return status
                }
            }
            for (url in parsedFacts.revocationListUrls) {
                val status = checkCrl(signerCertificate, issuerCertificate, url)
                if (status != RevocationStatus.UNCHECKED) {
                    return status
                }
            }
        }
        return RevocationStatus.UNCHECKED
    }

    private fun isFollowedOnlyByDocumentTimestamps(
        fromIndex: Int,
        signatures: List<PdfSignatureLocation>,
    ): Boolean {
        for (i in (fromIndex + 1) until signatures.size) {
            val cms = CmsSignedData.parse(signatures[i].cms) ?: return false
            if (!cms.isDocumentTimestamp) {
                return false
            }
        }
        return true
    }

    private fun verifySignature(
        pdf: ByteArray,
        signature: PdfSignatureLocation,
        coversWholeDocument: Boolean,
    ): DocumentSignatureVerdict? {
        val signedBytes = signature.signedBytes(pdf) ?: return null
        val cms = CmsSignedData.parse(signature.cms) ?: return null
        val signerCertificate = cms.signerCertificate() ?: return null

        val digestMatches =
            cms.messageDigest != null &&
                MessageDigest.getInstance(cms.digestJcaName).digest(signedBytes).contentEquals(cms.messageDigest)

        val signatureValid = verifyCmsSignature(cms, signerCertificate)
        val chainTrusted = if (cms.isDocumentTimestamp) true else isChainTrusted(signerCertificate)
        val revocationStatus =
            if (checkRevocation && isChainTrusted(signerCertificate)) {
                checkRevocation(signerCertificate, cms)
            } else {
                RevocationStatus.UNCHECKED
            }

        return DocumentSignatureVerdict(
            signerCommonName = commonNameOf(signerCertificate.subjectX500Principal.getName("RFC2253")),
            signerIssuer = commonNameOf(signerCertificate.issuerX500Principal.getName("RFC2253")),
            signerSerialNumber = serialNumberOf(signerCertificate),
            signingTime = cms.signingTime,
            digestAlgorithm = cms.digestJcaName,
            signatureAlgorithm = cms.signatureJcaName,
            coversWholeDocument = coversWholeDocument,
            digestMatches = digestMatches,
            signatureValid = signatureValid,
            chainTrusted = chainTrusted,
            hasSignatureTimestamp = cms.hasSignatureTimestamp,
            isDocumentTimestamp = cms.isDocumentTimestamp,
            revocationStatus = revocationStatus,
        )
    }

    private fun checkRevocation(
        signerCertificate: X509Certificate,
        cms: CmsSignedData,
    ): RevocationStatus {
        val issuerCertificate = findIssuerCertificate(signerCertificate, cms) ?: return RevocationStatus.UNCHECKED
        val facts = CertificateFacts.parse(signerCertificate.encoded) ?: return RevocationStatus.UNCHECKED
        facts.use { parsedFacts ->
            // Try OCSP responders first
            for (url in parsedFacts.ocspUrls) {
                val status = checkOcsp(signerCertificate, issuerCertificate, parsedFacts, url)
                if (status != RevocationStatus.UNCHECKED) {
                    return status
                }
            }
            // Fallback to CRL distribution points
            for (url in parsedFacts.revocationListUrls) {
                val status = checkCrl(signerCertificate, issuerCertificate, url)
                if (status != RevocationStatus.UNCHECKED) {
                    return status
                }
            }
        }
        return RevocationStatus.UNCHECKED
    }

    private fun findIssuerCertificate(
        signerCertificate: X509Certificate,
        cms: CmsSignedData,
    ): X509Certificate? {
        val candidates = trustAnchors + cms.allCertificates()
        return candidates.firstOrNull { candidate ->
            signerCertificate.issuerX500Principal == candidate.subjectX500Principal &&
                runCatching { signerCertificate.verify(candidate.publicKey) }.isSuccess
        }
    }

    private fun checkOcsp(
        signerCertificate: X509Certificate,
        issuerCertificate: X509Certificate,
        targetFacts: CertificateFacts,
        url: String,
    ): RevocationStatus =
        try {
            val issuerFacts = CertificateFacts.parse(issuerCertificate.encoded) ?: return RevocationStatus.UNCHECKED
            val nonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT).also { SecureRandom().nextBytes(it) }
            val request =
                issuerFacts.use { parsedIssuer ->
                    targetFacts.useOcspIdentity { issuerName, serialNumber ->
                        parsedIssuer.usePublicKeyBits { publicKeyBits ->
                            OcspRequest.encoded(issuerName, publicKeyBits, serialNumber, nonce)
                        }
                    }
                }
            val response =
                try {
                    httpPost(url, request, "application/ocsp-request")
                } finally {
                    request.fill(0)
                } ?: return RevocationStatus.UNCHECKED

            try {
                OcspResponse.verify(
                    response = response,
                    certificateDer = signerCertificate.encoded,
                    issuerCertificateDer = issuerCertificate.encoded,
                    nonce = nonce,
                    currentTime = Instant.now(),
                )
                RevocationStatus.GOOD
            } catch (e: OcspResponseValidationException) {
                if (e.kind == OcspResponseValidationFailure.REVOKED) {
                    RevocationStatus.REVOKED
                } else {
                    RevocationStatus.UNCHECKED
                }
            } catch (_: Exception) {
                RevocationStatus.UNCHECKED
            }
        } catch (_: Exception) {
            RevocationStatus.UNCHECKED
        }

    private fun checkCrl(
        signerCertificate: X509Certificate,
        issuerCertificate: X509Certificate,
        url: String,
    ): RevocationStatus =
        try {
            val crlBytes = httpGet(url) ?: return RevocationStatus.UNCHECKED
            val cf = CertificateFactory.getInstance("X.509")
            val crl = cf.generateCRL(crlBytes.inputStream()) as? X509CRL ?: return RevocationStatus.UNCHECKED
            crl.verify(issuerCertificate.publicKey)
            val now = java.util.Date()
            if (crl.nextUpdate != null && now.after(crl.nextUpdate)) {
                return RevocationStatus.UNCHECKED
            }
            if (crl.isRevoked(signerCertificate)) {
                RevocationStatus.REVOKED
            } else {
                RevocationStatus.GOOD
            }
        } catch (_: Exception) {
            RevocationStatus.UNCHECKED
        }

    private fun httpPost(
        urlString: String,
        body: ByteArray,
        contentType: String,
    ): ByteArray? =
        try {
            transport.post(
                body = body,
                address = urlString,
                contentType = contentType,
                credentials = null,
                maximumResponseBytes = SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES,
                endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
            )
        } catch (_: Exception) {
            null
        }

    private fun httpGet(urlString: String): ByteArray? =
        try {
            transport.get(
                address = urlString,
                maximumResponseBytes = PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_BYTES,
                endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
            )
        } catch (_: Exception) {
            null
        }

    private fun verifyCmsSignature(
        cms: CmsSignedData,
        signerCertificate: X509Certificate,
    ): Boolean =
        try {
            val jcaName = cms.signatureJcaName ?: return false
            val verifier = Signature.getInstance(jcaName)
            verifier.initVerify(signerCertificate.publicKey)
            verifier.update(cms.signedAttributesForVerification)
            verifier.verify(cms.signatureBytes)
        } catch (_: RuntimeException) {
            false
        } catch (_: java.security.GeneralSecurityException) {
            false
        }

    private fun isChainTrusted(signerCertificate: X509Certificate): Boolean =
        trustAnchors.any { anchor ->
            signerCertificate.issuerX500Principal == anchor.subjectX500Principal &&
                runCatching { signerCertificate.verify(anchor.publicKey) }.isSuccess
        }

    private fun commonNameOf(rfc2253: String): String? =
        COMMON_NAME_PATTERN
            .find(rfc2253)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()
            ?.unescapeRfc2253()

    private fun serialNumberOf(certificate: X509Certificate): String? {
        val rfc2253 = certificate.subjectX500Principal.getName("RFC2253")
        return SERIAL_NUMBER_PATTERN
            .find(rfc2253)
            ?.groupValues
            ?.getOrNull(1)
            ?.trim()
            ?.unescapeRfc2253() ?: certificate.serialNumber.toString(HEX_RADIX)
    }

    private fun String.unescapeRfc2253(): String = replace(Regex("""\\(.)"""), "$1")

    private companion object {
        const val HEX_RADIX = 16
        val COMMON_NAME_PATTERN = Regex("""CN=([^,]+)""")
        val SERIAL_NUMBER_PATTERN = Regex("""(?:SERIALNUMBER|SERIAL)=([^,]+)""", RegexOption.IGNORE_CASE)
    }
}

/** Where one signature lives in the file: its byte range and CMS blob. */
internal data class PdfSignatureLocation(
    val rangeStart: Int,
    val rangeFirstLength: Int,
    val rangeSecondStart: Int,
    val rangeSecondLength: Int,
    val cms: ByteArray,
) {
    fun signedBytes(pdf: ByteArray): ByteArray? {
        val firstEnd = rangeStart.toLong() + rangeFirstLength
        val secondEnd = rangeSecondStart.toLong() + rangeSecondLength
        if (rangeStart < 0 || rangeFirstLength < 0) {
            return null
        }
        if (rangeSecondStart < rangeStart || rangeSecondLength < 0) {
            return null
        }
        if (firstEnd > rangeSecondStart) {
            return null
        }
        if (firstEnd > pdf.size || secondEnd > pdf.size) {
            return null
        }
        val first = pdf.copyOfRange(rangeStart, firstEnd.toInt())
        val second = pdf.copyOfRange(rangeSecondStart, secondEnd.toInt())
        return first + second
    }

    /** Whether the signed range spans the file from its start to its end. */
    fun coversWholeDocument(fileLength: Int): Boolean =
        rangeStart == 0 && rangeSecondStart.toLong() + rangeSecondLength == fileLength.toLong()

    override fun equals(other: Any?): Boolean = this === other

    override fun hashCode(): Int = System.identityHashCode(this)
}
