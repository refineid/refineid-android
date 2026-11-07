// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import java.time.Instant

internal enum class ValidationPathRole {
    DOCUMENT_SIGNER,
    TIMESTAMP_AUTHORITY,
}

internal enum class ValidationMaterialCollectionFailure {
    CANDIDATE_LIMIT_EXCEEDED,
    CERTIFICATE_MALFORMED,
    CHAIN_CYCLE,
    CHAIN_TOO_DEEP,
    ISSUER_UNAVAILABLE,
    PATH_LIMIT_EXCEEDED,
    RANDOM_UNAVAILABLE,
    REVOCATION_UNAVAILABLE,
    REVOKED,
    TRUST_ANCHOR_UNAVAILABLE,
}

internal class ValidationMaterialCollectionException(
    val kind: ValidationMaterialCollectionFailure,
    val pathRole: ValidationPathRole? = null,
) : Exception(
        if (pathRole == null) {
            kind.name
        } else {
            kind.name + ":" + pathRole.name
        },
    )

internal enum class ValidationMaterialGetResource {
    CERTIFICATE,
    REVOCATION_LIST,
}

internal fun interface ValidationMaterialGetter {
    /** The returned byte array transfers to the collector. */
    fun fetch(
        address: String,
        resource: ValidationMaterialGetResource,
    ): ByteArray
}

internal fun interface ValidationMaterialPoster {
    /** The request is borrowed for this call; the returned byte array transfers to the collector. */
    fun send(
        request: ByteArray,
        address: String,
        contentType: String,
    ): ByteArray
}

internal fun interface ValidationSecureRandom {
    /** The returned byte array transfers to the collector. */
    fun generate(byteCount: Int): ByteArray
}

/**
 * Certificates that anchor the collection of a signer's validation material
 * besides the configured trust: the chain the signer's own card carries.
 * Verification never uses them.
 */
internal fun interface SignerAnchorSource {
    /** [signerCertificate] is borrowed; the returned arrays transfer to the caller. */
    fun copyAnchorsFor(signerCertificate: ByteArray): List<ByteArray>

    companion object {
        val NONE = SignerAnchorSource { emptyList() }
    }
}

internal data class ValidationMaterialCollectorDependencies(
    val get: ValidationMaterialGetter,
    val post: ValidationMaterialPoster,
    val now: () -> Instant,
    val random: ValidationSecureRandom,
)

internal class ValidationMaterialCollectionRequest(
    val signerCertificate: ByteArray,
    val timestampTokens: List<VerifiedTimestampToken>,
    val signerTrustCertificates: List<ByteArray>,
    val additionalCandidates: List<ByteArray> = emptyList(),
)

/** Builds complete signer and TSA paths and retains only authenticated validation evidence. */
internal object ValidationMaterialCollector {
    const val MAXIMUM_DEPTH = PdfValidationMaterialLimits.MAXIMUM_CERTIFICATES_PER_PATH
    const val MAXIMUM_CERTIFICATE_ADDRESSES = 3

    fun collect(
        request: ValidationMaterialCollectionRequest,
        dependencies: ValidationMaterialCollectorDependencies,
    ): PdfValidationMaterial {
        if (request.timestampTokens.size > MAXIMUM_TIMESTAMP_PATH_COUNT) {
            throw failure(ValidationMaterialCollectionFailure.PATH_LIMIT_EXCEEDED)
        }
        val evidenceTime = dependencies.now()
        val starts = chainStarts(request, evidenceTime)
        val collection = ValidationMaterialCollection()
        try {
            populateCandidates(request, collection)
            for (start in starts) {
                try {
                    ValidationMaterialCollectorPath.walk(
                        start = start,
                        evidenceTime = evidenceTime,
                        collection = collection,
                        dependencies = dependencies,
                    )
                } catch (_: AuthenticatedRevocationException) {
                    throw failure(
                        kind = ValidationMaterialCollectionFailure.REVOKED,
                        pathRole = start.role,
                    )
                }
            }
            return collection.materialExcluding(request.signerCertificate)
        } finally {
            starts.forEach(ValidationChainStart::close)
            collection.close()
        }
    }

    fun boundedCertificateAddresses(addresses: List<String>): List<String> {
        val selected = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        for (address in addresses) {
            if (seen.add(address)) {
                selected += address
                if (selected.size == MAXIMUM_CERTIFICATE_ADDRESSES) {
                    break
                }
            }
        }
        return selected
    }

    private fun chainStarts(
        request: ValidationMaterialCollectionRequest,
        evidenceTime: Instant,
    ): List<ValidationChainStart> {
        val starts = mutableListOf<ValidationChainStart>()
        var transferred = false
        try {
            for (token in request.timestampTokens) {
                val signer = token.copySignerCertificate()
                val anchor = token.copyTrustedCertificate()
                try {
                    starts +=
                        ValidationChainStart.copyOf(
                            certificate = signer,
                            role = ValidationPathRole.TIMESTAMP_AUTHORITY,
                            referenceTime = token.generatedAt,
                            trustedCertificates = listOf(anchor),
                        )
                } finally {
                    signer.fill(ZERO_BYTE)
                    anchor.fill(ZERO_BYTE)
                }
            }
            starts +=
                ValidationChainStart.copyOf(
                    certificate = request.signerCertificate,
                    role = ValidationPathRole.DOCUMENT_SIGNER,
                    referenceTime = request.timestampTokens.firstOrNull()?.generatedAt ?: evidenceTime,
                    trustedCertificates = request.signerTrustCertificates,
                )
            transferred = true
            return starts
        } finally {
            if (!transferred) {
                starts.forEach(ValidationChainStart::close)
            }
        }
    }

    private fun populateCandidates(
        request: ValidationMaterialCollectionRequest,
        collection: ValidationMaterialCollection,
    ) {
        collection.addCandidate(request.signerCertificate)
        request.additionalCandidates.forEach(collection::addCandidate)
        for (token in request.timestampTokens) {
            token.copySignerCertificate().useBytes { signer ->
                collection.addCandidate(signer)
                collection.addCertificate(signer)
            }
            token.copyVerifiedCertificateChain().useByteArrays { chain ->
                chain.forEach(collection::addCandidate)
            }
            token.copyEmbeddedCertificates().useByteArrays { embedded ->
                embedded.forEach(collection::addCandidate)
            }
        }
    }

    private fun failure(
        kind: ValidationMaterialCollectionFailure,
        pathRole: ValidationPathRole? = null,
    ): ValidationMaterialCollectionException = ValidationMaterialCollectionException(kind, pathRole)

    private inline fun <R> ByteArray.useBytes(operation: (ByteArray) -> R): R =
        try {
            operation(this)
        } finally {
            fill(ZERO_BYTE)
        }

    private inline fun <R> List<ByteArray>.useByteArrays(operation: (List<ByteArray>) -> R): R =
        try {
            operation(this)
        } finally {
            clearBytes()
        }

    private fun List<ByteArray>.clearBytes() {
        forEach { value -> value.fill(ZERO_BYTE) }
    }

    private const val MAXIMUM_TIMESTAMP_PATH_COUNT =
        PdfValidationMaterialLimits.MAXIMUM_VALIDATION_PATH_COUNT - 1
    private const val ZERO_BYTE: Byte = 0
}

internal class ValidationChainStart private constructor(
    private val ownedCertificate: ByteArray,
    val role: ValidationPathRole,
    val referenceTime: Instant,
    private val ownedTrustedCertificates: List<ByteArray>,
) : AutoCloseable {
    val hasTrustAnchor: Boolean
        get() = ownedTrustedCertificates.isNotEmpty()

    fun copyCertificate(): ByteArray = ownedCertificate.copyOf()

    fun trusts(certificate: ByteArray): Boolean =
        ownedTrustedCertificates.any { trusted -> trusted.contentEquals(certificate) }

    override fun close() {
        ownedCertificate.fill(ZERO_BYTE)
        ownedTrustedCertificates.clearBytes()
    }

    companion object {
        fun copyOf(
            certificate: ByteArray,
            role: ValidationPathRole,
            referenceTime: Instant,
            trustedCertificates: List<ByteArray>,
        ): ValidationChainStart {
            if (
                certificate.isEmpty() ||
                certificate.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES ||
                trustedCertificates.any { trusted ->
                    trusted.isEmpty() ||
                        trusted.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
                }
            ) {
                throw ValidationMaterialCollectionException(
                    ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED,
                )
            }
            if (trustedCertificates.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT) {
                throw ValidationMaterialCollectionException(
                    ValidationMaterialCollectionFailure.CANDIDATE_LIMIT_EXCEEDED,
                )
            }
            return ValidationChainStart(
                ownedCertificate = certificate.copyOf(),
                role = role,
                referenceTime = referenceTime,
                ownedTrustedCertificates = trustedCertificates.map(ByteArray::copyOf),
            )
        }

        private fun List<ByteArray>.clearBytes() {
            forEach { value -> value.fill(ZERO_BYTE) }
        }

        private const val ZERO_BYTE: Byte = 0
    }
}

internal class ValidationMaterialCollection : AutoCloseable {
    private val candidates = mutableListOf<ByteArray>()
    private val certificates = mutableListOf<ByteArray>()
    private val checkedCertificates = mutableListOf<ByteArray>()
    private val ocspResponses = mutableListOf<ByteArray>()
    private val revocationLists = mutableListOf<ByteArray>()

    fun addCandidate(certificate: ByteArray) {
        if (
            certificate.isEmpty() ||
            certificate.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
        ) {
            throw failure(ValidationMaterialCollectionFailure.CERTIFICATE_MALFORMED)
        }
        if (candidates.containsEncoding(certificate)) {
            return
        }
        if (candidates.size >= MAXIMUM_CANDIDATE_CERTIFICATE_COUNT) {
            throw failure(ValidationMaterialCollectionFailure.CANDIDATE_LIMIT_EXCEEDED)
        }
        candidates += certificate.copyOf()
    }

    fun addCertificate(certificate: ByteArray) {
        addCandidate(certificate)
        if (certificates.containsEncoding(certificate)) {
            return
        }
        if (certificates.size >= PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT) {
            throw failure(ValidationMaterialCollectionFailure.PATH_LIMIT_EXCEEDED)
        }
        certificates += certificate.copyOf()
    }

    fun directIssuer(
        certificate: ByteArray,
        referenceTime: Instant,
    ): ByteArray? =
        candidates
            .firstOrNull { candidate ->
                !candidate.contentEquals(certificate) &&
                    CertificateIssuer.isDirectlyIssued(certificate, candidate, referenceTime)
            }?.copyOf()

    fun isChecked(certificate: ByteArray): Boolean = checkedCertificates.containsEncoding(certificate)

    fun markChecked(certificate: ByteArray) {
        if (!checkedCertificates.containsEncoding(certificate)) {
            checkedCertificates += certificate.copyOf()
        }
    }

    fun addEvidence(evidence: AuthenticatedStatusEvidence) {
        evidence.useEncoding { encoding ->
            when (evidence.kind) {
                AuthenticatedStatusKind.OCSP -> {
                    addDistinctEvidence(
                        destination = ocspResponses,
                        encoding = encoding,
                        maximumCount = PdfValidationMaterialLimits.MAXIMUM_OCSP_RESPONSE_COUNT,
                    )
                }

                AuthenticatedStatusKind.REVOCATION_LIST -> {
                    addDistinctEvidence(
                        destination = revocationLists,
                        encoding = encoding,
                        maximumCount = PdfValidationMaterialLimits.MAXIMUM_REVOCATION_LIST_COUNT,
                    )
                }
            }
        }
    }

    fun materialExcluding(certificate: ByteArray): PdfValidationMaterial =
        PdfValidationMaterial.copyOf(
            certificates = certificates.filterNot { candidate -> candidate.contentEquals(certificate) },
            ocspResponses = ocspResponses,
            revocationLists = revocationLists,
        )

    override fun close() {
        candidates.clearBytes()
        certificates.clearBytes()
        checkedCertificates.clearBytes()
        ocspResponses.clearBytes()
        revocationLists.clearBytes()
    }

    private fun addDistinctEvidence(
        destination: MutableList<ByteArray>,
        encoding: ByteArray,
        maximumCount: Int,
    ) {
        if (destination.containsEncoding(encoding)) {
            return
        }
        if (destination.size >= maximumCount) {
            throw failure(ValidationMaterialCollectionFailure.PATH_LIMIT_EXCEEDED)
        }
        destination += encoding.copyOf()
    }

    private fun failure(kind: ValidationMaterialCollectionFailure): ValidationMaterialCollectionException =
        ValidationMaterialCollectionException(kind)

    private fun List<ByteArray>.containsEncoding(value: ByteArray): Boolean =
        any { candidate -> candidate.contentEquals(value) }

    private fun MutableList<ByteArray>.clearBytes() {
        forEach { value -> value.fill(ZERO_BYTE) }
        clear()
    }

    private companion object {
        const val CANDIDATE_POOL_MULTIPLIER = 3
        const val MAXIMUM_CANDIDATE_CERTIFICATE_COUNT =
            PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT * CANDIDATE_POOL_MULTIPLIER
        const val ZERO_BYTE: Byte = 0
    }
}
