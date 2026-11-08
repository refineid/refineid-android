// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.document.ArchivalLevelPolicy
import fi.refineid.android.document.BaselineLevel
import fi.refineid.android.document.PdfValidationMaterial
import fi.refineid.android.document.QualifiedPdfTimestampPhase
import fi.refineid.android.document.QualifiedPdfTimestampSource
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import fi.refineid.android.document.QualifiedPdfValidationSource
import fi.refineid.android.document.QualifiedPdfValidationSourceException
import fi.refineid.android.document.ValidationMaterialCollectionException
import fi.refineid.android.document.VerifiedTimestampToken

/**
 * Synchronous XAdES-B-LTA completion of a prepared ASiC-E signature, in
 * this order: the signature timestamp over the SignatureValue, the
 * authenticated validation material for the signer and that timestamp's
 * authority, then the archive timestamp over every preceding part of the
 * signature (ETSI EN 319 132-1 V1.3.1 clause 5.5.2.3). Callers must
 * invoke it away from the UI thread.
 */
internal object QualifiedAsicArchivalCompletion {
    fun complete(
        prepared: PreparedAsicSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
        policy: ArchivalLevelPolicy,
    ): AsicSigningResult =
        try {
            AsicSigningResult.Success(
                completeOwned(
                    prepared = prepared,
                    timestampSource = timestampSource,
                    validationSource = validationSource,
                    policy = policy,
                ),
            )
        } catch (reduced: ReducedCompletion) {
            AsicSigningResult.BelowLongTerm(
                container = reduced.container,
                level = reduced.level,
                reason = reduced.reason,
            )
        } catch (failure: AsicArchivalException) {
            AsicSigningResult.Failure(failure.reason)
        } catch (_: RuntimeException) {
            AsicSigningResult.Failure(AsicSigningFailure.InternalError)
        } finally {
            prepared.close()
        }

    private fun completeOwned(
        prepared: PreparedAsicSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
        policy: ArchivalLevelPolicy,
    ): ByteArray {
        val plan = prepared.plan
        val signature = prepared.rawSignature
        val signatureTimestamp =
            XadesSignature.timestampDigest(signature).useOwnedBytes { signatureDigest ->
                reachedOnFailure(policy, prepared, BaselineLevel.B_B, { plan.document(signature) }) {
                    acquireTimestamp(timestampSource, signatureDigest, QualifiedPdfTimestampPhase.SIGNATURE)
                }
            }
        return signatureTimestamp.use { verifiedSignatureTimestamp ->
            verifiedSignatureTimestamp.copyEncoding().useOwnedBytes { signatureTokenBytes ->
                val tokens = listOf(signatureTokenBytes)
                reachedOnFailure(policy, prepared, BaselineLevel.B_T, { plan.document(signature, tokens) }) {
                    validationMaterial(validationSource, prepared.certificateDer, verifiedSignatureTimestamp)
                }.use { material ->
                    val longTermDocument = { plan.document(signature, tokens, material) }
                    reachedOnFailure(policy, prepared, BaselineLevel.B_LT, longTermDocument) {
                        archiveTimestamp(prepared, timestampSource, tokens, material)
                    }.use { archiveTimestamp ->
                        archiveTimestamp.copyEncoding().useOwnedBytes { archiveTokenBytes ->
                            reachedOnFailure(policy, prepared, BaselineLevel.B_LT, longTermDocument) {
                                container(
                                    prepared,
                                    plan.document(signature, tokens, material, archiveTokenBytes),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Runs [operation], the step above [level]. Under
     * [ArchivalLevelPolicy.HIGHEST_REACHED] its typed failure ends the
     * completion with the container [reachedDocument] builds at [level];
     * under [ArchivalLevelPolicy.LONG_TERM_ONLY] it ends it with nothing.
     */
    private inline fun <T> reachedOnFailure(
        policy: ArchivalLevelPolicy,
        prepared: PreparedAsicSignature,
        level: BaselineLevel,
        reachedDocument: () -> String,
        operation: () -> T,
    ): T =
        try {
            operation()
        } catch (failure: AsicArchivalException) {
            if (policy != ArchivalLevelPolicy.HIGHEST_REACHED) {
                throw failure
            }
            throw ReducedCompletion(
                container = container(prepared, reachedDocument()),
                level = level,
                reason = failure.reason,
                cause = failure,
            )
        }

    /**
     * The archive timestamp over the signature as written so far. It is
     * accepted only for the exact imprint requested and only when its
     * signer path lies entirely inside the CertificateValues [material]
     * writes, the same authenticated collection that covers the
     * signature timestamp's authority.
     */
    private fun archiveTimestamp(
        prepared: PreparedAsicSignature,
        source: QualifiedPdfTimestampSource,
        signatureTimestamps: List<ByteArray>,
        material: PdfValidationMaterial,
    ): VerifiedTimestampToken {
        val token =
            prepared.plan
                .archiveTimestampDigest(prepared.rawSignature, signatureTimestamps, material)
                .useOwnedBytes { archiveDigest ->
                    acquireTimestamp(source, archiveDigest, QualifiedPdfTimestampPhase.ARCHIVE)
                }
        var accepted = false
        try {
            if (!signerPathCovered(token, material)) {
                throw AsicArchivalException(AsicSigningFailure.ArchiveTimestampPathUncovered)
            }
            accepted = true
            return token
        } finally {
            if (!accepted) {
                token.close()
            }
        }
    }

    /** Whether the token's signer, its verified chain and its trust anchor are all among [material]'s certificates. */
    private fun signerPathCovered(
        token: VerifiedTimestampToken,
        material: PdfValidationMaterial,
    ): Boolean {
        val path =
            listOf(token.copySignerCertificate()) + token.copyVerifiedCertificateChain() +
                listOf(token.copyTrustedCertificate())
        return try {
            material.useCopies { certificates, _, _ ->
                path.all { required -> certificates.any { written -> written.contentEquals(required) } }
            }
        } finally {
            path.forEach { certificate -> certificate.fill(CLEARED_BYTE) }
        }
    }

    private fun container(
        prepared: PreparedAsicSignature,
        document: String,
    ): ByteArray =
        AsicContainer.container(prepared.objects, document.encodeToByteArray())
            ?: throw AsicArchivalException(AsicSigningFailure.ContainerOverflow)

    private fun acquireTimestamp(
        source: QualifiedPdfTimestampSource,
        digest: ByteArray,
        phase: QualifiedPdfTimestampPhase,
    ): VerifiedTimestampToken {
        val token =
            try {
                source.acquire(digest)
            } catch (failure: QualifiedPdfTimestampSourceException) {
                throw AsicArchivalException(AsicSigningFailure.Timestamp(phase), failure)
            }
        val matches =
            try {
                token.matchesMessageImprint(digest)
            } catch (_: IllegalStateException) {
                false
            }
        if (!matches) {
            token.close()
            throw AsicArchivalException(AsicSigningFailure.Timestamp(phase))
        }
        return token
    }

    private fun validationMaterial(
        source: QualifiedPdfValidationSource,
        signerCertificate: ByteArray,
        signatureTimestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial =
        try {
            source.collect(
                signerCertificate = signerCertificate,
                signatureTimestamp = signatureTimestamp,
            )
        } catch (failure: ValidationMaterialCollectionException) {
            throw AsicArchivalException(AsicSigningFailure.Validation(failure.kind, failure.pathRole), failure)
        } catch (failure: QualifiedPdfValidationSourceException) {
            throw AsicArchivalException(AsicSigningFailure.ValidationUnavailable, failure)
        }

    private inline fun <T> ByteArray.useOwnedBytes(operation: (ByteArray) -> T): T =
        try {
            operation(this)
        } finally {
            fill(CLEARED_BYTE)
        }

    /** Carries the container reached below B-LTA out of the completion. */
    private class ReducedCompletion(
        val container: ByteArray,
        val level: BaselineLevel,
        val reason: AsicSigningFailure,
        cause: Throwable,
    ) : RuntimeException(null, cause)

    private class AsicArchivalException(
        val reason: AsicSigningFailure,
        cause: Throwable? = null,
    ) : RuntimeException(null, cause)

    private const val CLEARED_BYTE: Byte = 0
}
