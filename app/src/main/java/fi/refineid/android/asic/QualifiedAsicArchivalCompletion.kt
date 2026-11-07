// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.document.PdfValidationMaterial
import fi.refineid.android.document.QualifiedPdfTimestampSource
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import fi.refineid.android.document.QualifiedPdfValidationSource
import fi.refineid.android.document.QualifiedPdfValidationSourceException
import fi.refineid.android.document.ValidationMaterialCollectionException
import fi.refineid.android.document.VerifiedTimestampToken

internal object QualifiedAsicArchivalCompletion {
    fun complete(
        prepared: PreparedAsicSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
    ): AsicSigningResult {
        return try {
            val signatureDigest = XadesSignature.timestampDigest(prepared.rawSignature)
            val signatureTimestamp = acquireTimestamp(timestampSource, signatureDigest)
            try {
                val material = validationMaterial(validationSource, prepared.certificateDer, signatureTimestamp)
                try {
                    val tokenBytes = signatureTimestamp.copyEncoding()
                    try {
                        val document =
                            prepared.plan.document(
                                xmlSignature = prepared.rawSignature,
                                timestampTokens = listOf(tokenBytes),
                                material = material,
                            )
                        val archive = AsicContainer.container(prepared.objects, document.encodeToByteArray())
                        if (archive == null) {
                            AsicSigningResult.Failure(AsicSigningFailure.ContainerOverflow)
                        } else {
                            AsicSigningResult.Success(archive)
                        }
                    } finally {
                        tokenBytes.fill(0)
                    }
                } finally {
                    material.close()
                }
            } finally {
                signatureTimestamp.close()
            }
        } catch (failure: AsicArchivalException) {
            AsicSigningResult.Failure(failure.reason)
        } catch (_: RuntimeException) {
            AsicSigningResult.Failure(AsicSigningFailure.InternalError)
        } finally {
            prepared.close()
        }
    }

    private fun acquireTimestamp(
        source: QualifiedPdfTimestampSource,
        digest: ByteArray,
    ): VerifiedTimestampToken {
        val token =
            try {
                source.acquire(digest)
            } catch (failure: QualifiedPdfTimestampSourceException) {
                throw AsicArchivalException(AsicSigningFailure.Timestamp, failure)
            }
        val matches =
            try {
                token.matchesMessageImprint(digest)
            } catch (_: IllegalStateException) {
                false
            }
        if (!matches) {
            token.close()
            throw AsicArchivalException(AsicSigningFailure.Timestamp)
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

    private class AsicArchivalException(
        val reason: AsicSigningFailure,
        cause: Throwable? = null,
    ) : RuntimeException(null, cause)
}
