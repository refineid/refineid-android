// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import fi.refineid.android.diagnostics.AppTrace

/** Sanitized orchestration stage exposed only to the variant trace sink. */
internal enum class QualifiedPdfArchivalStage {
    SIGNATURE_TIMESTAMP,
    TIMESTAMPED_SIGNATURE,
    VALIDATION_MATERIAL,
    ARCHIVE_PREPARATION,
    ARCHIVE_TIMESTAMP,
}

/** The exact RFC 3161 request whose failure prevented archival completion. */
internal enum class QualifiedPdfTimestampPhase {
    SIGNATURE,
    ARCHIVE,
}

/** Coarse failure from an injected timestamp source after its own retry policy. */
internal class QualifiedPdfTimestampSourceException : RuntimeException()

internal fun interface QualifiedPdfTimestampSource {
    /** The digest is borrowed; the returned verified token transfers to the caller. */
    fun acquire(digest: ByteArray): VerifiedTimestampToken
}

/** Coarse non-path failure from an injected validation-material source. */
internal class QualifiedPdfValidationSourceException : RuntimeException()

internal fun interface QualifiedPdfValidationSource {
    /** Inputs are borrowed; the returned validation material transfers to the caller. */
    fun collect(
        signerCertificate: ByteArray,
        signatureTimestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial
}

internal sealed interface QualifiedPdfArchivalFailure {
    data class Timestamp(
        val phase: QualifiedPdfTimestampPhase,
    ) : QualifiedPdfArchivalFailure

    data class Validation(
        val kind: ValidationMaterialCollectionFailure,
        val pathRole: ValidationPathRole?,
    ) : QualifiedPdfArchivalFailure

    data class Cms(
        val kind: QualifiedDocumentCmsFailure,
    ) : QualifiedPdfArchivalFailure

    data class Document(
        val kind: PdfSigningFailure,
    ) : QualifiedPdfArchivalFailure

    data object ValidationUnavailable : QualifiedPdfArchivalFailure

    data object InternalError : QualifiedPdfArchivalFailure
}

/** A PAdES baseline level a completion reached before it stopped. */
internal enum class PadesBaselineLevel(
    /** The level's name in ETSI EN 319 142-1, clause 6. */
    val label: String,
) {
    /** The card signature with its certificate, no timestamp. */
    B_B("B-B"),

    /** B-B with a signature timestamp. */
    B_T("B-T"),
}

/**
 * What a completion does when it cannot reach PAdES-B-LTA. The build
 * fixes it at compile time through [forBuild]; nothing at run time
 * selects it.
 */
internal enum class PadesLevelPolicy {
    /** Only a PAdES-B-LTA document leaves the completion; anything less is discarded. */
    LONG_TERM_ONLY,

    /** The highest level reached is handed out, named by its level, for development use. */
    HIGHEST_REACHED,
    ;

    companion object {
        /** A release build makes only B-LTA documents; a debug build keeps what it reached. */
        fun forBuild(isDebugBuild: Boolean): PadesLevelPolicy =
            if (isDebugBuild) {
                HIGHEST_REACHED
            } else {
                LONG_TERM_ONLY
            }
    }
}

internal sealed interface QualifiedPdfArchivalResult {
    class Success(
        val document: SignedPdfDocument,
    ) : QualifiedPdfArchivalResult {
        override fun toString(): String = "Success(" + document + ")"
    }

    /**
     * Only under [PadesLevelPolicy.HIGHEST_REACHED]: B-LTA failed with
     * [kind], and [document] carries the [level] reached before it.
     */
    class BelowLongTerm(
        val document: SignedPdfDocument,
        val level: PadesBaselineLevel,
        val kind: QualifiedPdfArchivalFailure,
    ) : QualifiedPdfArchivalResult {
        override fun toString(): String = "BelowLongTerm(level=" + level + ", kind=" + kind + ", " + document + ")"
    }

    data class Failure(
        val kind: QualifiedPdfArchivalFailure,
    ) : QualifiedPdfArchivalResult
}

/** Synchronous PAdES-B-LTA completion. Callers must invoke it away from the UI thread. */
internal object QualifiedPdfArchivalCompletion {
    fun complete(
        prepared: PreparedQualifiedPdfSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
        policy: PadesLevelPolicy,
    ): QualifiedPdfArchivalResult {
        val startedAt = AppTrace.qualifiedPdfArchivalStarted()
        val result =
            try {
                QualifiedPdfArchivalResult.Success(
                    completeOwned(
                        prepared = prepared,
                        timestampSource = timestampSource,
                        validationSource = validationSource,
                        policy = policy,
                    ),
                )
            } catch (reduced: ReducedCompletion) {
                QualifiedPdfArchivalResult.BelowLongTerm(
                    document = reduced.document,
                    level = reduced.level,
                    kind = reduced.kind,
                )
            } catch (failure: CompletionException) {
                QualifiedPdfArchivalResult.Failure(failure.kind)
            } catch (failure: QualifiedDocumentCmsException) {
                QualifiedPdfArchivalResult.Failure(
                    QualifiedPdfArchivalFailure.Cms(failure.kind),
                )
            } catch (failure: PdfSigningException) {
                QualifiedPdfArchivalResult.Failure(
                    QualifiedPdfArchivalFailure.Document(failure.kind),
                )
            } catch (_: RuntimeException) {
                QualifiedPdfArchivalResult.Failure(QualifiedPdfArchivalFailure.InternalError)
            } finally {
                prepared.close()
            }
        AppTrace.qualifiedPdfArchivalCompleted(startedAt = startedAt, result = result)
        return result
    }

    private fun completeOwned(
        prepared: PreparedQualifiedPdfSignature,
        timestampSource: QualifiedPdfTimestampSource,
        validationSource: QualifiedPdfValidationSource,
        policy: PadesLevelPolicy,
    ): SignedPdfDocument =
        prepared.copySignerCertificate().useOwnedBytes { signerCertificate ->
            prepared.signatureTimestampDigest().useOwnedBytes { signatureDigest ->
                AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.SIGNATURE_TIMESTAMP)
                signatureTimestamp(
                    prepared = prepared,
                    source = timestampSource,
                    digest = signatureDigest,
                    policy = policy,
                ).use { signatureTimestamp ->
                    AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.TIMESTAMPED_SIGNATURE)
                    prepared.completeTimestamped(listOf(signatureTimestamp)).use { timestampedDocument ->
                        keepingReached(policy, timestampedDocument, PadesBaselineLevel.B_T) {
                            AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.VALIDATION_MATERIAL)
                            validationMaterial(
                                source = validationSource,
                                signerCertificate = signerCertificate,
                                signatureTimestamp = signatureTimestamp,
                            ).use { material ->
                                timestampedDocument.copyBytes().useOwnedBytes { timestampedBytes ->
                                    AppTrace.qualifiedPdfArchivalStage(
                                        QualifiedPdfArchivalStage.ARCHIVE_PREPARATION,
                                    )
                                    completeArchiveTimestamp(
                                        timestampedDocument = timestampedBytes,
                                        validationMaterial = material,
                                        timestampSource = timestampSource,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

    /**
     * The signature timestamp. Under [PadesLevelPolicy.HIGHEST_REACHED] a
     * failed request ends the completion with the B-B document instead.
     */
    private fun signatureTimestamp(
        prepared: PreparedQualifiedPdfSignature,
        source: QualifiedPdfTimestampSource,
        digest: ByteArray,
        policy: PadesLevelPolicy,
    ): VerifiedTimestampToken =
        try {
            acquireTimestamp(
                source = source,
                digest = digest,
                phase = QualifiedPdfTimestampPhase.SIGNATURE,
            )
        } catch (failure: CompletionException) {
            if (policy != PadesLevelPolicy.HIGHEST_REACHED) {
                throw failure
            }
            throw ReducedCompletion(
                document = prepared.completeBaseline(),
                level = PadesBaselineLevel.B_B,
                kind = failure.kind,
                cause = failure,
            )
        }

    /**
     * Runs the stages above [reached]. Under [PadesLevelPolicy.HIGHEST_REACHED]
     * a typed failure there ends the completion with a copy of [reached].
     */
    private inline fun <T> keepingReached(
        policy: PadesLevelPolicy,
        reached: SignedPdfDocument,
        level: PadesBaselineLevel,
        operation: () -> T,
    ): T =
        try {
            operation()
        } catch (failure: CompletionException) {
            throw reducedOr(failure, policy, reached, level, failure.kind)
        } catch (failure: QualifiedDocumentCmsException) {
            throw reducedOr(failure, policy, reached, level, QualifiedPdfArchivalFailure.Cms(failure.kind))
        } catch (failure: PdfSigningException) {
            throw reducedOr(failure, policy, reached, level, QualifiedPdfArchivalFailure.Document(failure.kind))
        }

    /** [failure] itself, or under [PadesLevelPolicy.HIGHEST_REACHED] the reduced completion carrying [reached]. */
    private fun reducedOr(
        failure: RuntimeException,
        policy: PadesLevelPolicy,
        reached: SignedPdfDocument,
        level: PadesBaselineLevel,
        kind: QualifiedPdfArchivalFailure,
    ): RuntimeException =
        if (policy == PadesLevelPolicy.HIGHEST_REACHED) {
            ReducedCompletion(
                document = SignedPdfDocument(reached.copyBytes()),
                level = level,
                kind = kind,
                cause = failure,
            )
        } else {
            failure
        }

    private fun completeArchiveTimestamp(
        timestampedDocument: ByteArray,
        validationMaterial: PdfValidationMaterial,
        timestampSource: QualifiedPdfTimestampSource,
    ): SignedPdfDocument =
        PdfArchiveTimestamp
            .prepare(
                timestampedDocument = timestampedDocument,
                validationMaterial = validationMaterial,
            ).use { preparedArchiveTimestamp ->
                preparedArchiveTimestamp.copyDigest().useOwnedBytes { archiveDigest ->
                    AppTrace.qualifiedPdfArchivalStage(QualifiedPdfArchivalStage.ARCHIVE_TIMESTAMP)
                    acquireTimestamp(
                        source = timestampSource,
                        digest = archiveDigest,
                        phase = QualifiedPdfTimestampPhase.ARCHIVE,
                    ).use { archiveTimestamp ->
                        try {
                            preparedArchiveTimestamp.complete(archiveTimestamp)
                        } catch (_: PdfArchiveTimestampException) {
                            throw completionFailure(QualifiedPdfTimestampPhase.ARCHIVE)
                        }
                    }
                }
            }

    private fun acquireTimestamp(
        source: QualifiedPdfTimestampSource,
        digest: ByteArray,
        phase: QualifiedPdfTimestampPhase,
    ): VerifiedTimestampToken {
        val token =
            try {
                source.acquire(digest)
            } catch (_: QualifiedPdfTimestampSourceException) {
                throw completionFailure(phase)
            }
        val matches =
            try {
                token.matchesMessageImprint(digest)
            } catch (_: IllegalStateException) {
                false
            }
        if (!matches) {
            token.close()
            throw completionFailure(phase)
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
            throw CompletionException(
                kind =
                    QualifiedPdfArchivalFailure.Validation(
                        kind = failure.kind,
                        pathRole = failure.pathRole,
                    ),
                cause = failure,
            )
        } catch (_: QualifiedPdfValidationSourceException) {
            throw CompletionException(QualifiedPdfArchivalFailure.ValidationUnavailable)
        }

    private fun completionFailure(phase: QualifiedPdfTimestampPhase): CompletionException =
        CompletionException(QualifiedPdfArchivalFailure.Timestamp(phase))

    private inline fun <T> ByteArray.useOwnedBytes(operation: (ByteArray) -> T): T =
        try {
            operation(this)
        } finally {
            fill(CLEARED_BYTE)
        }

    /** Carries the document reached below B-LTA out of the completion. */
    private class ReducedCompletion(
        val document: SignedPdfDocument,
        val level: PadesBaselineLevel,
        val kind: QualifiedPdfArchivalFailure,
        cause: Throwable,
    ) : RuntimeException(null, cause)

    private class CompletionException(
        val kind: QualifiedPdfArchivalFailure,
        cause: Throwable? = null,
    ) : RuntimeException(null, cause)

    private const val CLEARED_BYTE: Byte = 0
}
