// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.document.ArchivalLevelPolicy
import fi.refineid.android.document.BaselineLevel
import fi.refineid.android.document.QualifiedPdfTimestampPhase
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationPathRole
import java.time.Instant

/** Why a container could not be produced. */
internal sealed interface AsicSigningFailure {
    /** No files, or a name the container cannot carry. Refused before the card is touched. */
    data object UnusableNames : AsicSigningFailure

    /** The signing key is one no qualified algorithm covers. */
    data object KeyProfileUnsupported : AsicSigningFailure

    /** The finished entries overflowed the container's 32-bit fields. */
    data object ContainerOverflow : AsicSigningFailure

    /** The qualified certificate could not be read. */
    data class Certificate(
        val kind: NativeCertificateReadFailure,
    ) : AsicSigningFailure

    /** The card refused or failed the signature. */
    data class Card(
        val kind: QualifiedSignFailure,
    ) : AsicSigningFailure

    /** No verified timestamp for the exact digest of [phase] was obtained. */
    data class Timestamp(
        val phase: QualifiedPdfTimestampPhase,
    ) : AsicSigningFailure

    /**
     * The archive timestamp's signer path is not entirely inside the
     * CertificateValues already written, so a later verifier could not
     * validate it from the container alone.
     */
    data object ArchiveTimestampPathUncovered : AsicSigningFailure

    /** OCSP/CRL validation material collection failed. */
    data class Validation(
        val kind: ValidationMaterialCollectionFailure,
        val pathRole: ValidationPathRole?,
    ) : AsicSigningFailure

    /** Network/validation sources unavailable. */
    data object ValidationUnavailable : AsicSigningFailure

    /** Completion after the card signature stopped on an unexpected fault. */
    data object InternalError : AsicSigningFailure
}

/** The container bytes, or why they could not be produced. */
internal sealed interface AsicSigningResult {
    /** A container whose signature is XAdES-B-LTA. */
    class Success(
        val container: ByteArray,
    ) : AsicSigningResult

    /**
     * Only under [ArchivalLevelPolicy.HIGHEST_REACHED]: B-LTA failed with
     * [reason], and [container] carries the [level] reached before it.
     */
    class BelowLongTerm(
        val container: ByteArray,
        val level: BaselineLevel,
        val reason: AsicSigningFailure,
    ) : AsicSigningResult {
        override fun toString(): String = "BelowLongTerm(level=" + level + ", reason=" + reason + ")"
    }

    class Failure(
        val reason: AsicSigningFailure,
    ) : AsicSigningResult
}

/**
 * Has the card sign a set of files for one ASiC-E container, ported from
 * the reference `AsicSigner`. [QualifiedAsicArchivalCompletion] turns the
 * prepared signature into the container.
 */
internal class AsicSigningCoordinator(
    private val cardService: QualifiedCardService,
    private val now: () -> Instant = Instant::now,
) {
    fun prepare(
        objects: List<AsicDataObject>,
        pin2: Pin2Submission,
        onResult: (PreparedAsicSignatureResult) -> Unit,
    ) {
        if (objects.isEmpty() || !AsicContainer.areNamesUsable(objects)) {
            pin2.close()
            onResult(PreparedAsicSignatureResult.Failure(AsicSigningFailure.UnusableNames))
            return
        }
        cardService.requestQualifiedCertificate { certificateResult ->
            when (certificateResult) {
                is NativeCertificateReadResult.Failure -> {
                    pin2.close()
                    onResult(
                        PreparedAsicSignatureResult.Failure(AsicSigningFailure.Certificate(certificateResult.kind)),
                    )
                }

                is NativeCertificateReadResult.Success -> {
                    val certificate = certificateResult.certificate
                    val algorithm =
                        QualifiedSigningAlgorithm.entries.firstOrNull { it.keyProfile == certificate.keyProfile }
                    if (algorithm == null) {
                        certificate.close()
                        pin2.close()
                        onResult(PreparedAsicSignatureResult.Failure(AsicSigningFailure.KeyProfileUnsupported))
                        return@requestQualifiedCertificate
                    }
                    val certDer = certificate.copyDer()
                    val plan =
                        XadesSignature.plan(
                            profile = certificate.keyProfile,
                            objects = objects,
                            certificateDer = certDer,
                            signedAt = now(),
                        )
                    cardService.requestQualifiedSignature(
                        algorithm = algorithm,
                        pin2 = pin2,
                        content = plan.signedInfo.encodeToByteArray(),
                        expectedCertificate = certificate,
                    ) { signatureResult ->
                        certificate.close()
                        when (signatureResult) {
                            is QualifiedSignResult.Failure -> {
                                certDer.fill(0)
                                onResult(
                                    PreparedAsicSignatureResult.Failure(AsicSigningFailure.Card(signatureResult.kind)),
                                )
                            }

                            is QualifiedSignResult.Success -> {
                                val rawSignature = signatureResult.signature.useBytes { it.copyOf() }
                                signatureResult.signature.close()
                                onResult(
                                    PreparedAsicSignatureResult.Success(
                                        PreparedAsicSignature(
                                            plan = plan,
                                            objects = objects,
                                            rawSignature = rawSignature,
                                            certificateDer = certDer,
                                        ),
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
