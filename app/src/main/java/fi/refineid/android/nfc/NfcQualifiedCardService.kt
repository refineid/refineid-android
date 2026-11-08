package fi.refineid.android.nfc

import android.os.Handler
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightFailure
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/**
 * Qualified document signing over one holder-opened contactless
 * session. Each request re-runs PACE on the session worker thread; the
 * certificate read, PIN2 preflight, and signature never touch the main
 * thread, and a request is dropped if the session generation moved.
 */
internal class NfcQualifiedCardService(
    private val probeExecutor: ExecutorService,
    private val mainHandler: Handler,
    private val isReady: () -> Boolean,
    private val currentGeneration: () -> Int,
    private val activeSession: () -> ContactlessCardSession?,
) : QualifiedCardService {
    override fun requestQualifiedCertificate(
        onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit,
    ) {
        if (!isReady()) {
            onResult(certificateUnavailable())
            return
        }
        val generation = currentGeneration()
        try {
            probeExecutor.execute {
                val result =
                    if (generation == currentGeneration()) {
                        try {
                            activeSession()?.readQualifiedCertificate() ?: certificateUnavailable()
                        } catch (_: RuntimeException) {
                            NativeCertificateReadResult.Failure(
                                NativeCertificateReadFailure.BRIDGE_ERROR,
                            )
                        }
                    } else {
                        certificateUnavailable()
                    }
                if (result is NativeCertificateReadResult.Failure &&
                    result.kind == NativeCertificateReadFailure.PACE_REJECTED
                ) {
                    fi.refineid.android.core.CanSessionStore
                        .drop()
                }
                mainHandler.post {
                    if (generation == currentGeneration()) {
                        onResult(result)
                    } else {
                        result.closeCertificate()
                        onResult(certificateUnavailable())
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            onResult(certificateUnavailable())
        }
    }

    override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit) {
        if (!isReady()) {
            onResult(pin2Unavailable())
            return
        }
        val generation = currentGeneration()
        try {
            probeExecutor.execute {
                val result =
                    if (generation == currentGeneration()) {
                        try {
                            activeSession()?.probePin2Status() ?: pin2Unavailable()
                        } catch (_: RuntimeException) {
                            NativePin2PreflightResult.Failure(
                                NativePin2PreflightFailure.BRIDGE_ERROR,
                            )
                        }
                    } else {
                        pin2Unavailable()
                    }
                mainHandler.post {
                    if (generation == currentGeneration()) {
                        onResult(result)
                    } else {
                        onResult(pin2Unavailable())
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            onResult(pin2Unavailable())
        }
    }

    override fun requestQualifiedSignature(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        content: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    ) = requestQualifiedInput(
        pin2 = pin2,
        input = content,
        expectedCertificate = expectedCertificate,
        onResult = onResult,
        signer = { session, cert, input ->
            session.qualifiedSign(
                algorithm = algorithm,
                pin2 = pin2,
                content = input,
                expectedCertificate = cert,
            )
        },
    )

    override fun requestQualifiedDigestSignature(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        digest: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    ) = requestQualifiedInput(
        pin2 = pin2,
        input = digest,
        expectedCertificate = expectedCertificate,
        onResult = onResult,
        signer = { session, cert, input ->
            session.qualifiedSignPrehashed(
                algorithm = algorithm,
                pin2 = pin2,
                digest = input,
                expectedCertificate = cert,
            )
        },
    )

    private fun requestQualifiedInput(
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
        signer: (ContactlessCardSession, NativeQualifiedCertificate, ByteArray) -> QualifiedSignResult,
    ) {
        if (!isReady()) {
            pin2.close()
            onResult(qualifiedUnavailable())
            return
        }
        val certificateCopy =
            try {
                expectedCertificate.copyOwned()
            } catch (_: IllegalStateException) {
                pin2.close()
                onResult(QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR))
                return
            }
        val inputCopy = input.copyOf()
        val generation = currentGeneration()
        try {
            probeExecutor.execute {
                val result =
                    try {
                        if (generation == currentGeneration()) {
                            activeSession()?.let { session ->
                                signer(session, certificateCopy, inputCopy)
                            } ?: run {
                                pin2.close()
                                qualifiedUnavailable()
                            }
                        } else {
                            pin2.close()
                            qualifiedUnavailable()
                        }
                    } catch (_: RuntimeException) {
                        pin2.close()
                        QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)
                    } finally {
                        certificateCopy.close()
                        inputCopy.fill(ZERO_BYTE)
                    }
                mainHandler.post {
                    if (generation == currentGeneration()) {
                        onResult(result)
                    } else {
                        result.closeSignature()
                        onResult(qualifiedUnavailable())
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            pin2.close()
            certificateCopy.close()
            inputCopy.fill(ZERO_BYTE)
            onResult(qualifiedUnavailable())
        }
    }

    private fun certificateUnavailable(): NativeCertificateReadResult.Failure =
        NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE)

    private fun pin2Unavailable(): NativePin2PreflightResult.Failure =
        NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)

    private fun qualifiedUnavailable(): QualifiedSignResult.Failure =
        QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)

    private fun NativeCertificateReadResult<NativeQualifiedCertificate>.closeCertificate() {
        if (this is NativeCertificateReadResult.Success) {
            certificate.close()
        }
    }

    private fun QualifiedSignResult.closeSignature() {
        if (this is QualifiedSignResult.Success) {
            signature.close()
        }
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}
