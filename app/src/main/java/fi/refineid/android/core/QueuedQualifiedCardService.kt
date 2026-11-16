// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fi.refineid.android.core

import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/** Session-thread qualified certificate, PIN2 preflight, and signing operations. */
internal interface QualifiedCardSessionOps {
    fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate>

    fun probePin2Status(): NativePin2PreflightResult

    fun qualifiedSignInput(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult
}

/**
 * Serializes [QualifiedCardService] certificate reads, PIN2 preflight probes,
 * and qualified signatures onto a card session's owner [worker] and delivers
 * outcomes through [postResult] while the session generation remains current.
 */
internal class QueuedQualifiedCardService(
    private val worker: Executor,
    private val postResult: (() -> Unit) -> Unit,
    private val isReady: () -> Boolean,
    private val currentGeneration: () -> Int,
    private val isCurrentGeneration: (Int) -> Boolean = { generation -> generation == currentGeneration() },
    private val activeSession: () -> QualifiedCardSessionOps?,
    private val onCertificatePaceRejected: () -> Unit = {},
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
            worker.execute {
                val result =
                    try {
                        if (isCurrentGeneration(generation)) {
                            activeSession()?.readQualifiedCertificate() ?: certificateUnavailable()
                        } else {
                            certificateUnavailable()
                        }
                    } catch (_: RuntimeException) {
                        NativeCertificateReadResult.Failure(
                            NativeCertificateReadFailure.BRIDGE_ERROR,
                        )
                    }
                if (result is NativeCertificateReadResult.Failure &&
                    result.kind == NativeCertificateReadFailure.PACE_REJECTED
                ) {
                    onCertificatePaceRejected()
                }
                postResult {
                    if (isCurrentGeneration(generation)) {
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
            worker.execute {
                val result =
                    try {
                        if (isCurrentGeneration(generation)) {
                            activeSession()?.probePin2Status() ?: pin2Unavailable()
                        } else {
                            pin2Unavailable()
                        }
                    } catch (_: RuntimeException) {
                        NativePin2PreflightResult.Failure(
                            NativePin2PreflightFailure.BRIDGE_ERROR,
                        )
                    }
                postResult {
                    if (isCurrentGeneration(generation)) {
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
        algorithm = algorithm,
        inputMode = QualifiedSigningInputMode.MESSAGE,
        pin2 = pin2,
        input = content,
        expectedCertificate = expectedCertificate,
        onResult = onResult,
    )

    override fun requestQualifiedDigestSignature(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        digest: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    ) = requestQualifiedInput(
        algorithm = algorithm,
        inputMode = QualifiedSigningInputMode.PREHASHED,
        pin2 = pin2,
        input = digest,
        expectedCertificate = expectedCertificate,
        onResult = onResult,
    )

    private fun requestQualifiedInput(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        onResult: (QualifiedSignResult) -> Unit,
    ) {
        var handedOff = false
        var certificateCopy: NativeQualifiedCertificate? = null
        var inputCopy: ByteArray? = null
        try {
            if (!isReady()) {
                pin2.close()
                handedOff = true
                onResult(qualifiedUnavailable())
                return
            }
            val ownedCertificate =
                try {
                    expectedCertificate.copyOwned()
                } catch (_: RuntimeException) {
                    pin2.close()
                    handedOff = true
                    onResult(QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR))
                    return
                }
            certificateCopy = ownedCertificate
            val ownedInput = input.copyOf()
            inputCopy = ownedInput
            val generation = currentGeneration()
            worker.execute {
                val result =
                    try {
                        if (isCurrentGeneration(generation)) {
                            activeSession()?.qualifiedSignInput(
                                algorithm = algorithm,
                                inputMode = inputMode,
                                pin2 = pin2,
                                input = ownedInput,
                                expectedCertificate = ownedCertificate,
                            ) ?: qualifiedUnavailable()
                        } else {
                            qualifiedUnavailable()
                        }
                    } catch (_: RuntimeException) {
                        QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)
                    } finally {
                        closeSigningInputs(
                            pin2 = pin2,
                            certificateCopy = ownedCertificate,
                            inputCopy = ownedInput,
                        )
                    }
                postResult {
                    if (isCurrentGeneration(generation)) {
                        onResult(result)
                    } else {
                        result.closeSignature()
                        onResult(qualifiedUnavailable())
                    }
                }
            }
            handedOff = true
        } catch (_: RejectedExecutionException) {
            closeSigningInputs(pin2 = pin2, certificateCopy = certificateCopy, inputCopy = inputCopy)
            handedOff = true
            onResult(qualifiedUnavailable())
        } finally {
            if (!handedOff) {
                closeSigningInputs(pin2 = pin2, certificateCopy = certificateCopy, inputCopy = inputCopy)
            }
        }
    }

    private fun closeSigningInputs(
        pin2: Pin2Submission,
        certificateCopy: NativeQualifiedCertificate?,
        inputCopy: ByteArray?,
    ) {
        inputCopy?.fill(ZERO_BYTE)
        try {
            pin2.close()
        } finally {
            certificateCopy?.close()
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
