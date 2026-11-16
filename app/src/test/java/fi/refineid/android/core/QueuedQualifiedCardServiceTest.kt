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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

class QueuedQualifiedCardServiceTest {
    @Test
    fun executesCertificatePreflightAndSigningOnWorkerWithDefensiveCopies() {
        val queue = ManualQueue()
        val session = RecordingQualifiedSession()
        val service =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )

        val certResults = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val preflightResults = mutableListOf<NativePin2PreflightResult>()
        val messageSignResults = mutableListOf<QualifiedSignResult>()
        val digestSignResults = mutableListOf<QualifiedSignResult>()

        val callerCert = syntheticCertificate()
        val messagePin = TrackedPin2.create()
        val digestPin = TrackedPin2.create()
        val callerMessage = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray()
        val expectedMessageSnapshot = callerMessage.copyOf()
        val callerDigest =
            ByteArray(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.digestLength) {
                SYNTHETIC_DIGEST_FILL_BYTE
            }
        val expectedDigestSnapshot = callerDigest.copyOf()

        service.requestQualifiedCertificate(certResults::add)
        service.requestPin2Preflight(preflightResults::add)
        service.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = messagePin.submission,
            content = callerMessage,
            expectedCertificate = callerCert,
            onResult = messageSignResults::add,
        )
        service.requestQualifiedDigestSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = digestPin.submission,
            digest = callerDigest,
            expectedCertificate = callerCert,
            onResult = digestSignResults::add,
        )

        callerMessage.fill(MUTATED_INPUT_BYTE)
        callerDigest.fill(MUTATED_INPUT_BYTE)
        assertTrue(session.recordedSignInputs.isEmpty())

        queue.runWorker()
        assertEquals(
            listOf(QualifiedSigningInputMode.MESSAGE, QualifiedSigningInputMode.PREHASHED),
            session.recordedModes,
        )
        assertArrayEquals(expectedMessageSnapshot, session.recordedSignSnapshots[FIRST_SIGN_INDEX])
        assertArrayEquals(expectedDigestSnapshot, session.recordedSignSnapshots[SECOND_SIGN_INDEX])
        assertTrue(session.recordedSignInputs.all { inputRef -> inputRef.all { it == ZERO_BYTE } })
        for (workerCert in session.recordedCertificates) {
            assertNotSame(callerCert, workerCert)
            assertThrows(IllegalStateException::class.java) { workerCert.copyDer() }
        }
        assertArrayEquals(SYNTHETIC_DER_BYTES, callerCert.copyDer())
        messagePin.assertWipedAndClosed()
        digestPin.assertWipedAndClosed()
        assertTrue(certResults.isEmpty())
        assertTrue(preflightResults.isEmpty())
        assertTrue(messageSignResults.isEmpty())
        assertTrue(digestSignResults.isEmpty())

        queue.runPosted()
        val readCert = (certResults.single() as NativeCertificateReadResult.Success).certificate
        assertArrayEquals(SYNTHETIC_DER_BYTES, readCert.copyDer())
        readCert.close()
        assertEquals(listOf(NativePin2PreflightResult.Success(SYNTHETIC_PREFLIGHT)), preflightResults)
        val messageSig = (messageSignResults.single() as QualifiedSignResult.Success).signature
        val digestSig = (digestSignResults.single() as QualifiedSignResult.Success).signature
        assertEquals(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.signatureLength, messageSig.length)
        assertEquals(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.signatureLength, digestSig.length)
        messageSig.close()
        digestSig.close()
        callerCert.close()
    }

    @Test
    fun fencesStaleGenerationBeforeWorkerAndBeforePostResultClosingOwnedResults() {
        val queue = ManualQueue()
        val session = RecordingQualifiedSession()
        var generation = INITIAL_GENERATION
        val service =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { generation },
                activeSession = { session },
            )
        val callerCert = syntheticCertificate()
        val payload = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray()

        val staleBeforeWorkerCert = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val staleBeforeWorkerPreflight = mutableListOf<NativePin2PreflightResult>()
        val staleBeforeWorkerSign = mutableListOf<QualifiedSignResult>()
        val staleBeforeWorkerPin = TrackedPin2.create()

        service.requestQualifiedCertificate(staleBeforeWorkerCert::add)
        service.requestPin2Preflight(staleBeforeWorkerPreflight::add)
        service.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = staleBeforeWorkerPin.submission,
            content = payload,
            expectedCertificate = callerCert,
            onResult = staleBeforeWorkerSign::add,
        )
        generation += 1
        queue.drainAll()

        assertEquals(NO_CALLS, session.certificateReads)
        assertEquals(NO_CALLS, session.preflightProbes)
        assertTrue(session.recordedModes.isEmpty())
        staleBeforeWorkerPin.assertWipedAndClosed()
        assertEquals(
            listOf(NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE)),
            staleBeforeWorkerCert,
        )
        assertEquals(
            listOf(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)),
            staleBeforeWorkerPreflight,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            staleBeforeWorkerSign,
        )

        val staleBeforePostCert = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val staleBeforePostPreflight = mutableListOf<NativePin2PreflightResult>()
        val staleBeforePostSign = mutableListOf<QualifiedSignResult>()
        val staleBeforePostPin = TrackedPin2.create()

        service.requestQualifiedCertificate(staleBeforePostCert::add)
        service.requestPin2Preflight(staleBeforePostPreflight::add)
        service.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = staleBeforePostPin.submission,
            content = payload,
            expectedCertificate = callerCert,
            onResult = staleBeforePostSign::add,
        )
        queue.runWorker()
        val issuedCertificate = session.lastIssuedCertificate!!
        val issuedCertBacking = session.lastIssuedCertificateBacking!!
        val issuedSignature = session.lastIssuedSignature!!
        val issuedSigBacking = session.lastIssuedSignatureBacking!!

        generation += 1
        queue.runPosted()

        staleBeforePostPin.assertWipedAndClosed()
        assertTrue(issuedCertBacking.all { it == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) { issuedCertificate.copyDer() }
        assertTrue(issuedSigBacking.all { it == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) { issuedSignature.copyBytes() }
        assertEquals(
            listOf(NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE)),
            staleBeforePostCert,
        )
        assertEquals(
            listOf(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)),
            staleBeforePostPreflight,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            staleBeforePostSign,
        )
        callerCert.close()
    }

    @Test
    fun wipesPin2AcrossNotReadyClosedCertificateAndRejectedWorker() {
        val queue = ManualQueue()
        val payload = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray()
        val digest =
            ByteArray(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.digestLength) {
                SYNTHETIC_DIGEST_FILL_BYTE
            }
        val liveCert = syntheticCertificate()

        val notReadyService =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { false },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { RecordingQualifiedSession() },
            )
        val notReadyPin = TrackedPin2.create()
        val notReadyResults = mutableListOf<QualifiedSignResult>()
        notReadyService.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = notReadyPin.submission,
            content = payload,
            expectedCertificate = liveCert,
            onResult = notReadyResults::add,
        )
        notReadyPin.assertWipedAndClosed()
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            notReadyResults,
        )

        val closedCert = syntheticCertificate().also(NativeQualifiedCertificate::close)
        val readyService =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { RecordingQualifiedSession() },
            )
        val closedCertPin = TrackedPin2.create()
        val closedCertResults = mutableListOf<QualifiedSignResult>()
        readyService.requestQualifiedDigestSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = closedCertPin.submission,
            digest = digest,
            expectedCertificate = closedCert,
            onResult = closedCertResults::add,
        )
        closedCertPin.assertWipedAndClosed()
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)),
            closedCertResults,
        )

        val rejectingService =
            QueuedQualifiedCardService(
                worker = Executor { throw RejectedExecutionException("rejected") },
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { RecordingQualifiedSession() },
            )
        val rejectedPin = TrackedPin2.create()
        val rejectedCertResults = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val rejectedPreflightResults = mutableListOf<NativePin2PreflightResult>()
        val rejectedSignResults = mutableListOf<QualifiedSignResult>()
        rejectingService.requestQualifiedCertificate(rejectedCertResults::add)
        rejectingService.requestPin2Preflight(rejectedPreflightResults::add)
        rejectingService.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = rejectedPin.submission,
            content = payload,
            expectedCertificate = liveCert,
            onResult = rejectedSignResults::add,
        )
        rejectedPin.assertWipedAndClosed()
        assertEquals(
            listOf(NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE)),
            rejectedCertResults,
        )
        assertEquals(
            listOf(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)),
            rejectedPreflightResults,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            rejectedSignResults,
        )

        liveCert.close()
    }

    @Test
    fun wipesPin2AcrossNullSessionAndCustomGenerationPredicate() {
        val queue = ManualQueue()
        val payload = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray()
        val liveCert = syntheticCertificate()

        val nullSessionService =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { null },
            )
        val nullSessionPin = TrackedPin2.create()
        val nullSessionCertResults = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val nullSessionPreflightResults = mutableListOf<NativePin2PreflightResult>()
        val nullSessionSignResults = mutableListOf<QualifiedSignResult>()
        nullSessionService.requestQualifiedCertificate(nullSessionCertResults::add)
        nullSessionService.requestPin2Preflight(nullSessionPreflightResults::add)
        nullSessionService.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = nullSessionPin.submission,
            content = payload,
            expectedCertificate = liveCert,
            onResult = nullSessionSignResults::add,
        )
        queue.drainAll()
        nullSessionPin.assertWipedAndClosed()
        assertEquals(
            listOf(NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE)),
            nullSessionCertResults,
        )
        assertEquals(
            listOf(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)),
            nullSessionPreflightResults,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            nullSessionSignResults,
        )

        var started = true
        val predicateService =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { started },
                currentGeneration = { INITIAL_GENERATION },
                isCurrentGeneration = { gen -> started && gen == INITIAL_GENERATION },
                activeSession = { RecordingQualifiedSession() },
            )
        val predicatePin = TrackedPin2.create()
        val predicateResults = mutableListOf<QualifiedSignResult>()
        predicateService.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = predicatePin.submission,
            content = payload,
            expectedCertificate = liveCert,
            onResult = predicateResults::add,
        )
        started = false
        queue.drainAll()
        predicatePin.assertWipedAndClosed()
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)),
            predicateResults,
        )

        liveCert.close()
    }

    @Test
    fun catchesRuntimeExceptionAcrossAllOperationsWipesSecretsAndDeliversBridgeError() {
        val queue = ManualQueue()
        val session = RecordingQualifiedSession(failureToThrow = UnsupportedOperationException("boom"))
        var paceRejectedCount = 0
        val service =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
                onCertificatePaceRejected = { paceRejectedCount += 1 },
            )

        val callerCert = syntheticCertificate()
        val messagePin = TrackedPin2.create()
        val digestPin = TrackedPin2.create()
        val certResults = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val preflightResults = mutableListOf<NativePin2PreflightResult>()
        val messageSignResults = mutableListOf<QualifiedSignResult>()
        val digestSignResults = mutableListOf<QualifiedSignResult>()

        service.requestQualifiedCertificate(certResults::add)
        service.requestPin2Preflight(preflightResults::add)
        service.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = messagePin.submission,
            content = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray(),
            expectedCertificate = callerCert,
            onResult = messageSignResults::add,
        )
        service.requestQualifiedDigestSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = digestPin.submission,
            digest =
                ByteArray(QualifiedSigningAlgorithm.ECDSA_P384_SHA384.digestLength) {
                    SYNTHETIC_DIGEST_FILL_BYTE
                },
            expectedCertificate = callerCert,
            onResult = digestSignResults::add,
        )

        queue.drainAll()

        assertEquals(NO_CALLS, paceRejectedCount)
        messagePin.assertWipedAndClosed()
        digestPin.assertWipedAndClosed()
        assertTrue(session.recordedSignInputs.all { inputRef -> inputRef.all { it == ZERO_BYTE } })
        assertEquals(
            listOf(NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)),
            certResults,
        )
        assertEquals(
            listOf(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)),
            preflightResults,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)),
            messageSignResults,
        )
        assertEquals(
            listOf(QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)),
            digestSignResults,
        )
        callerCert.close()
    }

    @Test
    fun rethrowsErrorOnWorkerAfterWipingPin2AndCopiedBuffers() {
        val queue = ManualQueue()
        val session = RecordingQualifiedSession(failureToThrow = AssertionError("fatal"))
        val service =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )
        val callerCert = syntheticCertificate()
        val pin = TrackedPin2.create()
        val signResults = mutableListOf<QualifiedSignResult>()

        service.requestQualifiedSignature(
            algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
            pin2 = pin.submission,
            content = SYNTHETIC_MESSAGE_TEXT.encodeToByteArray(),
            expectedCertificate = callerCert,
            onResult = signResults::add,
        )

        val task = queue.workerTasks.removeFirst()
        assertThrows(AssertionError::class.java) {
            task.run()
        }
        assertTrue(queue.resultTasks.isEmpty())
        assertTrue(signResults.isEmpty())
        pin.assertWipedAndClosed()
        assertTrue(session.recordedSignInputs.single().all { it == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java) {
            session.recordedCertificates.single().copyDer()
        }
        callerCert.close()
    }

    @Test
    fun invokesPaceRejectedHookOnlyWhenCertificateReadReturnsPaceRejected() {
        val queue = ManualQueue()
        val session = RecordingQualifiedSession()
        var paceRejectedCount = 0
        val service =
            QueuedQualifiedCardService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
                onCertificatePaceRejected = { paceRejectedCount += 1 },
            )

        val results = mutableListOf<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val outcomesToReturn =
            listOf(
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.REJECTED),
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.TRANSPORT_ERROR),
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.PACE_REJECTED),
                NativeCertificateReadResult.Success(syntheticCertificate()),
            )
        for (outcome in outcomesToReturn) {
            session.nextCertificateOutcome = outcome
            service.requestQualifiedCertificate(results::add)
            queue.drainAll()
        }

        assertEquals(EXPECTED_SINGLE_PACE_REJECTED_HOOK_CALL, paceRejectedCount)
        assertEquals(outcomesToReturn.size, results.size)
        assertEquals(
            NativeCertificateReadResult.Failure(NativeCertificateReadFailure.PACE_REJECTED),
            results[PACE_REJECTED_OUTCOME_INDEX],
        )
        (results.last() as NativeCertificateReadResult.Success).certificate.close()
    }

    private class ManualQueue {
        val workerTasks = ArrayDeque<Runnable>()
        val resultTasks = ArrayDeque<() -> Unit>()
        val worker = Executor { command -> workerTasks.addLast(command) }
        val postResult: (() -> Unit) -> Unit = { callback -> resultTasks.addLast(callback) }

        fun runWorker() {
            while (workerTasks.isNotEmpty()) {
                workerTasks.removeFirst().run()
            }
        }

        fun runPosted() {
            while (resultTasks.isNotEmpty()) {
                resultTasks.removeFirst().invoke()
            }
        }

        fun drainAll() {
            runWorker()
            runPosted()
        }
    }

    private class RecordingQualifiedSession(
        private val failureToThrow: Throwable? = null,
    ) : QualifiedCardSessionOps {
        var certificateReads = 0
        var preflightProbes = 0
        var nextCertificateOutcome: NativeCertificateReadResult<NativeQualifiedCertificate>? = null
        var lastIssuedCertificate: NativeQualifiedCertificate? = null
        var lastIssuedCertificateBacking: ByteArray? = null
        var lastIssuedSignature: NativeQualifiedSignature? = null
        var lastIssuedSignatureBacking: ByteArray? = null
        val recordedModes = mutableListOf<QualifiedSigningInputMode>()
        val recordedSignInputs = mutableListOf<ByteArray>()
        val recordedSignSnapshots = mutableListOf<ByteArray>()
        val recordedCertificates = mutableListOf<NativeQualifiedCertificate>()

        override fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate> {
            certificateReads += 1
            failureToThrow?.let { throw it }
            nextCertificateOutcome?.let { scripted ->
                nextCertificateOutcome = null
                return scripted
            }
            val backingDer = SYNTHETIC_DER_BYTES.copyOf()
            val cert =
                NativeQualifiedCertificate(
                    keyProfile = NativeCardKeyProfile.ECDSA_P384,
                    ownedDer = backingDer,
                )
            lastIssuedCertificate = cert
            lastIssuedCertificateBacking = backingDer
            return NativeCertificateReadResult.Success(cert)
        }

        override fun probePin2Status(): NativePin2PreflightResult {
            preflightProbes += 1
            failureToThrow?.let { throw it }
            return NativePin2PreflightResult.Success(SYNTHETIC_PREFLIGHT)
        }

        override fun qualifiedSignInput(
            algorithm: QualifiedSigningAlgorithm,
            inputMode: QualifiedSigningInputMode,
            pin2: Pin2Submission,
            input: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
        ): QualifiedSignResult {
            recordedModes += inputMode
            recordedSignInputs += input
            recordedSignSnapshots += input.copyOf()
            recordedCertificates += expectedCertificate
            failureToThrow?.let { throw it }
            pin2.consume { pinBytes ->
                check(pinBytes.any { it != ZERO_BYTE }) { "expected live PIN2 bytes" }
            }
            val backingSig = ByteArray(algorithm.signatureLength) { SYNTHETIC_SIGNATURE_BYTE }
            val signature = NativeQualifiedSignature(algorithm = algorithm, ownedBytes = backingSig)
            lastIssuedSignature = signature
            lastIssuedSignatureBacking = backingSig
            return QualifiedSignResult.Success(signature)
        }
    }

    private class TrackedPin2(
        val backingBytes: ByteArray,
        val submission: Pin2Submission,
    ) {
        fun assertWipedAndClosed() {
            assertTrue(backingBytes.all { it == ZERO_BYTE })
            assertThrows(IllegalStateException::class.java) {
                submission.copyBytes()
            }
        }

        companion object {
            fun create(): TrackedPin2 {
                val backing = ByteArray(CardPinLengths.FINEID.pin2.first) { DIGIT_ZERO_BYTE }
                return TrackedPin2(
                    backingBytes = backing,
                    submission = Pin2Submission.fromOwnedBytes(backing),
                )
            }
        }
    }

    private companion object {
        const val DIGIT_ZERO_BYTE: Byte = '0'.code.toByte()
        const val ZERO_BYTE: Byte = 0
        const val INITIAL_GENERATION = 1
        const val NO_CALLS = 0
        const val FIRST_SIGN_INDEX = 0
        const val SECOND_SIGN_INDEX = 1
        const val SYNTHETIC_MESSAGE_TEXT = "synthetic-message"
        const val SYNTHETIC_CERTIFICATE_TEXT = "synthetic-certificate"
        const val SYNTHETIC_DIGEST_FILL_BYTE: Byte = 'd'.code.toByte()
        const val MUTATED_INPUT_BYTE: Byte = 'X'.code.toByte()
        const val SYNTHETIC_SIGNATURE_BYTE: Byte = 'S'.code.toByte()
        const val EXPECTED_SINGLE_PACE_REJECTED_HOOK_CALL = 1
        const val PACE_REJECTED_OUTCOME_INDEX = 2

        val SYNTHETIC_DER_BYTES = SYNTHETIC_CERTIFICATE_TEXT.encodeToByteArray()

        val SYNTHETIC_PREFLIGHT =
            NativePin2Preflight(
                referenceScheme = NativePinReferenceScheme.CITIZEN,
                state = NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT),
                retryFloorPermits = true,
            )

        fun syntheticCertificate(): NativeQualifiedCertificate =
            NativeQualifiedCertificate(
                keyProfile = NativeCardKeyProfile.ECDSA_P384,
                ownedDer = SYNTHETIC_DER_BYTES.copyOf(),
            )
    }
}
