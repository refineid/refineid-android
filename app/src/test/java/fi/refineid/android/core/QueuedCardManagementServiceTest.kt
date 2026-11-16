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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

class QueuedCardManagementServiceTest {
    @Test
    fun executesAllOperationsOnWorkerAndDeliversResultsViaPostResult() {
        val queue = ManualQueue()
        val session = RecordingManagementSession()
        val service =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )

        val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
        service.probeCredentialHealth(healthResults::add)
        val batch = exerciseSecretOperations(service)
        val singlePinCode = secretBytes(CardPinLengths.FINEID.puk.first)
        val singlePinNew1 = secretBytes(CardPinLengths.FINEID.pin1.first)
        val singlePinActivation = mutableListOf<CardManagementResult<ActivationReport>>()
        service.activateCard(
            scheme = CardManagementScheme.PUK,
            code = singlePinCode,
            newPin1 = singlePinNew1,
            newPin2 = null,
            onResult = singlePinActivation::add,
        )

        assertTrue(session.calls.isEmpty())
        assertTrue(healthResults.isEmpty())
        assertTrue(batch.outcomes.isEmpty())
        assertTrue(singlePinActivation.isEmpty())

        queue.runWorker()
        assertEquals(
            listOf(
                OP_PROBE,
                OP_CHANGE_PIN1,
                OP_CHANGE_PIN2,
                OP_UNBLOCK_PIN1,
                OP_UNBLOCK_PIN2,
                OP_ACTIVATE,
                OP_ACTIVATE,
            ),
            session.calls,
        )
        assertEquals(true, session.lastReadPinLengths)
        assertTrue(session.allObservedSecretsWereNonZero)
        batch.assertAllZeroized()
        assertZeroized(singlePinCode, singlePinNew1)
        assertTrue(healthResults.isEmpty())
        assertTrue(batch.outcomes.isEmpty())

        queue.runPosted()
        assertEquals(listOf(CardManagementResult.Success(SYNTHETIC_HEALTH)), healthResults)
        assertEquals(EXPECTED_SECRET_OP_COUNT, batch.outcomes.size)
        assertTrue(batch.outcomes.all { it is CardManagementResult.Success<*> })
        assertEquals(listOf(CardManagementResult.Success(SYNTHETIC_ACTIVATION_REPORT)), singlePinActivation)
    }

    @Test
    fun wipesSecretsAndReturnsUnavailableImmediatelyWhenNotReady() {
        val queue = ManualQueue()
        val session = RecordingManagementSession()
        val service =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { false },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )

        val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
        service.probeCredentialHealth(healthResults::add)
        val batch = exerciseSecretOperations(service)

        assertTrue(queue.workerTasks.isEmpty())
        assertTrue(queue.resultTasks.isEmpty())
        assertTrue(session.calls.isEmpty())
        assertEquals(
            listOf(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)),
            healthResults,
        )
        batch.assertAllUnavailable()
        batch.assertAllZeroized()
    }

    @Test
    fun fencesStaleGenerationAndCustomPredicateWhileWipingSecrets() {
        val queue = ManualQueue()
        val session = RecordingManagementSession()
        var generation = INITIAL_GENERATION
        val defaultFencedService =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { generation },
                activeSession = { session },
            )

        val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
        defaultFencedService.probeCredentialHealth(healthResults::add)
        val staleGenerationBatch = exerciseSecretOperations(defaultFencedService)
        generation += 1
        queue.drainAll()

        var isStarted = true
        val predicateFencedService =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { isStarted },
                currentGeneration = { generation },
                isCurrentGeneration = { queued -> isStarted && queued == generation },
                activeSession = { session },
            )
        val predicateBatch = exerciseSecretOperations(predicateFencedService)
        isStarted = false
        queue.drainAll()

        assertTrue(session.calls.isEmpty())
        assertEquals(
            listOf(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)),
            healthResults,
        )
        staleGenerationBatch.assertAllUnavailable()
        staleGenerationBatch.assertAllZeroized()
        predicateBatch.assertAllUnavailable()
        predicateBatch.assertAllZeroized()
    }

    @Test
    fun wipesSecretsAndReturnsUnavailableWhenActiveSessionIsNull() {
        val queue = ManualQueue()
        val service =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { null },
            )

        val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
        service.probeCredentialHealth(healthResults::add)
        val batch = exerciseSecretOperations(service)
        queue.drainAll()

        assertEquals(
            listOf(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)),
            healthResults,
        )
        batch.assertAllUnavailable()
        batch.assertAllZeroized()
    }

    @Test
    fun wipesSecretsAndReturnsUnavailableWhenWorkerRejectsExecution() {
        val queue = ManualQueue()
        val session = RecordingManagementSession()
        val rejectingWorker =
            Executor {
                throw RejectedExecutionException("worker shut down")
            }
        val service =
            QueuedCardManagementService(
                worker = rejectingWorker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )

        val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
        service.probeCredentialHealth(healthResults::add)
        val batch = exerciseSecretOperations(service)

        assertTrue(queue.resultTasks.isEmpty())
        assertTrue(session.calls.isEmpty())
        assertEquals(
            listOf(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)),
            healthResults,
        )
        batch.assertAllUnavailable()
        batch.assertAllZeroized()
    }

    @Test
    fun catchesRuntimeExceptionOnWorkerWipesSecretsAndDeliversBridgeError() {
        val queue = ManualQueue()
        for (failure in listOf(IllegalStateException("closed"), UnsupportedOperationException("boom"))) {
            val session = RecordingManagementSession(failureToThrow = failure)
            val service =
                QueuedCardManagementService(
                    worker = queue.worker,
                    postResult = queue.postResult,
                    isReady = { true },
                    currentGeneration = { INITIAL_GENERATION },
                    activeSession = { session },
                )

            val healthResults = mutableListOf<CardManagementResult<CredentialHealth>>()
            service.probeCredentialHealth(healthResults::add)
            val batch = exerciseSecretOperations(service)
            queue.drainAll()

            assertEquals(
                listOf(CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)),
                healthResults,
            )
            assertEquals(EXPECTED_SECRET_OP_COUNT, batch.outcomes.size)
            assertTrue(
                batch.outcomes.all {
                    it == CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                },
            )
            batch.assertAllZeroized()
        }
    }

    @Test
    fun rethrowsErrorOnWorkerAfterWipingSecrets() {
        val queue = ManualQueue()
        val session = RecordingManagementSession(failureToThrow = AssertionError("fatal"))
        val service =
            QueuedCardManagementService(
                worker = queue.worker,
                postResult = queue.postResult,
                isReady = { true },
                currentGeneration = { INITIAL_GENERATION },
                activeSession = { session },
            )

        val currentPin = secretBytes(CardPinLengths.FINEID.pin1.first)
        val newPin = secretBytes(CardPinLengths.FINEID.pin1.first)
        val activationCode = secretBytes(CardPinLengths.FINEID.puk.first)
        val activationPin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
        val activationPin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
        val delivered = mutableListOf<CardManagementResult<*>>()

        service.changePin1(currentPin, newPin, delivered::add)
        service.activateCard(
            scheme = CardManagementScheme.PUK,
            code = activationCode,
            newPin1 = activationPin1,
            newPin2 = activationPin2,
            onResult = delivered::add,
        )

        while (queue.workerTasks.isNotEmpty()) {
            val task = queue.workerTasks.removeFirst()
            assertThrows(AssertionError::class.java) {
                task.run()
            }
        }
        assertTrue(queue.resultTasks.isEmpty())
        assertTrue(delivered.isEmpty())
        assertZeroized(currentPin, newPin, activationCode, activationPin1, activationPin2)
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

    private class RecordingManagementSession(
        private val failureToThrow: Throwable? = null,
    ) : CardManagementSessionOps {
        val calls = mutableListOf<String>()
        var lastReadPinLengths: Boolean? = null
        var allObservedSecretsWereNonZero = true

        override fun probeCredentialHealth(readPinLengths: Boolean): CardManagementResult<CredentialHealth> {
            calls += OP_PROBE
            lastReadPinLengths = readPinLengths
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(SYNTHETIC_HEALTH)
        }

        override fun changePin1(
            currentPin: ByteArray,
            newPin: ByteArray,
        ): CardManagementResult<ManageOutcome> {
            calls += OP_CHANGE_PIN1
            observeSecrets(currentPin, newPin)
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(ManageOutcome.Succeeded)
        }

        override fun changePin2(
            currentPin: ByteArray,
            newPin: ByteArray,
        ): CardManagementResult<ManageOutcome> {
            calls += OP_CHANGE_PIN2
            observeSecrets(currentPin, newPin)
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(ManageOutcome.Succeeded)
        }

        override fun unblockPin1(
            puk: ByteArray,
            newPin: ByteArray,
        ): CardManagementResult<ManageOutcome> {
            calls += OP_UNBLOCK_PIN1
            observeSecrets(puk, newPin)
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(ManageOutcome.Succeeded)
        }

        override fun unblockPin2(
            puk: ByteArray,
            newPin: ByteArray,
        ): CardManagementResult<ManageOutcome> {
            calls += OP_UNBLOCK_PIN2
            observeSecrets(puk, newPin)
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(ManageOutcome.Succeeded)
        }

        override fun activateCard(
            scheme: CardManagementScheme,
            code: ByteArray,
            newPin1: ByteArray?,
            newPin2: ByteArray?,
        ): CardManagementResult<ActivationReport> {
            calls += OP_ACTIVATE
            observeSecrets(
                *listOfNotNull(code, newPin1, newPin2).toTypedArray(),
            )
            failureToThrow?.let { throw it }
            return CardManagementResult.Success(SYNTHETIC_ACTIVATION_REPORT)
        }

        private fun observeSecrets(vararg arrays: ByteArray) {
            if (arrays.any { array -> array.isEmpty() || array.all { it == ZERO_BYTE } }) {
                allObservedSecretsWereNonZero = false
            }
        }
    }

    private class SecretOperationBatch(
        val secrets: List<ByteArray>,
        val outcomes: MutableList<CardManagementResult<*>>,
    ) {
        fun assertAllZeroized() {
            assertZeroized(*secrets.toTypedArray())
        }

        fun assertAllUnavailable() {
            assertEquals(EXPECTED_SECRET_OP_COUNT, outcomes.size)
            assertTrue(
                outcomes.all {
                    it == CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                },
            )
        }
    }

    private companion object {
        const val DIGIT_ZERO_BYTE: Byte = '0'.code.toByte()
        const val ZERO_BYTE: Byte = 0
        const val INITIAL_GENERATION = 1
        const val EXPECTED_SECRET_OP_COUNT = 5

        const val OP_PROBE = "probeCredentialHealth"
        const val OP_CHANGE_PIN1 = "changePin1"
        const val OP_CHANGE_PIN2 = "changePin2"
        const val OP_UNBLOCK_PIN1 = "unblockPin1"
        const val OP_UNBLOCK_PIN2 = "unblockPin2"
        const val OP_ACTIVATE = "activateCard"

        val SYNTHETIC_HEALTH =
            CredentialHealth(
                pin1State = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
                pin2State = NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT),
                pukState = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
                scheme = NativePinReferenceScheme.CITIZEN,
                activationScheme = CardManagementScheme.PUK,
                activationNeeds = CardActivationNeeds(pin1 = false, pin2 = false),
                pinLengths = CardPinLengths.FINEID,
            )

        val SYNTHETIC_ACTIVATION_REPORT =
            ActivationReport(
                scheme = CardManagementScheme.PUK,
                pin1Outcome = ManageOutcome.Succeeded,
                pin2Outcome = ManageOutcome.Succeeded,
            )

        fun secretBytes(length: Int): ByteArray = ByteArray(length) { DIGIT_ZERO_BYTE }

        fun assertZeroized(vararg arrays: ByteArray) {
            for (array in arrays) {
                assertTrue(array.all { it == ZERO_BYTE })
            }
        }

        fun exerciseSecretOperations(service: CardManagementService): SecretOperationBatch {
            val outcomes = mutableListOf<CardManagementResult<*>>()
            val pin1Current = secretBytes(CardPinLengths.FINEID.pin1.first)
            val pin1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
            val pin2Current = secretBytes(CardPinLengths.FINEID.pin2.first)
            val pin2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
            val unblock1Puk = secretBytes(CardPinLengths.FINEID.puk.first)
            val unblock1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
            val unblock2Puk = secretBytes(CardPinLengths.FINEID.puk.first)
            val unblock2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
            val activationCode = secretBytes(CardPinLengths.FINEID.puk.first)
            val activationPin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
            val activationPin2 = secretBytes(CardPinLengths.FINEID.pin2.first)

            service.changePin1(pin1Current, pin1Next, outcomes::add)
            service.changePin2(pin2Current, pin2Next, outcomes::add)
            service.unblockPin1(unblock1Puk, unblock1Next, outcomes::add)
            service.unblockPin2(unblock2Puk, unblock2Next, outcomes::add)
            service.activateCard(
                scheme = CardManagementScheme.PUK,
                code = activationCode,
                newPin1 = activationPin1,
                newPin2 = activationPin2,
                onResult = outcomes::add,
            )

            return SecretOperationBatch(
                secrets =
                    listOf(
                        pin1Current,
                        pin1Next,
                        pin2Current,
                        pin2Next,
                        unblock1Puk,
                        unblock1Next,
                        unblock2Puk,
                        unblock2Next,
                        activationCode,
                        activationPin1,
                        activationPin2,
                    ),
                outcomes = outcomes,
            )
        }
    }
}
