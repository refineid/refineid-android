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

/** Session-thread card management operations shared across card transports. */
internal interface CardManagementSessionOps {
    fun probeCredentialHealth(readPinLengths: Boolean): CardManagementResult<CredentialHealth>

    fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
    ): CardManagementResult<ActivationReport>
}

/**
 * Serializes [CardManagementService] work onto a card session's owner [worker]
 * and delivers outcomes through [postResult].
 *
 * Credential buffers are zeroized whenever work is refused before queueing,
 * rejected by the executor, dropped because the session generation moved or no
 * session is open, or completed or aborted on the worker thread.
 */
internal class QueuedCardManagementService(
    private val worker: Executor,
    private val postResult: (() -> Unit) -> Unit,
    private val isReady: () -> Boolean,
    private val currentGeneration: () -> Int,
    private val isCurrentGeneration: (Int) -> Boolean = { generation -> generation == currentGeneration() },
    private val activeSession: () -> CardManagementSessionOps?,
) : CardManagementService {
    override fun probeCredentialHealth(onResult: (CardManagementResult<CredentialHealth>) -> Unit) =
        enqueue(onResult = onResult) { session ->
            session.probeCredentialHealth(readPinLengths = true)
        }

    override fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) = enqueue(
        wipeSecrets = {
            currentPin.fill(ZERO_BYTE)
            newPin.fill(ZERO_BYTE)
        },
        onResult = onResult,
    ) { session ->
        session.changePin1(currentPin, newPin)
    }

    override fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) = enqueue(
        wipeSecrets = {
            currentPin.fill(ZERO_BYTE)
            newPin.fill(ZERO_BYTE)
        },
        onResult = onResult,
    ) { session ->
        session.changePin2(currentPin, newPin)
    }

    override fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) = enqueue(
        wipeSecrets = {
            puk.fill(ZERO_BYTE)
            newPin.fill(ZERO_BYTE)
        },
        onResult = onResult,
    ) { session ->
        session.unblockPin1(puk, newPin)
    }

    override fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) = enqueue(
        wipeSecrets = {
            puk.fill(ZERO_BYTE)
            newPin.fill(ZERO_BYTE)
        },
        onResult = onResult,
    ) { session ->
        session.unblockPin2(puk, newPin)
    }

    override fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        onResult: (CardManagementResult<ActivationReport>) -> Unit,
    ) = enqueue(
        wipeSecrets = {
            code.fill(ZERO_BYTE)
            newPin1?.fill(ZERO_BYTE)
            newPin2?.fill(ZERO_BYTE)
        },
        onResult = onResult,
    ) { session ->
        session.activateCard(scheme, code, newPin1, newPin2)
    }

    private fun <T> enqueue(
        wipeSecrets: () -> Unit = {},
        onResult: (CardManagementResult<T>) -> Unit,
        operation: (CardManagementSessionOps) -> CardManagementResult<T>,
    ) {
        var handedOff = false
        try {
            if (!isReady()) {
                wipeSecrets()
                handedOff = true
                onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
                return
            }
            val generation = currentGeneration()
            worker.execute {
                val result =
                    try {
                        if (isCurrentGeneration(generation)) {
                            activeSession()?.let(operation)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } else {
                            CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        }
                    } catch (_: RuntimeException) {
                        CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                    } finally {
                        wipeSecrets()
                    }
                postResult {
                    onResult(result)
                }
            }
            handedOff = true
        } catch (_: RejectedExecutionException) {
            wipeSecrets()
            handedOff = true
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        } finally {
            if (!handedOff) {
                wipeSecrets()
            }
        }
    }

    private companion object {
        const val ZERO_BYTE: Byte = 0
    }
}
