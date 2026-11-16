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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.coroutines.cancellation.CancellationException

internal class NativeOrganizationCardTest {
    @Test
    fun wipesSecretsAndReturnsBridgeErrorWhenNativeLibraryIsUnloaded() {
        assertFalse(NativeCore.isLoaded)
        val exchange = RecordingBlockExchange()
        val bridgeFailure = CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)

        val pin1Current = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_CURRENT_MARKER)
        val pin1Next = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(bridgeFailure, NativeOrganizationCard.changePin1(pin1Current, pin1Next, exchange))
        assertZeroed(pin1Current, pin1Next)

        val pin2Current = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_CURRENT_MARKER)
        val pin2Next = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(bridgeFailure, NativeOrganizationCard.changePin2(pin2Current, pin2Next, exchange))
        assertZeroed(pin2Current, pin2Next)

        val pukForPin1 = secretBytes(CardPinLengths.FINEID.puk.first, SYNTHETIC_CURRENT_MARKER)
        val resetPin1 = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(bridgeFailure, NativeOrganizationCard.resetPin1(pukForPin1, resetPin1, exchange))
        assertZeroed(pukForPin1, resetPin1)

        val pukForPin2 = secretBytes(CardPinLengths.FINEID.puk.first, SYNTHETIC_CURRENT_MARKER)
        val resetPin2 = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(bridgeFailure, NativeOrganizationCard.resetPin2(pukForPin2, resetPin2, exchange))
        assertZeroed(pukForPin2, resetPin2)

        assertEquals(NativeCardManagementWire.ZERO_INT, exchange.invocations)
    }

    @Test
    fun managedPinOpWipesSecretsAcrossLoadedSuccessAndThrowablePaths() {
        val bridgeFailure = CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)

        val okFirst = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_CURRENT_MARKER)
        val okSecond = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(
            CardManagementResult.Success(ManageOutcome.Succeeded),
            NativeOrganizationCard.managedPinOp(okFirst, okSecond, isLoaded = true) {
                CardManagementResult.Success(ManageOutcome.Succeeded)
            },
        )
        assertZeroed(okFirst, okSecond)

        val linkFirst = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_CURRENT_MARKER)
        val linkSecond = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(
            bridgeFailure,
            NativeOrganizationCard.managedPinOp(linkFirst, linkSecond, isLoaded = true) {
                throw UnsatisfiedLinkError("missing symbol")
            },
        )
        assertZeroed(linkFirst, linkSecond)

        val runtimeFirst = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_CURRENT_MARKER)
        val runtimeSecond = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_NEXT_MARKER)
        assertEquals(
            bridgeFailure,
            NativeOrganizationCard.managedPinOp(runtimeFirst, runtimeSecond, isLoaded = true) {
                error("unexpected bridge runtime failure")
            },
        )
        assertZeroed(runtimeFirst, runtimeSecond)

        val cancelledFirst = secretBytes(CardPinLengths.FINEID.puk.first, SYNTHETIC_CURRENT_MARKER)
        val cancelledSecond = secretBytes(CardPinLengths.FINEID.pin1.first, SYNTHETIC_NEXT_MARKER)
        assertThrows(CancellationException::class.java) {
            NativeOrganizationCard.managedPinOp(cancelledFirst, cancelledSecond, isLoaded = true) {
                throw CancellationException("cancelled")
            }
        }
        assertZeroed(cancelledFirst, cancelledSecond)

        val errorFirst = secretBytes(CardPinLengths.FINEID.puk.first, SYNTHETIC_CURRENT_MARKER)
        val errorSecond = secretBytes(CardPinLengths.FINEID.pin2.first, SYNTHETIC_NEXT_MARKER)
        assertThrows(AssertionError::class.java) {
            NativeOrganizationCard.managedPinOp(errorFirst, errorSecond, isLoaded = true) {
                throw AssertionError("fatal error")
            }
        }
        assertZeroed(errorFirst, errorSecond)
    }

    private fun secretBytes(
        length: Int,
        marker: Byte,
    ): ByteArray = ByteArray(length) { marker }

    private fun assertZeroed(vararg arrays: ByteArray) {
        arrays.forEach { array ->
            assertTrue(array.isNotEmpty())
            assertTrue(array.all { it == NativeCardManagementWire.ZERO_BYTE })
        }
    }

    private class RecordingBlockExchange : NativeBlockExchange {
        var invocations: Int = NativeCardManagementWire.ZERO_INT
            private set

        override fun exchangePublic(block: ByteArray): ByteArray {
            invocations += SINGLE_INVOCATION
            return byteArrayOf(BACKEND_FAILURE_REPLY_TAG)
        }

        override fun exchangeCredential(block: ByteArray): ByteArray {
            invocations += SINGLE_INVOCATION
            return byteArrayOf(BACKEND_FAILURE_REPLY_TAG)
        }
    }

    private companion object {
        const val SYNTHETIC_CURRENT_MARKER: Byte = 'a'.code.toByte()
        const val SYNTHETIC_NEXT_MARKER: Byte = 'b'.code.toByte()
        const val SINGLE_INVOCATION = 1
        const val BACKEND_FAILURE_REPLY_TAG: Byte = 6
    }
}
