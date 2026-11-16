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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier

internal class NativeCardManagementTest {
    @Test
    fun declaresOnlyThreeParameterizedNativeEntryPoints() {
        val nativeMethodNames =
            NativeCardManagement::class.java.declaredMethods
                .filter { Modifier.isNative(it.modifiers) }
                .map { it.name }
                .toSet()

        assertEquals(
            setOf(
                "probeCredentialHealthNative",
                "managePinNative",
                "activateCardNative",
            ),
            nativeMethodNames,
        )
    }

    @Test
    fun wireConstantsMatchRustCardManagementModule() {
        assertEquals(
            NativeCardExchangeLevel.APDU.wireValue,
            CardManagementChannelMode.fromExchangeLevel(NativeCardExchangeLevel.APDU).wireValue,
        )
        assertEquals(
            NativeCardExchangeLevel.T0_TPDU.wireValue,
            CardManagementChannelMode.fromExchangeLevel(NativeCardExchangeLevel.T0_TPDU).wireValue,
        )
        assertEquals(
            CardManagementChannelMode.entries.size,
            CardManagementChannelMode.entries
                .map { it.wireValue }
                .toSet()
                .size,
        )
        assertEquals(
            PinManageOp.entries.size,
            PinManageOp.entries
                .map { it.wireValue }
                .toSet()
                .size,
        )

        val rustConstants = parseRustCardManagementConstants()
        val expectedKotlinWire =
            mapOf(
                "CHANNEL_MODE_WIRED_APDU" to NativeCardManagementWire.CHANNEL_MODE_WIRED_APDU,
                "CHANNEL_MODE_WIRED_T0_TPDU" to NativeCardManagementWire.CHANNEL_MODE_WIRED_T0_TPDU,
                "CHANNEL_MODE_CONTACTLESS_PACE" to NativeCardManagementWire.CHANNEL_MODE_CONTACTLESS_PACE,
                "CHANNEL_MODE_CONTACTLESS_HELD_SESSION" to
                    NativeCardManagementWire.CHANNEL_MODE_CONTACTLESS_HELD_SESSION,
                "PIN_OP_CHANGE_PIN1" to NativeCardManagementWire.PIN_OP_CHANGE_PIN1,
                "PIN_OP_CHANGE_PIN2" to NativeCardManagementWire.PIN_OP_CHANGE_PIN2,
                "PIN_OP_UNBLOCK_PIN1" to NativeCardManagementWire.PIN_OP_UNBLOCK_PIN1,
                "PIN_OP_UNBLOCK_PIN2" to NativeCardManagementWire.PIN_OP_UNBLOCK_PIN2,
                "MANAGEMENT_TAG_BRIDGE_ERROR" to NativeCardManagementWire.MANAGEMENT_TAG_BRIDGE_ERROR,
                "MANAGEMENT_TAG_SUCCEEDED" to NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED,
                "MANAGEMENT_TAG_CARD_UNAVAILABLE" to NativeCardManagementWire.MANAGEMENT_TAG_CARD_UNAVAILABLE,
                "MANAGEMENT_TAG_TRANSPORT_ERROR" to NativeCardManagementWire.MANAGEMENT_TAG_TRANSPORT_ERROR,
                "MANAGEMENT_TAG_INVALID_CREDENTIAL" to NativeCardManagementWire.MANAGEMENT_TAG_INVALID_CREDENTIAL,
                "MANAGEMENT_TAG_SAFETY_REFUSED" to NativeCardManagementWire.MANAGEMENT_TAG_SAFETY_REFUSED,
                "MANAGEMENT_TAG_PACE_REJECTED" to NativeCardManagementWire.MANAGEMENT_TAG_PACE_REJECTED,
                "MANAGEMENT_TAG_WRONG_CREDENTIAL" to NativeCardManagementWire.MANAGEMENT_TAG_WRONG_CREDENTIAL,
                "MANAGEMENT_TAG_LOCKED" to NativeCardManagementWire.MANAGEMENT_TAG_LOCKED,
                "MANAGEMENT_TAG_OTHER" to NativeCardManagementWire.MANAGEMENT_TAG_OTHER,
                "PIN_STATE_VERIFIED" to NativeCardManagementWire.PIN_STATE_VERIFIED,
                "PIN_STATE_REMAINING" to NativeCardManagementWire.PIN_STATE_REMAINING,
                "PIN_STATE_LOCKED" to NativeCardManagementWire.PIN_STATE_LOCKED,
                "PIN_STATE_NO_INFO" to NativeCardManagementWire.PIN_STATE_NO_INFO,
                "PIN_STATE_UNRECOGNISED" to NativeCardManagementWire.PIN_STATE_UNRECOGNISED,
                "SCHEME_CITIZEN" to NativeCardManagementWire.SCHEME_CITIZEN,
                "SCHEME_ORGANIZATIONAL" to NativeCardManagementWire.SCHEME_ORGANIZATIONAL,
                "ACTIVATION_SCHEME_UNKNOWN" to NativeCardManagementWire.ACTIVATION_SCHEME_UNKNOWN,
                "ACTIVATION_SCHEME_PUK" to NativeCardManagementWire.ACTIVATION_SCHEME_PUK,
                "ACTIVATION_SCHEME_PRESET" to NativeCardManagementWire.ACTIVATION_SCHEME_PRESET,
                "ACTIVATION_NEEDS_NONE" to NativeCardManagementWire.ACTIVATION_NEEDS_NONE,
                "ACTIVATION_NEEDS_PIN1_ONLY" to NativeCardManagementWire.ACTIVATION_NEEDS_PIN1_ONLY,
                "ACTIVATION_NEEDS_PIN2_ONLY" to NativeCardManagementWire.ACTIVATION_NEEDS_PIN2_ONLY,
                "ACTIVATION_NEEDS_BOTH" to NativeCardManagementWire.ACTIVATION_NEEDS_BOTH,
            )

        expectedKotlinWire.forEach { (name, kotlinValue) ->
            assertEquals("Wire mismatch for $name", rustConstants[name], kotlinValue)
        }
    }

    @Test
    fun wipesWiredSecretsAndReturnsBridgeErrorWhenNativeLibraryIsUnloaded() {
        assertFalse(NativeCore.isLoaded)
        val exchange = RecordingBlockExchange()
        val bridgeFailure = CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)

        for (level in NativeCardExchangeLevel.entries) {
            assertEquals(
                bridgeFailure,
                NativeCardManagement.probeCredentialHealth(level, readPinLengths = true, exchange = exchange),
            )

            val pin1Current = secretBytes(CardPinLengths.FINEID.pin1.first)
            val pin1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
            assertEquals(bridgeFailure, NativeCardManagement.changePin1(level, pin1Current, pin1Next, exchange))
            assertZeroed(pin1Current, pin1Next)

            val pin2Current = secretBytes(CardPinLengths.FINEID.pin2.first)
            val pin2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
            assertEquals(bridgeFailure, NativeCardManagement.changePin2(level, pin2Current, pin2Next, exchange))
            assertZeroed(pin2Current, pin2Next)

            val pukForPin1 = secretBytes(CardPinLengths.FINEID.puk.first)
            val unblockedPin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
            assertEquals(bridgeFailure, NativeCardManagement.unblockPin1(level, pukForPin1, unblockedPin1, exchange))
            assertZeroed(pukForPin1, unblockedPin1)

            val pukForPin2 = secretBytes(CardPinLengths.FINEID.puk.first)
            val unblockedPin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
            assertEquals(bridgeFailure, NativeCardManagement.unblockPin2(level, pukForPin2, unblockedPin2, exchange))
            assertZeroed(pukForPin2, unblockedPin2)

            val fullCode = secretBytes(CardPinLengths.FINEID.puk.first)
            val fullPin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
            val fullPin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
            assertEquals(
                bridgeFailure,
                NativeCardManagement.activateCard(
                    level,
                    CardManagementScheme.PUK,
                    fullCode,
                    fullPin1,
                    fullPin2,
                    exchange,
                ),
            )
            assertZeroed(fullCode, fullPin1, fullPin2)

            val codeWithoutPins = secretBytes(PRESET_ACTIVATION_CODE_LENGTH)
            assertEquals(
                bridgeFailure,
                NativeCardManagement.activateCard(
                    level,
                    CardManagementScheme.PRESET_PIN,
                    codeWithoutPins,
                    newPin1 = null,
                    newPin2 = null,
                    exchange = exchange,
                ),
            )
            assertZeroed(codeWithoutPins)
        }
        assertEquals(NativeCardManagementWire.ZERO_INT, exchange.invocations)
    }

    @Test
    fun wipesContactlessPaceSecretsAndReturnsBridgeErrorWhenNativeLibraryIsUnloaded() {
        assertFalse(NativeCore.isLoaded)
        val exchange = RecordingBlockExchange()
        val bridgeFailure = CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)

        val probeCan = secretBytes(CanSubmission.CAN_DIGITS)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessProbeCredentialHealth(
                can = probeCan,
                readPinLengths = false,
                exchange = exchange,
            ),
        )
        assertZeroed(probeCan)

        val change1Can = secretBytes(CanSubmission.CAN_DIGITS)
        val change1Current = secretBytes(CardPinLengths.FINEID.pin1.first)
        val change1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessChangePin1(change1Can, change1Current, change1Next, exchange),
        )
        assertZeroed(change1Can, change1Current, change1Next)

        val change2Can = secretBytes(CanSubmission.CAN_DIGITS)
        val change2Current = secretBytes(CardPinLengths.FINEID.pin2.first)
        val change2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessChangePin2(change2Can, change2Current, change2Next, exchange),
        )
        assertZeroed(change2Can, change2Current, change2Next)

        val unblock1Can = secretBytes(CanSubmission.CAN_DIGITS)
        val unblock1Puk = secretBytes(CardPinLengths.FINEID.puk.first)
        val unblock1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessUnblockPin1(unblock1Can, unblock1Puk, unblock1Next, exchange),
        )
        assertZeroed(unblock1Can, unblock1Puk, unblock1Next)

        val unblock2Can = secretBytes(CanSubmission.CAN_DIGITS)
        val unblock2Puk = secretBytes(CardPinLengths.FINEID.puk.first)
        val unblock2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessUnblockPin2(unblock2Can, unblock2Puk, unblock2Next, exchange),
        )
        assertZeroed(unblock2Can, unblock2Puk, unblock2Next)

        val activateCan = secretBytes(CanSubmission.CAN_DIGITS)
        val activateCode = secretBytes(CardPinLengths.FINEID.puk.first)
        val activatePin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
        val activatePin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessActivateCard(
                can = activateCan,
                scheme = CardManagementScheme.PUK,
                code = activateCode,
                newPin1 = activatePin1,
                newPin2 = activatePin2,
                exchange = exchange,
            ),
        )
        assertZeroed(activateCan, activateCode, activatePin1, activatePin2)

        val singlePinCan = secretBytes(CanSubmission.CAN_DIGITS)
        val singlePinCode = secretBytes(PRESET_ACTIVATION_CODE_LENGTH)
        val singlePin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessActivateCard(
                can = singlePinCan,
                scheme = CardManagementScheme.PRESET_PIN,
                code = singlePinCode,
                newPin1 = null,
                newPin2 = singlePin2,
                exchange = exchange,
            ),
        )
        assertZeroed(singlePinCan, singlePinCode, singlePin2)
        assertEquals(NativeCardManagementWire.ZERO_INT, exchange.invocations)
    }

    @Test
    fun wipesHeldSessionSecretsAndReturnsBridgeErrorWhenNativeLibraryIsUnloaded() {
        assertFalse(NativeCore.isLoaded)
        val exchange = RecordingBlockExchange()
        val bridgeFailure = CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)

        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessProbeCredentialHealthOnSession(readPinLengths = true, exchange = exchange),
        )

        val pin1Current = secretBytes(CardPinLengths.FINEID.pin1.first)
        val pin1Next = secretBytes(CardPinLengths.FINEID.pin1.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessChangePin1OnSession(pin1Current, pin1Next, exchange),
        )
        assertZeroed(pin1Current, pin1Next)

        val pin2Current = secretBytes(CardPinLengths.FINEID.pin2.first)
        val pin2Next = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessChangePin2OnSession(pin2Current, pin2Next, exchange),
        )
        assertZeroed(pin2Current, pin2Next)

        val puk1 = secretBytes(CardPinLengths.FINEID.puk.first)
        val unblockPin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessUnblockPin1OnSession(puk1, unblockPin1, exchange),
        )
        assertZeroed(puk1, unblockPin1)

        val puk2 = secretBytes(CardPinLengths.FINEID.puk.first)
        val unblockPin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessUnblockPin2OnSession(puk2, unblockPin2, exchange),
        )
        assertZeroed(puk2, unblockPin2)

        val activateCode = secretBytes(CardPinLengths.FINEID.puk.first)
        val activatePin1 = secretBytes(CardPinLengths.FINEID.pin1.first)
        val activatePin2 = secretBytes(CardPinLengths.FINEID.pin2.first)
        assertEquals(
            bridgeFailure,
            NativeCardManagement.contactlessActivateCardOnSession(
                scheme = CardManagementScheme.PUK,
                code = activateCode,
                newPin1 = activatePin1,
                newPin2 = activatePin2,
                exchange = exchange,
            ),
        )
        assertZeroed(activateCode, activatePin1, activatePin2)
        assertEquals(NativeCardManagementWire.ZERO_INT, exchange.invocations)
    }

    @Test
    fun decodesCredentialHealthAndClearsReplyBuffer() {
        val baseReply =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                NativeCardManagementWire.PIN_STATE_REMAINING.toByte(),
                SYNTHETIC_PIN1_RETRIES.toByte(),
                NativeCardManagementWire.PIN_STATE_LOCKED.toByte(),
                NativeCardManagementWire.ZERO_BYTE,
                NativeCardManagementWire.PIN_STATE_VERIFIED.toByte(),
                NO_RETRY_OCTET,
                NativeCardManagementWire.SCHEME_ORGANIZATIONAL.toByte(),
                NativeCardManagementWire.ACTIVATION_SCHEME_PUK.toByte(),
                NativeCardManagementWire.ACTIVATION_NEEDS_PIN1_ONLY.toByte(),
            )
        assertEquals(
            CardManagementResult.Success(
                CredentialHealth(
                    pin1State = NativePin1State.Remaining(SYNTHETIC_PIN1_RETRIES),
                    pin2State = NativePin2State.Locked,
                    pukState = NativePin1State.Verified,
                    scheme = NativePinReferenceScheme.ORGANIZATIONAL,
                    activationScheme = CardManagementScheme.PUK,
                    activationNeeds = CardActivationNeeds(pin1 = true, pin2 = false),
                    pinLengths = null,
                ),
            ),
            NativeCardManagement.decodeCredentialHealth(baseReply),
        )
        assertZeroed(baseReply)

        val replyWithLengths =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                NativeCardManagementWire.PIN_STATE_NO_INFO.toByte(),
                NO_RETRY_OCTET,
                NativeCardManagementWire.PIN_STATE_UNRECOGNISED.toByte(),
                NO_RETRY_OCTET,
                NativeCardManagementWire.PIN_STATE_REMAINING.toByte(),
                SYNTHETIC_PUK_RETRIES.toByte(),
                NativeCardManagementWire.SCHEME_CITIZEN.toByte(),
                NativeCardManagementWire.ACTIVATION_SCHEME_PRESET.toByte(),
                NativeCardManagementWire.ACTIVATION_NEEDS_BOTH.toByte(),
                CardPinLengths.FINEID.pin1.first
                    .toByte(),
                CardPinLengths.FINEID.pin1.last
                    .toByte(),
                NativeCardManagementWire.ZERO_BYTE,
                NativeCardManagementWire.ZERO_BYTE,
                CardPinLengths.FINEID.puk.first
                    .toByte(),
                CardPinLengths.FINEID.puk.last
                    .toByte(),
            )
        assertEquals(
            CardManagementResult.Success(
                CredentialHealth(
                    pin1State = NativePin1State.NoInformation,
                    pin2State = NativePin2State.Unrecognized,
                    pukState = NativePin1State.Remaining(SYNTHETIC_PUK_RETRIES),
                    scheme = NativePinReferenceScheme.CITIZEN,
                    activationScheme = CardManagementScheme.PRESET_PIN,
                    activationNeeds = CardActivationNeeds(pin1 = true, pin2 = true),
                    pinLengths =
                        CardPinLengths(
                            pin1 = CardPinLengths.FINEID.pin1,
                            pin2 = IntRange.EMPTY,
                            puk = CardPinLengths.FINEID.puk,
                        ),
                ),
            ),
            NativeCardManagement.decodeCredentialHealth(replyWithLengths),
        )
        assertZeroed(replyWithLengths)

        val malformed =
            listOf(
                byteArrayOf(),
                byteArrayOf(
                    NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                    NativeCardManagementWire.PIN_STATE_VERIFIED.toByte(),
                ),
                ByteArray(NativeCardManagementWire.HEALTH_REPLY_LENGTH + SINGLE_EXTRA_BYTE) {
                    NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte()
                },
            )
        malformed.forEach { reply ->
            assertEquals(
                CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR),
                NativeCardManagement.decodeCredentialHealth(reply),
            )
            assertZeroed(reply)
        }
    }

    @Test
    fun decodesManageOutcomesActivationReportsAndClearsReplyBuffers() {
        val wrongPinReply =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_WRONG_CREDENTIAL.toByte(),
                SYNTHETIC_PIN1_RETRIES.toByte(),
            )
        assertEquals(
            CardManagementResult.Success(ManageOutcome.WrongCredential(SYNTHETIC_PIN1_RETRIES)),
            NativeCardManagement.decodeManageOutcome(wrongPinReply),
        )
        assertZeroed(wrongPinReply)

        val statusWordReply =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_OTHER.toByte(),
                NativeCardManagementWire.ZERO_BYTE,
                SYNTHETIC_SW1.toByte(),
                SYNTHETIC_SW2.toByte(),
            )
        assertEquals(
            CardManagementResult.Success(ManageOutcome.Other(SYNTHETIC_SW1, SYNTHETIC_SW2)),
            NativeCardManagement.decodeManageOutcome(statusWordReply),
        )
        assertZeroed(statusWordReply)

        val paceFailureReply = byteArrayOf(NativeCardManagementWire.MANAGEMENT_TAG_PACE_REJECTED.toByte())
        assertEquals(
            CardManagementResult.Failure(CardManagementFailure.PACE_REJECTED),
            NativeCardManagement.decodeManageOutcome(paceFailureReply),
        )
        assertZeroed(paceFailureReply)

        val activationReply =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                NativeCardManagementWire.ACTIVATION_SCHEME_PRESET.toByte(),
                NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                NativeCardManagementWire.ZERO_BYTE,
                NativeCardManagementWire.MANAGEMENT_TAG_BRIDGE_ERROR.toByte(),
                NativeCardManagementWire.ZERO_BYTE,
            )
        val decodedActivation = NativeCardManagement.decodeActivationReport(activationReply)
        assertEquals(
            CardManagementResult.Success(
                ActivationReport(
                    scheme = CardManagementScheme.PRESET_PIN,
                    pin1Outcome = ManageOutcome.Succeeded,
                    pin2Outcome = null,
                ),
            ),
            decodedActivation,
        )
        assertNull((decodedActivation as CardManagementResult.Success).value.pin2Outcome)
        assertZeroed(activationReply)

        val truncatedActivation =
            byteArrayOf(
                NativeCardManagementWire.MANAGEMENT_TAG_SUCCEEDED.toByte(),
                NativeCardManagementWire.ACTIVATION_SCHEME_PUK.toByte(),
            )
        assertEquals(
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR),
            NativeCardManagement.decodeActivationReport(truncatedActivation),
        )
        assertZeroed(truncatedActivation)
    }

    private fun secretBytes(length: Int): ByteArray = ByteArray(length) { SYNTHETIC_SECRET_MARKER }

    private fun assertZeroed(vararg arrays: ByteArray) {
        arrays.forEach { array ->
            assertTrue(array.all { it == NativeCardManagementWire.ZERO_BYTE })
        }
    }

    private fun parseRustCardManagementConstants(): Map<String, Int> {
        val rustSource =
            sequenceOf(
                File("../native/refineid-android-core/src/card_management.rs"),
                File("native/refineid-android-core/src/card_management.rs"),
            ).firstOrNull(File::isFile)
                ?: error("Unable to locate card_management.rs from working directory")

        val pattern = Regex("""pub\(crate\)\s+const\s+([A-Z0-9_]+):\s*(?:u8|i32)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+);""")
        return pattern
            .findAll(rustSource.readText())
            .associate { match ->
                val name = match.groupValues[REGEX_NAME_GROUP]
                val literal = match.groupValues[REGEX_VALUE_GROUP]
                val parsed =
                    if (literal.startsWith(HEX_PREFIX)) {
                        literal.removePrefix(HEX_PREFIX).toInt(HEX_RADIX)
                    } else {
                        literal.toInt()
                    }
                name to parsed
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
        const val SYNTHETIC_SECRET_MARKER: Byte = 'a'.code.toByte()
        const val PRESET_ACTIVATION_CODE_LENGTH = 7
        const val SYNTHETIC_PIN1_RETRIES = 3
        const val SYNTHETIC_PUK_RETRIES = 10
        const val SYNTHETIC_SW1 = 0x69
        const val SYNTHETIC_SW2 = 0x82
        const val NO_RETRY_OCTET: Byte = -1
        const val SINGLE_EXTRA_BYTE = 1
        const val SINGLE_INVOCATION = 1
        const val BACKEND_FAILURE_REPLY_TAG: Byte = 6
        const val REGEX_NAME_GROUP = 1
        const val REGEX_VALUE_GROUP = 2
        const val HEX_PREFIX = "0x"
        const val HEX_RADIX = 16
    }
}
