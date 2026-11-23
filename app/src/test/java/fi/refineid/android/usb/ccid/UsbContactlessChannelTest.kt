package fi.refineid.android.usb.ccid

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignFailure
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeAuthenticationSignature
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativePin1Preflight
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePinReferenceScheme
import fi.refineid.android.core.PIN1_MINIMUM_LENGTH
import fi.refineid.android.core.Pin1Submission
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

internal class UsbContactlessChannelTest {
    @Test
    fun failedAuthenticationSignReleasesHeldSessionAndNextSignReopensFreshChannel() {
        val ops =
            FakeUsbContactlessOps(
                connectOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_PRISTINE),
                            ),
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_AFTER_ONE_FAILURE),
                            ),
                        ),
                    ),
                signOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.WRONG_PIN,
                            ),
                            NativeAuthenticationSignResult.Success(syntheticSignature()),
                        ),
                    ),
            )
        val channel = UsbContactlessChannel(ops)
        val inputCan = "123456".encodeToByteArray()

        assertTrue(channel.open(inputCan) is NativeContactlessOpenResult.Success)
        assertTrue(channel.isContactless)
        assertTrue(channel.hasHeldSession)
        assertTrue(inputCan.all { it == 0.toByte() })

        var pinCommandsStarted = 0
        var pinAccepted = 0
        val refreshedPreflights = mutableListOf<NativePin1Preflight>()

        val firstPin = syntheticPin()
        val firstResult =
            channel.authenticateAndSign(
                algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                inputMode = AuthenticationSigningInputMode.MESSAGE,
                pin1 = firstPin,
                input = byteArrayOf(1, 2, 3),
                onBeforePinCommand = { pinCommandsStarted += 1 },
                onPin1Accepted = { pinAccepted += 1 },
                onPreflightRefreshed = { refreshedPreflights += it },
            )
        assertEquals(
            NativeAuthenticationSignFailure.WRONG_PIN,
            (firstResult as NativeAuthenticationSignResult.Failure).kind,
        )
        assertTrue(channel.isContactless)
        assertFalse(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE), ops.steps)
        assertEquals(1, pinCommandsStarted)
        assertEquals(0, pinAccepted)
        assertClosed(firstPin)

        val secondPin = syntheticPin()
        val secondResult =
            channel.authenticateAndSign(
                algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                inputMode = AuthenticationSigningInputMode.MESSAGE,
                pin1 = secondPin,
                input = byteArrayOf(4, 5, 6),
                onBeforePinCommand = { pinCommandsStarted += 1 },
                onPin1Accepted = { pinAccepted += 1 },
                onPreflightRefreshed = { refreshedPreflights += it },
            )
        assertTrue(secondResult is NativeAuthenticationSignResult.Success)
        assertTrue(channel.isContactless)
        assertTrue(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE, CONNECT, SIGN), ops.steps)
        assertEquals(2, ops.observedCans.size)
        assertArrayEquals("123456".encodeToByteArray(), ops.observedCans[0])
        assertArrayEquals("123456".encodeToByteArray(), ops.observedCans[1])
        assertEquals(listOf(preflightRemaining(RETRIES_AFTER_ONE_FAILURE)), refreshedPreflights)
        assertEquals(2, pinCommandsStarted)
        assertEquals(1, pinAccepted)
        assertClosed(secondPin)

        channel.close()
        assertFalse(channel.isContactless)
        assertFalse(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE, CONNECT, SIGN, CLOSE), ops.steps)
    }

    @Test
    fun subsequentEnsureHeldSessionAfterFailedSignReopensPaceChannel() {
        val ops =
            FakeUsbContactlessOps(
                connectOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_PRISTINE),
                            ),
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_AFTER_ONE_FAILURE),
                            ),
                        ),
                    ),
                signOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.SIGNING_REJECTED,
                            ),
                        ),
                    ),
            )
        val channel = UsbContactlessChannel(ops)
        assertTrue(channel.open("654321".encodeToByteArray()) is NativeContactlessOpenResult.Success)

        val failed =
            channel.authenticateAndSign(
                algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                inputMode = AuthenticationSigningInputMode.MESSAGE,
                pin1 = syntheticPin(),
                input = byteArrayOf(7),
                onBeforePinCommand = {},
                onPin1Accepted = {},
            )
        assertTrue(failed is NativeAuthenticationSignResult.Failure)
        assertFalse(channel.hasHeldSession)

        val refreshed = mutableListOf<NativePin1Preflight>()
        assertNull(channel.ensureHeldSession { refreshed += it })
        assertTrue(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE, CONNECT), ops.steps)
        assertEquals(listOf(preflightRemaining(RETRIES_AFTER_ONE_FAILURE)), refreshed)
    }

    @Test
    fun failedReopenClosesPinAndDoesNotTransmitSignature() {
        val ops =
            FakeUsbContactlessOps(
                connectOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_PRISTINE),
                            ),
                            NativeContactlessOpenResult.Failure(
                                NativeCertificateReadFailure.TRANSPORT_ERROR,
                            ),
                        ),
                    ),
                signOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.TRANSPORT_ERROR,
                            ),
                        ),
                    ),
            )
        val channel = UsbContactlessChannel(ops)
        assertTrue(channel.open("123456".encodeToByteArray()) is NativeContactlessOpenResult.Success)

        channel.authenticateAndSign(
            algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = syntheticPin(),
            input = byteArrayOf(1),
            onBeforePinCommand = {},
            onPin1Accepted = {},
        )
        assertFalse(channel.hasHeldSession)

        var pinCommandsStarted = 0
        val secondPin = syntheticPin()
        val result =
            channel.authenticateAndSign(
                algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                inputMode = AuthenticationSigningInputMode.MESSAGE,
                pin1 = secondPin,
                input = byteArrayOf(2),
                onBeforePinCommand = { pinCommandsStarted += 1 },
                onPin1Accepted = {},
            )
        assertEquals(
            NativeAuthenticationSignFailure.TRANSPORT_ERROR,
            (result as NativeAuthenticationSignResult.Failure).kind,
        )
        assertEquals(0, pinCommandsStarted)
        assertFalse(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE, CONNECT, CLOSE), ops.steps)
        assertClosed(secondPin)
    }

    @Test
    fun activationRequiredDuringReopenClosesNativeChannelAndFailsClosed() {
        val ops =
            FakeUsbContactlessOps(
                connectOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeContactlessOpenResult.Success(
                                certificate = syntheticCertificate(),
                                preflight = preflightRemaining(RETRIES_PRISTINE),
                            ),
                            NativeContactlessOpenResult.ActivationRequired(
                                scheme = CardManagementScheme.PUK,
                                needs = CardActivationNeeds(pin1 = true, pin2 = false),
                            ),
                        ),
                    ),
                signOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.WRONG_PIN,
                            ),
                        ),
                    ),
            )
        val channel = UsbContactlessChannel(ops)
        assertTrue(channel.open("123456".encodeToByteArray()) is NativeContactlessOpenResult.Success)
        channel.authenticateAndSign(
            algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = syntheticPin(),
            input = byteArrayOf(1),
            onBeforePinCommand = {},
            onPin1Accepted = {},
        )

        assertEquals(
            NativeCertificateReadFailure.ACTIVATION_REQUIRED,
            channel.ensureHeldSession(),
        )
        assertFalse(channel.hasHeldSession)
        assertEquals(listOf(CONNECT, SIGN, CLOSE, CONNECT, CLOSE), ops.steps)
    }

    @Test
    fun failedInitialOpenLeavesSessionContact() {
        val ops =
            FakeUsbContactlessOps(
                connectOutcomes =
                    ArrayDeque(
                        listOf(
                            NativeContactlessOpenResult.Failure(
                                NativeCertificateReadFailure.PACE_REJECTED,
                            ),
                        ),
                    ),
                signOutcomes = ArrayDeque(),
            )
        val channel = UsbContactlessChannel(ops)
        val result = channel.open("123456".encodeToByteArray())
        assertEquals(
            NativeCertificateReadFailure.PACE_REJECTED,
            (result as NativeContactlessOpenResult.Failure).kind,
        )
        assertFalse(channel.isContactless)
        assertFalse(channel.hasHeldSession)
    }

    private class FakeUsbContactlessOps(
        private val connectOutcomes: ArrayDeque<NativeContactlessOpenResult>,
        private val signOutcomes: ArrayDeque<NativeAuthenticationSignResult>,
    ) : UsbContactlessOps {
        val steps = mutableListOf<String>()
        val observedCans = mutableListOf<ByteArray>()

        override fun connect(canCopy: ByteArray): NativeContactlessOpenResult {
            steps += CONNECT
            observedCans += canCopy.copyOf()
            canCopy.fill(0)
            return connectOutcomes.removeFirst()
        }

        override fun authenticateAndSignOnSession(
            algorithm: AuthenticationSigningAlgorithm,
            inputMode: AuthenticationSigningInputMode,
            pin1: Pin1Submission,
            input: ByteArray,
        ): NativeAuthenticationSignResult {
            steps += SIGN
            pin1.close()
            return signOutcomes.removeFirst()
        }

        override fun closeHeldSession() {
            steps += CLOSE
        }
    }

    private companion object {
        const val CONNECT = "connect"
        const val SIGN = "sign"
        const val CLOSE = "close"
        const val RETRIES_PRISTINE = 5
        const val RETRIES_AFTER_ONE_FAILURE = 4
        const val SAFETY_FLOOR = 3
        const val DER_SEQUENCE_TAG: Byte = 0x30

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())

        fun assertClosed(candidate: Pin1Submission) {
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        }

        fun syntheticCertificate(): NativeAuthenticationCertificate =
            NativeAuthenticationCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = byteArrayOf(DER_SEQUENCE_TAG, 0x00),
            )

        fun syntheticSignature(): NativeAuthenticationSignature =
            NativeAuthenticationSignature(
                algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                ownedBytes = byteArrayOf(0x01, 0x02),
            )

        fun preflightRemaining(attempts: Int): NativePin1Preflight =
            NativePin1Preflight(
                referenceScheme = NativePinReferenceScheme.CITIZEN,
                state = NativePin1State.Remaining(attempts),
                retryFloorPermits = attempts >= SAFETY_FLOOR,
            )
    }
}
