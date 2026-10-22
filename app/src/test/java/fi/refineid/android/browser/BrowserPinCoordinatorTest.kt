package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignature
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.Pin1VerificationResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SignatureException

class BrowserPinCoordinatorTest {
    @Test
    fun onePromptSuppliesOnePinAndOneCardSignature() {
        val statuses = mutableListOf<BrowserSignatureStatus>()
        val prompts = mutableListOf<BrowserPinRequest?>()
        val service = RecordingCardService()
        val coordinator =
            BrowserPinCoordinator(
                cardService = service,
                dispatchToUi = { action -> action() },
                onPromptChanged = { request ->
                    prompts += request
                    request?.submit(Pin1Submission.from(SYNTHETIC_PIN1))
                },
                onStatusChanged = statuses::add,
            )

        val signature =
            coordinator.sign(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                SYNTHETIC_MESSAGE.copyOf(),
            )

        assertArrayEquals(SYNTHETIC_MESSAGE, service.observedMessage)
        assertEquals(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, service.observedAlgorithm)
        assertEquals(SYNTHETIC_PIN1, service.observedPin1)
        assertEquals(
            listOf(
                BrowserSignatureStatus.PIN_REQUIRED,
                BrowserSignatureStatus.SIGNING,
                BrowserSignatureStatus.SUCCEEDED,
            ),
            statuses,
        )
        assertEquals(EXPECTED_PROMPT_EVENT_COUNT, prompts.size)
        assertTrue(prompts.first() is BrowserPinRequest)
        assertEquals(null, prompts.last())
        signature.close()
        coordinator.close()
    }

    @Test
    fun coarseCardFailureBecomesAJcaFailureAndUiStatus() {
        val statuses = mutableListOf<BrowserSignatureStatus>()
        val service = RecordingCardService(AuthenticationSignFailure.WRONG_PIN)
        val coordinator =
            BrowserPinCoordinator(
                cardService = service,
                dispatchToUi = { action -> action() },
                onPromptChanged = { request ->
                    request?.submit(Pin1Submission.from(SYNTHETIC_PIN1))
                },
                onStatusChanged = statuses::add,
            )

        assertThrows(SignatureException::class.java) {
            coordinator.sign(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                SYNTHETIC_MESSAGE.copyOf(),
            )
        }
        assertEquals(BrowserSignatureStatus.WRONG_PIN, statuses.last())
        coordinator.close()
    }

    @Test
    fun closedCoordinatorRejectsWithoutPromptingOrUsingTheCard() {
        var promptCount = 0
        val service = RecordingCardService()
        val coordinator =
            BrowserPinCoordinator(
                cardService = service,
                dispatchToUi = { action -> action() },
                onPromptChanged = { promptCount += 1 },
                onStatusChanged = {},
            )
        coordinator.close()

        assertThrows(SignatureException::class.java) {
            coordinator.sign(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                SYNTHETIC_MESSAGE.copyOf(),
            )
        }
        assertEquals(CLOSE_PROMPT_EVENT_COUNT, promptCount)
        assertEquals(null, service.observedAlgorithm)
    }

    @Test
    fun timedOutPromptRejectsAndClosesALatePin() {
        var prompt: BrowserPinRequest? = null
        val statuses = mutableListOf<BrowserSignatureStatus>()
        val service = RecordingCardService()
        val coordinator =
            BrowserPinCoordinator(
                cardService = service,
                dispatchToUi = { action -> action() },
                onPromptChanged = { request ->
                    if (request != null) {
                        prompt = request
                    }
                },
                onStatusChanged = statuses::add,
                pinEntryTimeoutMilliseconds = IMMEDIATE_TIMEOUT_MILLISECONDS,
            )

        assertThrows(SignatureException::class.java) {
            coordinator.sign(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                SYNTHETIC_MESSAGE.copyOf(),
            )
        }
        val latePin = Pin1Submission.from(SYNTHETIC_PIN1)
        checkNotNull(prompt).submit(latePin)
        assertThrows(IllegalStateException::class.java) {
            latePin.consume { }
        }
        assertEquals(BrowserSignatureStatus.TIMED_OUT, statuses.last())
        assertEquals(null, service.observedAlgorithm)
        coordinator.close()
    }

    @Test
    fun cancelledPromptRejectsBeforeCardUseAndReportsItsCause() {
        val statuses = mutableListOf<BrowserSignatureStatus>()
        val service = RecordingCardService()
        val coordinator =
            BrowserPinCoordinator(
                cardService = service,
                dispatchToUi = { action -> action() },
                onPromptChanged = { request -> request?.cancel() },
                onStatusChanged = statuses::add,
            )

        assertThrows(SignatureException::class.java) {
            coordinator.sign(
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                SYNTHETIC_MESSAGE.copyOf(),
            )
        }
        assertEquals(BrowserSignatureStatus.CANCELLED, statuses.last())
        assertEquals(null, service.observedAlgorithm)
        coordinator.close()
    }

    @Test
    fun aPinHeldForOneCardIsNeverPresentedToAnother() {
        val cache = AuthenticationPinCache()
        val card = ScriptedCardService(CERTIFICATE_A, FINEID_PIN_TRY_LIMIT)
        val entered = ArrayDeque(listOf(SYNTHETIC_PIN1, OTHER_SYNTHETIC_PIN1))
        val coordinator = scriptedCoordinator(card, cache, entered)

        coordinator.sign(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, SYNTHETIC_MESSAGE.copyOf()).close()
        coordinator.sign(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, SYNTHETIC_MESSAGE.copyOf()).close()
        assertEquals(
            "the second signature on the same card asks nothing",
            listOf(OTHER_SYNTHETIC_PIN1),
            entered.toList(),
        )

        card.certificate = CERTIFICATE_B
        coordinator.sign(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, SYNTHETIC_MESSAGE.copyOf()).close()

        assertTrue("the other card's holder was asked", entered.isEmpty())
        assertEquals(listOf(SYNTHETIC_PIN1, SYNTHETIC_PIN1, SYNTHETIC_PIN1), card.presentedTo(CERTIFICATE_A))
        assertEquals(listOf(OTHER_SYNTHETIC_PIN1, OTHER_SYNTHETIC_PIN1), card.presentedTo(CERTIFICATE_B))
        coordinator.close()
    }

    @Test
    fun aPinAcceptedBelowAPristineCounterServesOnlyItsSignature() {
        val cache = AuthenticationPinCache()
        val card = ScriptedCardService(CERTIFICATE_A, ONE_ATTEMPT_SPENT)
        val entered = ArrayDeque(listOf(SYNTHETIC_PIN1, SYNTHETIC_PIN1))
        val coordinator = scriptedCoordinator(card, cache, entered)

        coordinator.sign(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, SYNTHETIC_MESSAGE.copyOf()).close()
        assertFalse(cache.hasPin)
        coordinator.sign(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256, SYNTHETIC_MESSAGE.copyOf()).close()

        assertTrue("each signature asked the holder", entered.isEmpty())
        coordinator.close()
    }

    private fun scriptedCoordinator(
        card: ScriptedCardService,
        cache: AuthenticationPinCache,
        entered: ArrayDeque<String>,
    ): BrowserPinCoordinator =
        BrowserPinCoordinator(
            cardService = card,
            dispatchToUi = { action -> action() },
            onPromptChanged = { request -> request?.submit(Pin1Submission.from(entered.removeFirst())) },
            onStatusChanged = {},
            pinCache = cache,
        )

    /** A card whose certificate the test swaps; it records each PIN presented to it, by certificate. */
    private class ScriptedCardService(
        var certificate: String,
        private val attempts: Int,
    ) : AuthenticationCardService {
        private val presented = mutableListOf<Pair<String, String>>()

        fun presentedTo(certificate: String): List<String> =
            presented.filter { it.first == certificate }.map { it.second }

        private fun present(pin1: Pin1Submission) {
            presented += certificate to pin1.consume { bytes -> bytes.decodeToString() }
        }

        override fun verifyAuthenticationPin(
            pin1: Pin1Submission,
            expectedGeneration: Int?,
        ): Pin1Verification {
            present(pin1)
            return Pin1Verification(Pin1VerificationResult.VERIFIED)
        }

        override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
            onResult(NativeAuthenticationCertificate(NativeCardKeyProfile.RSA_2048, certificate.encodeToByteArray()))
        }

        override fun requestPin1AttemptsLeft(onResult: (Int?) -> Unit) = onResult(attempts)

        override fun signAuthenticationMessage(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            message: ByteArray,
        ): AuthenticationSignResult {
            present(pin1)
            return AuthenticationSignResult.Success(
                NativeAuthenticationSignature(algorithm, ByteArray(algorithm.signatureLength) { SIGNATURE_FILL }),
            )
        }

        override fun signAuthenticationDigest(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            digest: ByteArray,
        ): AuthenticationSignResult {
            pin1.close()
            throw AssertionError("message test unexpectedly requested a digest signature")
        }
    }

    private class RecordingCardService(
        private val failure: AuthenticationSignFailure? = null,
    ) : AuthenticationCardService {
        var observedAlgorithm: AuthenticationSigningAlgorithm? = null
        var observedMessage: ByteArray? = null
        var observedPin1: String? = null

        override fun verifyAuthenticationPin(
            pin1: Pin1Submission,
            expectedGeneration: Int?,
        ): fi.refineid.android.core.Pin1Verification {
            pin1.close()
            return fi.refineid.android.core
                .Pin1Verification(fi.refineid.android.core.Pin1VerificationResult.VERIFIED)
        }

        override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
            onResult(null)
        }

        override fun signAuthenticationMessage(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            message: ByteArray,
        ): AuthenticationSignResult {
            observedAlgorithm = algorithm
            observedMessage = message.copyOf()
            observedPin1 =
                pin1.consume { bytes ->
                    bytes.decodeToString()
                }
            return failure?.let(AuthenticationSignResult::Failure)
                ?: AuthenticationSignResult.Success(
                    NativeAuthenticationSignature(
                        algorithm,
                        ByteArray(algorithm.signatureLength) { SIGNATURE_FILL },
                    ),
                )
        }

        override fun signAuthenticationDigest(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            digest: ByteArray,
        ): AuthenticationSignResult {
            pin1.close()
            throw AssertionError("message test unexpectedly requested a digest signature")
        }
    }

    private companion object {
        const val SYNTHETIC_PIN1 = "1357"
        const val OTHER_SYNTHETIC_PIN1 = "2468"
        const val ONE_ATTEMPT_SPENT = FINEID_PIN_TRY_LIMIT - 1
        const val CERTIFICATE_A = "synthetic authentication certificate of card A"
        const val CERTIFICATE_B = "synthetic authentication certificate of card B"
        const val EXPECTED_PROMPT_EVENT_COUNT = 2
        const val CLOSE_PROMPT_EVENT_COUNT = 1
        const val IMMEDIATE_TIMEOUT_MILLISECONDS = 0L
        const val SIGNATURE_FILL: Byte = 0x5A
        val SYNTHETIC_MESSAGE = "browser authentication".encodeToByteArray()
    }
}
