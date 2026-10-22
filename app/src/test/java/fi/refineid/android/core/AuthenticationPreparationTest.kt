package fi.refineid.android.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext

internal class AuthenticationPreparationTest {
    @Test
    fun collectsMissingCredentialsAndContinuesOnlyAfterVerification() =
        runBlocking {
            val backend = Backend()
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            assertEquals(AuthenticationPreparationState.Credentials(true, true), preparation.state.value)
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertTrue(backend.retained)
            assertEquals(1, backend.verifications)
            assertTrue(backend.ownedCopyCleared())
        }

    @Test
    fun primedIdentityWithoutPinRequestsOnlyPin() =
        runBlocking {
            val backend = Backend().apply { ready = AuthenticationReadiness(true, false, true) }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
        }

    @Test
    fun primedAcceptedPinContinuesWithoutAnotherTapOrVerify() =
        runBlocking {
            val backend = Backend().apply { ready = AuthenticationReadiness(true, false, true) }
            val cache =
                AuthenticationPinCache().apply {
                    recordVerified(
                        syntheticPin().consume { it.copyOf() },
                        retention(CARD_A),
                    )
                }
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            assertTrue(opened)
            assertEquals(0, backend.verifications)
        }

    @Test
    fun rejectionInvalidatesAndNeverContinuesOrRetries() =
        runBlocking {
            val backend = Backend().apply { result = Pin1VerificationResult.WRONG_PIN }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertFalse(opened)
            assertFalse(backend.retained)
            assertEquals(1, backend.invalidations.get())
            assertEquals(1, backend.verifications)
            assertTrue(cache.isRejected(syntheticPin()))
        }

    @Test
    fun lockedCardInvalidatesWithoutRejectingUntestedCandidate() =
        runBlocking {
            val backend = Backend().apply { result = Pin1VerificationResult.PIN_LOCKED }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertFalse(opened)
            assertFalse(backend.retained)
            assertEquals(1, backend.invalidations.get())
            assertEquals(1, backend.verifications)
            syntheticPin().use { assertFalse(cache.isRejected(it)) }
        }

    @Test
    fun cancellingCardWaitClearsSubmittedPinAndSuppressesContinuation() =
        runBlocking {
            val backend = Backend().apply { wait = CompletableDeferred() }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            val candidate = syntheticPin()
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, candidate)
            preparation.state.first { it == AuthenticationPreparationState.WaitingForCard }
            preparation.cancel()
            yield()
            assertFalse(opened)
            assertFalse(backend.retained)
            assertEquals(AuthenticationPreparationState.Idle, preparation.state.value)
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        }

    @Test
    fun cancellingCompletedPreparationPreservesCardSession() =
        runBlocking {
            val backend = Backend()
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            preparation.cancel()
            assertFalse(backend.cancelled)
        }

    @Test
    fun cancellationDuringVerificationStillInvalidatesRejectedCredential() =
        runBlocking {
            val answer = CompletableFuture<Pin1VerificationResult>()
            val backend = Backend().apply { cardAnswer = answer }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            backend.awaitCardCommand()
            preparation.cancel()
            answer.complete(Pin1VerificationResult.WRONG_PIN)
            backend.awaitVerifyReturned()
            yield()
            assertEquals(1, backend.invalidations.get())
            assertFalse(opened)
            assertFalse(backend.retained)
            assertEquals(AuthenticationPreparationState.Idle, preparation.state.value)
            syntheticPin().use { assertTrue(cache.isRejected(it)) }
        }

    @Test
    fun cancellationDuringVerificationStillInvalidatesLockedCardOnly() =
        runBlocking {
            val answer = CompletableFuture<Pin1VerificationResult>()
            val backend = Backend().apply { cardAnswer = answer }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            backend.awaitCardCommand()
            preparation.cancel()
            answer.complete(Pin1VerificationResult.PIN_LOCKED)
            backend.awaitVerifyReturned()
            yield()
            assertEquals(1, backend.invalidations.get())
            syntheticPin().use { assertFalse(cache.isRejected(it)) }
        }

    @Test
    fun acceptanceArrivingAfterCancellationIsNotRetained() =
        runBlocking {
            val answer = CompletableFuture<Pin1VerificationResult>()
            val backend = Backend().apply { cardAnswer = answer }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            backend.awaitCardCommand()
            preparation.cancel()
            answer.complete(Pin1VerificationResult.VERIFIED)
            backend.awaitVerifyReturned()
            yield()
            assertFalse(opened)
            assertFalse(backend.retained)
            assertFalse(cache.hasPin)
            assertEquals(0, backend.invalidations.get())
        }

    @Test
    fun cancellationBeforeCardCommandSendsNoCredential() =
        runBlocking {
            val worker = Executors.newSingleThreadExecutor()
            val gate = CountDownLatch(1)
            worker.execute { gate.await() }
            val backend = Backend().apply { verifyContext = worker.asCoroutineDispatcher() }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            val candidate = syntheticPin()
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, candidate)
            preparation.state.first { it == AuthenticationPreparationState.Verifying }
            preparation.cancel()
            gate.countDown()
            backend.awaitVerifyReturned()
            worker.shutdown()
            yield()
            assertEquals(0, backend.verifications)
            assertEquals(0, backend.invalidations.get())
            assertFalse(backend.retained)
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
            syntheticPin().use { assertFalse(cache.isRejected(it)) }
        }

    @Test
    fun replacingOrCancellingPreparationCompletesAbandonedRequest() =
        runBlocking {
            val preparation = AuthenticationPreparation(this, Backend(), AuthenticationPinCache())
            var abandoned = 0
            preparation.start(AuthenticationPurpose.SIGN_IN, onCancelled = { abandoned++ }) {}
            preparation.start(AuthenticationPurpose.SIGN_IN, onCancelled = { abandoned++ }) {}
            assertEquals(1, abandoned)
            preparation.cancel()
            assertEquals(2, abandoned)
        }

    @Test
    fun aCardNotSeenIsWaitedForAgainWithThePinAlreadyEntered() =
        runBlocking {
            val backend = Backend().apply { requiresCan = true }
            val lostTaps = listOf(CardConnection.ABSENT, CardConnection.ABSENT)
            backend.connectAnswers.addAll(lostTaps)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(CanSubmission.from(SYNTHETIC_CAN), syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(lostTaps.size + 1, backend.connections)
            assertEquals(lostTaps.size + 1, backend.cansOffered)
            assertEquals(1, backend.attemptsReads)
            assertEquals(1, backend.verifications)
            assertTrue(backend.retained)
        }

    @Test
    fun aTimedOutWaitFailsTheAttemptAndKeepsThePinForTheRetry() =
        runBlocking {
            val backend = Backend().apply { wait = CompletableDeferred() }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache(), SHORT_TIMEOUT_MS)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertEquals(
                AuthenticationPreparationState.Failed(Pin1VerificationResult.CARD_UNAVAILABLE),
                preparation.state.value,
            )
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, false), preparation.state.value)
            preparation.cancel()
        }

    @Test
    fun aLostAnswerSendsThePinAgainOnlyWhileTheCardAllowsAsManyAttempts() =
        runBlocking {
            val backend = Backend()
            backend.verifyAnswers.add(Pin1VerificationResult.TRANSPORT_ERROR)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(2, backend.attemptsReads)
            assertEquals(2, backend.verifications)
        }

    @Test
    fun aLostAnswerWithFewerAttemptsLeftIsARejectionAndAsksThePinAgain() =
        runBlocking {
            val backend = Backend()
            backend.verifyAnswers.add(Pin1VerificationResult.TRANSPORT_ERROR)
            backend.attemptsAnswers.addAll(listOf(FINEID_PIN_TRY_LIMIT, ONE_ATTEMPT_SPENT))
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Credentials && !it.needsCan }
            assertEquals(
                AuthenticationPreparationState.Credentials(false, true, ONE_ATTEMPT_SPENT),
                preparation.state.value,
            )
            assertEquals(1, backend.verifications)
            assertEquals(1, backend.invalidations.get())
            syntheticPin().use { assertTrue(cache.isRejected(it)) }
        }

    @Test
    fun aLostAnswerWithNoAttemptsLeftLocksAndReleasesThePin() =
        runBlocking {
            val backend = Backend()
            backend.verifyAnswers.add(Pin1VerificationResult.TRANSPORT_ERROR)
            backend.attemptsAnswers.addAll(listOf(1, 0))
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertEquals(
                AuthenticationPreparationState.Failed(Pin1VerificationResult.PIN_LOCKED),
                preparation.state.value,
            )
            assertEquals(1, backend.invalidations.get())
            syntheticPin().use { assertFalse(cache.isRejected(it)) }
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, true), preparation.state.value)
        }

    @Test
    fun aCardWithNoAttemptsLeftLocksBeforeAnyPinIsSent() =
        runBlocking {
            val backend = Backend()
            backend.attemptsAnswers.add(0)
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertEquals(
                AuthenticationPreparationState.Failed(Pin1VerificationResult.PIN_LOCKED),
                preparation.state.value,
            )
            assertEquals(0, backend.verifications)
            assertEquals(1, backend.invalidations.get())
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, true), preparation.state.value)
        }

    @Test
    fun aLostAnswerWithUnreadableAttemptsAsksThePinAgain() =
        runBlocking {
            val backend = Backend()
            backend.verifyAnswers.add(Pin1VerificationResult.TRANSPORT_ERROR)
            backend.attemptsAnswers.addAll(listOf(FINEID_PIN_TRY_LIMIT, null))
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Credentials && !it.needsCan }
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
            assertEquals(1, backend.verifications)
            assertEquals(0, backend.invalidations.get())
            syntheticPin().use { assertFalse(cache.isRejected(it)) }
        }

    @Test
    fun contactLostDuringVerificationTriesTheSamePinAgain() =
        runBlocking {
            val backend = Backend()
            val lostAnswers = listOf(Pin1VerificationResult.TRANSPORT_ERROR, Pin1VerificationResult.CARD_UNAVAILABLE)
            backend.verifyAnswers.addAll(lostAnswers)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(lostAnswers.size + 1, backend.verifications)
            assertEquals(lostAnswers.size + 1, backend.connections)
            assertEquals(0, backend.invalidations.get())
        }

    @Test
    fun aCardThatCannotBeUsedFailsAndTheRetryAsksNoPin() =
        runBlocking {
            val backend = Backend()
            backend.connectAnswers.add(CardConnection.REFUSED)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertEquals(
                AuthenticationPreparationState.Failed(Pin1VerificationResult.CARD_UNAVAILABLE),
                preparation.state.value,
            )
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, false), preparation.state.value)
            preparation.submit(CanSubmission.from(SYNTHETIC_CAN), null)
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertEquals(1, backend.verifications)
        }

    @Test
    fun aWrongCanFailsAsSuchAndKeepsThePin() =
        runBlocking {
            val backend = Backend()
            backend.connectAnswers.add(CardConnection.WRONG_CAN)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(CanSubmission.from(SYNTHETIC_CAN), syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertEquals(
                AuthenticationPreparationState.Failed(Pin1VerificationResult.PACE_REJECTED),
                preparation.state.value,
            )
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, false), preparation.state.value)
            preparation.cancel()
        }

    @Test
    fun aRejectedPinIsAskedAgainOnRetry() =
        runBlocking {
            val backend = Backend().apply { result = Pin1VerificationResult.WRONG_PIN }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            preparation.retry()
            assertEquals(AuthenticationPreparationState.Credentials(true, true), preparation.state.value)
        }

    @Test
    fun cancellingAfterAFailedTapClearsTheHeldPin() =
        runBlocking {
            val backend = Backend()
            backend.connectAnswers.add(CardConnection.REFUSED)
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            val candidate = syntheticPin()
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, candidate)
            preparation.state.first { it is AuthenticationPreparationState.Failed }
            assertTrue(runCatching { candidate.copyBytes() }.isSuccess)
            preparation.cancel()
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        }

    @Test
    fun duplicateSubmissionsDoNotStartAnotherCardOperation() =
        runBlocking {
            val backend = Backend().apply { wait = CompletableDeferred() }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.WaitingForCard }
            assertEquals(1, backend.connections)
            preparation.cancel()
        }

    @Test
    fun aPinHeldForOneCardIsNeverSentToAnotherAndTheHolderIsAsked() =
        runBlocking {
            val backend = Backend().apply { ready = AuthenticationReadiness(false, false, true) }
            backend.cards.add(CARD_B)
            val cache =
                AuthenticationPinCache().apply {
                    recordVerified(
                        syntheticPin().consume { it.copyOf() },
                        retention(CARD_A),
                    )
                }
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.state.first { it is AuthenticationPreparationState.Credentials }
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
            assertEquals(0, backend.verifications)
            assertFalse(cache.hasPin)
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(1, backend.verifications)
            assertEquals(CARD_B, backend.retainedFor)
        }

    @Test
    fun aPinHeldForTheConnectedCardIsSentWithoutAPrompt() =
        runBlocking {
            val backend = Backend().apply { ready = AuthenticationReadiness(false, false, true) }
            val cache =
                AuthenticationPinCache().apply {
                    recordVerified(
                        syntheticPin().consume { it.copyOf() },
                        retention(CARD_A),
                    )
                }
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(1, backend.verifications)
            assertEquals(CARD_A, backend.retainedFor)
        }

    @Test
    fun aHeldPinIsDroppedUnsentOnceItsCardCounterFalls() =
        runBlocking {
            val backend =
                Backend().apply {
                    ready = AuthenticationReadiness(false, false, true)
                    attemptsLeft = ONE_ATTEMPT_SPENT
                }
            val cache =
                AuthenticationPinCache().apply {
                    recordVerified(
                        syntheticPin().consume { it.copyOf() },
                        retention(CARD_A),
                    )
                }
            val preparation = AuthenticationPreparation(this, backend, cache)
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.state.first { it is AuthenticationPreparationState.Credentials }
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
            assertEquals(0, backend.verifications)
            assertFalse(cache.hasPin)
        }

    @Test
    fun aPinAcceptedBelowAPristineCounterServesOnlyThisPreparation() =
        runBlocking {
            val backend = Backend().apply { attemptsLeft = ONE_ATTEMPT_SPENT }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            var opened = false
            preparation.start(AuthenticationPurpose.SIGN_IN) { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Ready }
            assertTrue(opened)
            assertEquals(1, backend.verifications)
            assertFalse(backend.retained)
        }

    @Test
    fun anEnteredPinWhoseAnswerWasLostIsNotSentToAnotherCard() =
        runBlocking {
            val backend = Backend()
            backend.verifyAnswers.add(Pin1VerificationResult.TRANSPORT_ERROR)
            backend.cards.addAll(listOf(CARD_A, CARD_B))
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start(AuthenticationPurpose.SIGN_IN) {}
            preparation.submit(null, syntheticPin())
            preparation.state.first { it is AuthenticationPreparationState.Credentials && !it.needsCan }
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
            assertEquals(1, backend.verifications)
        }

    private class Backend : AuthenticationPreparationBackend {
        var ready = AuthenticationReadiness(false, true, true)
        var result = Pin1VerificationResult.VERIFIED
        var verifyContext: CoroutineContext = Dispatchers.IO

        /** When set, the card command blocks like native VERIFY until answered. */
        var cardAnswer: CompletableFuture<Pin1VerificationResult>? = null

        @Volatile
        var verifications = 0
        var connections = 0
        var cansOffered = 0
        var attemptsReads = 0
        var retained = false

        /** The card answers READY only to a wait that offers the access number. */
        var requiresCan = false

        /** Attempts the card allows when no scripted answer is queued. */
        var attemptsLeft: Int? = FINEID_PIN_TRY_LIMIT

        /** The cards successive waits find; the last one found stays, [CARD_A] before any. */
        val cards = ArrayDeque<AuthenticationCardIdentity?>()
        private var connected: AuthenticationCardIdentity? = null

        /** The card the last retained PIN was held for. */
        var retainedFor: AuthenticationCardIdentity? = null

        /** Answers to successive reads of the attempts left, then [attemptsLeft]. */
        val attemptsAnswers = ArrayDeque<Int?>()

        /** Answers to successive waits for the card, then READY. */
        val connectAnswers = ArrayDeque<CardConnection>()

        /** Answers to successive card commands, then [result]. */
        val verifyAnswers = ArrayDeque<Pin1VerificationResult>()
        val invalidations = AtomicInteger()
        var cancelled = false
        var wait: CompletableDeferred<Boolean>? = null
        private val cardCommand = CompletableFuture<Unit>()
        private val verifyReturned = CompletableDeferred<Unit>()
        private var owned: ByteArray? = null

        override fun readiness(): AuthenticationReadiness = ready

        override suspend fun connect(can: CanSubmission?): CardConnection {
            connections++
            if (can != null) cansOffered++
            can?.close()
            if (wait?.await() == false) return CardConnection.ABSENT
            val answer = connectAnswers.removeFirstOrNull() ?: CardConnection.READY
            if (answer == CardConnection.READY && requiresCan && can == null) return CardConnection.WRONG_CAN
            if (answer == CardConnection.READY) connected = cards.removeFirstOrNull() ?: connected ?: CARD_A
            return answer
        }

        override suspend fun connectedCard(): AuthenticationCardIdentity? = connected

        override suspend fun pin1AttemptsLeft(): Int? {
            attemptsReads++
            return if (attemptsAnswers.isEmpty()) attemptsLeft else attemptsAnswers.removeFirst()
        }

        override suspend fun verify(
            pin1: Pin1Submission,
            outcome: Pin1VerificationOutcome,
        ): Pin1VerificationResult =
            try {
                runPin1Verification(verifyContext, pin1, outcome) { submission ->
                    submission.close()
                    verifications++
                    cardCommand.complete(Unit)
                    cardAnswer?.get(TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        ?: verifyAnswers.removeFirstOrNull()
                        ?: result
                }
            } finally {
                verifyReturned.complete(Unit)
            }

        override suspend fun retainVerified(
            pin: ByteArray,
            retention: Pin1Retention,
        ): Boolean {
            owned = pin
            retained = true
            retainedFor = retention.card
            pin.fill(0)
            return true
        }

        override fun invalidate() {
            invalidations.incrementAndGet()
        }

        override fun cancel() {
            cancelled = true
        }

        suspend fun awaitCardCommand() {
            withContext(Dispatchers.IO) { cardCommand.get(TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS) }
        }

        suspend fun awaitVerifyReturned() {
            withTimeout(TimeUnit.SECONDS.toMillis(TEST_TIMEOUT_SECONDS)) { verifyReturned.await() }
        }

        fun ownedCopyCleared(): Boolean = owned?.all { it == CLEARED_BYTE } == true
    }

    private companion object {
        const val CLEARED_BYTE: Byte = 0
        const val TEST_TIMEOUT_SECONDS = 5L
        const val SHORT_TIMEOUT_MS = 50L
        const val ONE_ATTEMPT_SPENT = FINEID_PIN_TRY_LIMIT - 1
        const val CERTIFICATE_A = "synthetic authentication certificate of card A"
        const val CERTIFICATE_B = "synthetic authentication certificate of card B"
        val CARD_A = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_A.encodeToByteArray()))
        val CARD_B = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_B.encodeToByteArray()))

        fun retention(card: AuthenticationCardIdentity): Pin1Retention =
            checkNotNull(Pin1Retention.of(card, FINEID_PIN_TRY_LIMIT))

        val SYNTHETIC_CAN = CharArray(CanSubmission.CAN_DIGITS) { '0' }.concatToString()

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())
    }
}
