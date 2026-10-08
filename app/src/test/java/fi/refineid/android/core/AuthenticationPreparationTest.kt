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
            preparation.start { opened = true }
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
            preparation.start {}
            assertEquals(AuthenticationPreparationState.Credentials(false, true), preparation.state.value)
        }

    @Test
    fun primedAcceptedPinContinuesWithoutAnotherTapOrVerify() =
        runBlocking {
            val backend = Backend().apply { ready = AuthenticationReadiness(true, false, true) }
            val cache = AuthenticationPinCache().apply { recordVerified(syntheticPin().consume { it.copyOf() }) }
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start { opened = true }
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
            preparation.start { opened = true }
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
            preparation.start { opened = true }
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
            preparation.start { opened = true }
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
            preparation.start {}
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
            preparation.start { opened = true }
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
            preparation.start {}
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
            preparation.start { opened = true }
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
            preparation.start {}
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
            preparation.start({}, { abandoned++ })
            preparation.start({}, { abandoned++ })
            assertEquals(1, abandoned)
            preparation.cancel()
            assertEquals(2, abandoned)
        }

    @Test
    fun duplicateSubmissionsDoNotStartAnotherCardOperation() =
        runBlocking {
            val backend = Backend().apply { wait = CompletableDeferred() }
            val preparation = AuthenticationPreparation(this, backend, AuthenticationPinCache())
            preparation.start {}
            preparation.submit(null, syntheticPin())
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.WaitingForCard }
            assertEquals(1, backend.connections)
            preparation.cancel()
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
        var retained = false
        val invalidations = AtomicInteger()
        var cancelled = false
        var wait: CompletableDeferred<Boolean>? = null
        private val cardCommand = CompletableFuture<Unit>()
        private val verifyReturned = CompletableDeferred<Unit>()
        private var owned: ByteArray? = null

        override fun readiness(): AuthenticationReadiness = ready

        override suspend fun connect(can: CanSubmission?): Boolean {
            connections++
            return wait?.await() ?: true
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
                    cardAnswer?.get(TEST_TIMEOUT_SECONDS, TimeUnit.SECONDS) ?: result
                }
            } finally {
                verifyReturned.complete(Unit)
            }

        override suspend fun retainVerified(pin: ByteArray): Boolean {
            owned = pin
            retained = true
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

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())
    }
}
