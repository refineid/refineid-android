package fi.refineid.android.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

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
            assertTrue(backend.invalidated)
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
            assertTrue(backend.invalidated)
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
            val backend = Backend().apply { verificationWait = CompletableDeferred() }
            val cache = AuthenticationPinCache()
            val preparation = AuthenticationPreparation(this, backend, cache)
            var opened = false
            preparation.start { opened = true }
            preparation.submit(null, syntheticPin())
            preparation.state.first { it == AuthenticationPreparationState.Verifying }
            yield()
            preparation.cancel()
            checkNotNull(backend.verificationWait).complete(Pin1VerificationResult.WRONG_PIN)
            yield()
            assertTrue(backend.invalidated)
            assertFalse(opened)
            assertFalse(backend.retained)
            syntheticPin().use { assertTrue(cache.isRejected(it)) }
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
        var verifications = 0
        var connections = 0
        var retained = false
        var invalidated = false
        var cancelled = false
        var wait: CompletableDeferred<Boolean>? = null
        var verificationWait: CompletableDeferred<Pin1VerificationResult>? = null
        private var owned: ByteArray? = null

        override fun readiness(): AuthenticationReadiness = ready

        override suspend fun connect(can: CanSubmission?): Boolean {
            connections++
            return wait?.await() ?: true
        }

        override suspend fun verify(pin1: Pin1Submission): Pin1VerificationResult {
            verifications++
            pin1.close()
            return verificationWait?.await() ?: result
        }

        override suspend fun retainVerified(pin: ByteArray): Boolean {
            owned = pin
            retained = true
            pin.fill(0)
            return true
        }

        override fun invalidate() {
            invalidated = true
        }

        override fun cancel() {
            cancelled = true
        }

        fun ownedCopyCleared(): Boolean = owned?.all { it == CLEARED_BYTE } == true
    }

    private companion object {
        const val CLEARED_BYTE: Byte = 0

        fun syntheticPin(): Pin1Submission =
            Pin1Submission.from(CharArray(PIN1_MINIMUM_LENGTH) { '0' }.concatToString())
    }
}
