package fi.refineid.android.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(AndroidJUnit4::class)
internal class QueuedPin1VerificationInstrumentedTest {
    @Test
    fun supersededQueuedVerificationNeverPresentsCredential() {
        val owner = Executors.newSingleThreadExecutor()
        val caller = Executors.newSingleThreadExecutor()
        val busy = CountDownLatch(1)
        val release = CountDownLatch(1)
        val captured = CountDownLatch(1)
        val generation = AtomicInteger()
        val candidate = Pin1Submission.fromOwnedBytes(ByteArray(PIN1_MINIMUM_LENGTH) { DIGIT_ZERO_BYTE })
        var verified = false
        try {
            owner.execute {
                busy.countDown()
                release.await()
            }
            assertTrue(busy.await(TIMEOUT_SECONDS, TimeUnit.SECONDS))
            val result =
                caller.submit<Pin1VerificationResult> {
                    verifyQueuedPin1(
                        candidate,
                        owner,
                        isReady = { true },
                        currentGeneration = {
                            val current = generation.get()
                            captured.countDown()
                            current
                        },
                        expectedGeneration = 0,
                        verify = {
                            verified = true
                            Pin1VerificationResult.VERIFIED
                        },
                    )
                }
            assertTrue(captured.await(TIMEOUT_SECONDS, TimeUnit.SECONDS))
            generation.incrementAndGet()
            release.countDown()
            assertEquals(Pin1VerificationResult.CARD_UNAVAILABLE, result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS))
            assertFalse(verified)
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        } finally {
            release.countDown()
            candidate.close()
            caller.shutdownNow()
            owner.shutdownNow()
        }
    }

    @Test
    fun staleSessionGenerationIsRefusedBeforeQueueing() {
        val owner = Executors.newSingleThreadExecutor()
        val caller = Executors.newSingleThreadExecutor()
        val candidate = Pin1Submission.fromOwnedBytes(ByteArray(PIN1_MINIMUM_LENGTH) { DIGIT_ZERO_BYTE })
        var verified = false
        try {
            val result =
                caller.submit<Pin1VerificationResult> {
                    verifyQueuedPin1(
                        candidate,
                        owner,
                        isReady = { true },
                        currentGeneration = { 1 },
                        expectedGeneration = 0,
                        verify = {
                            verified = true
                            Pin1VerificationResult.VERIFIED
                        },
                    )
                }
            assertEquals(Pin1VerificationResult.CARD_UNAVAILABLE, result.get(TIMEOUT_SECONDS, TimeUnit.SECONDS))
            assertFalse(verified)
            assertTrue(runCatching { candidate.copyBytes() }.isFailure)
        } finally {
            candidate.close()
            caller.shutdownNow()
            owner.shutdownNow()
        }
    }

    private companion object {
        const val TIMEOUT_SECONDS = 5L
    }
}
