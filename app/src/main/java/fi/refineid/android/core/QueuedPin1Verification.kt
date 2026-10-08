package fi.refineid.android.core

import android.os.Looper
import fi.refineid.android.usb.awaitPreservingInterrupt
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/** Runs a credential command on its session owner and rejects superseded work. */
internal fun verifyQueuedPin1(
    pin1: Pin1Submission,
    executor: ExecutorService,
    isReady: () -> Boolean,
    currentGeneration: () -> Int,
    verify: (Pin1Submission) -> Pin1VerificationResult?,
): Pin1VerificationResult {
    if (Looper.myLooper() == Looper.getMainLooper() || !isReady()) {
        pin1.close()
        return Pin1VerificationResult.CARD_UNAVAILABLE
    }
    val generation = currentGeneration()
    val completion = CompletableFuture<Pin1VerificationResult>()
    try {
        executor.execute {
            val result =
                try {
                    if (generation == currentGeneration() && isReady()) {
                        verify(pin1) ?: Pin1VerificationResult.CARD_UNAVAILABLE
                    } else {
                        Pin1VerificationResult.CARD_UNAVAILABLE
                    }
                } catch (_: RuntimeException) {
                    Pin1VerificationResult.BRIDGE_ERROR
                } finally {
                    pin1.close()
                }
            completion.complete(result)
        }
    } catch (_: RejectedExecutionException) {
        pin1.close()
        return Pin1VerificationResult.CARD_UNAVAILABLE
    }
    return completion.awaitPreservingInterrupt()
}
