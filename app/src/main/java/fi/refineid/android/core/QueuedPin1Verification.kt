package fi.refineid.android.core

import android.os.Looper
import fi.refineid.android.usb.awaitPreservingInterrupt
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/**
 * Runs a credential command on its session owner. Work queued for a
 * session other than [expectedGeneration], or for a card that is no longer
 * ready, is refused before the PIN reaches the card.
 */
internal fun verifyQueuedPin1(
    pin1: Pin1Submission,
    executor: ExecutorService,
    isReady: () -> Boolean,
    currentGeneration: () -> Int,
    expectedGeneration: Int,
    verify: (Pin1Submission) -> Pin1Verification?,
): Pin1Verification {
    if (Looper.myLooper() == Looper.getMainLooper() || !isReady() || expectedGeneration != currentGeneration()) {
        pin1.close()
        return Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
    }
    val completion = CompletableFuture<Pin1Verification>()
    try {
        executor.execute {
            val result =
                try {
                    if (expectedGeneration == currentGeneration() && isReady()) {
                        verify(pin1) ?: Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
                    } else {
                        Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
                    }
                } catch (_: RuntimeException) {
                    Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR)
                } finally {
                    pin1.close()
                }
            completion.complete(result)
        }
    } catch (_: RejectedExecutionException) {
        pin1.close()
        return Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
    }
    return completion.awaitPreservingInterrupt()
}
