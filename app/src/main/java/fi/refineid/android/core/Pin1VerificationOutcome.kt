package fi.refineid.android.core

import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.CoroutineContext

/**
 * The card's answer to one PIN1 VERIFY, owning its own copy of the
 * candidate digits. The verifier reports the answer on the thread that
 * observed it, before a cancelled requester can discard it, so a card
 * rejection always clears custody. Only the first rejection acts;
 * [close] zeroes the copy when no rejection consumed it.
 */
internal class Pin1VerificationOutcome(
    candidate: ByteArray,
    private val pinCache: AuthenticationPinCache,
    private val invalidate: () -> Unit,
) : AutoCloseable {
    private val rejected = AtomicBoolean(false)
    private var owned: ByteArray? = candidate

    fun report(result: Pin1VerificationResult) {
        if (result != Pin1VerificationResult.WRONG_PIN && result != Pin1VerificationResult.PIN_LOCKED) return
        if (!rejected.compareAndSet(false, true)) return
        val bytes = take()
        // A locked card answers without testing the digits; they stay unrecorded.
        if (result == Pin1VerificationResult.WRONG_PIN && bytes != null) {
            pinCache.recordRejected(bytes)
        } else {
            bytes?.fill(0)
        }
        invalidate()
    }

    override fun close() {
        take()?.fill(0)
    }

    private fun take(): ByteArray? =
        synchronized(this) {
            owned.also { owned = null }
        }
}

/**
 * Runs one blocking VERIFY in [context], taking ownership of [pin1] and
 * [outcome]. A caller cancelled before the block starts sends no
 * credential command. Once [verify] starts it runs to completion, and its
 * answer reaches [outcome] before the caller can observe cancellation.
 */
internal suspend fun runPin1Verification(
    context: CoroutineContext,
    pin1: Pin1Submission,
    outcome: Pin1VerificationOutcome,
    verify: (Pin1Submission) -> Pin1VerificationResult,
): Pin1VerificationResult =
    outcome.use {
        pin1.use {
            withContext(context) {
                ensureActive()
                verify(pin1).also(outcome::report)
            }
        }
    }
