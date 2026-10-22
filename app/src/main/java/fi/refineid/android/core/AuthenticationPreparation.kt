package fi.refineid.android.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.coroutineContext

internal data class AuthenticationReadiness(
    val hasCertificate: Boolean,
    val needsCan: Boolean,
    val available: Boolean,
)

/**
 * How a wait for the card ended: the card is ready, no card answered
 * (none seen, or contact lost before it was read), the card refused the
 * access number, or the card answered and cannot be used.
 */
internal enum class CardConnection {
    READY,
    ABSENT,
    WRONG_CAN,
    REFUSED,
}

internal interface AuthenticationPreparationBackend {
    fun readiness(): AuthenticationReadiness

    /** Arms the reader with the holder's access number, when one is needed, and waits for the card. */
    suspend fun connect(can: CanSubmission?): CardConnection

    /** The card [connect] proved ready, named by its authentication certificate; null when it cannot be read. */
    suspend fun connectedCard(): AuthenticationCardIdentity?

    /** PIN 1 attempts the ready card allows, read without a VERIFY; null when it cannot be read. */
    suspend fun pin1AttemptsLeft(): Int?

    /** Takes ownership of [pin1] and [outcome]; see [runPin1Verification]. */
    suspend fun verify(
        pin1: Pin1Submission,
        outcome: Pin1VerificationOutcome,
    ): Pin1VerificationResult

    /**
     * Holds [pin], which the ready card accepted, for the card [retention]
     * names; takes ownership of [pin]. False when the ready card is no
     * longer the one served.
     */
    suspend fun retainVerified(
        pin: ByteArray,
        retention: Pin1Retention,
    ): Boolean

    fun invalidate()

    fun cancel() = Unit
}

/** What the holder is readying the card for; the prompt names it. */
internal enum class AuthenticationPurpose(
    /** Whether readying for it verifies PIN 1 on the card. */
    val needsPin1: Boolean,
) {
    /** A login in this phone's browser: the card is read and PIN 1 verified before the site is opened. */
    SIGN_IN(needsPin1 = true),

    /**
     * Serving paired computers: the card is held, read with its access
     * number when it needs one, and PIN 1 waits for the first
     * authentication a computer asks for (RAPP v26.10.22 section 11 item 2).
     */
    REMOTE_ACCESS(needsPin1 = false),
}

internal sealed interface AuthenticationPreparationState {
    data object Idle : AuthenticationPreparationState

    data class Credentials(
        val needsCan: Boolean,
        val needsPin: Boolean,
        val attemptsLeft: Int? = null,
    ) : AuthenticationPreparationState

    data object WaitingForCard : AuthenticationPreparationState

    data object Verifying : AuthenticationPreparationState

    data object Ready : AuthenticationPreparationState

    data class Failed(
        val result: Pin1VerificationResult,
    ) : AuthenticationPreparationState
}

/**
 * Owns preparation and continuation; no Android types or credentials in
 * published state. The access number, and PIN 1 for a purpose that
 * [AuthenticationPurpose.needsPin1], are asked once per preparation and
 * held in memory until the card accepts them, answers about them, or the
 * preparation ends; a card that was not seen or lost
 * contact is waited for again. A VERIFY whose answer was lost may have
 * spent an attempt, so the held PIN goes to the card again only after the
 * attempts the card allows are read back unchanged.
 *
 * A PIN 1 goes only to one card: a held one to the card it was verified
 * on, while that card's counter reads pristine, and an entered one to the
 * card it was first sent to; otherwise the holder is asked. An accepted
 * PIN 1 is held for the card only when its counter read pristine before
 * the VERIFY (credential custody).
 */
internal class AuthenticationPreparation(
    private val scope: CoroutineScope,
    private val backend: AuthenticationPreparationBackend,
    private val pinCache: AuthenticationPinCache,
    private val preparationTimeoutMs: Long = PREPARATION_TIMEOUT_MS,
) {
    private val mutableState = MutableStateFlow<AuthenticationPreparationState>(AuthenticationPreparationState.Idle)
    val state: StateFlow<AuthenticationPreparationState> = mutableState.asStateFlow()
    private val mutablePurpose = MutableStateFlow(AuthenticationPurpose.SIGN_IN)
    val purpose: StateFlow<AuthenticationPurpose> = mutablePurpose.asStateFlow()
    private var job: Job? = null
    private var continuation: (() -> Unit)? = null
    private var cancellation: (() -> Unit)? = null
    private var heldPin: Pin1Submission? = null

    /**
     * The card [heldPin] belongs to: the one custody held it for, or the one
     * it was first sent to; null before either is known.
     */
    private var heldFor: AuthenticationCardIdentity? = null
    private var heldCan: CanSubmission? = null

    /** Attempts the card allowed before the last VERIFY left, or null when unread. */
    private var attemptsBeforeVerify: Int? = null

    /** True while a VERIFY may have reached the card without an answer. */
    private var answerLost = false

    fun start(
        purpose: AuthenticationPurpose,
        onCancelled: () -> Unit = {},
        onReady: () -> Unit,
    ) {
        if (job?.isActive == true) {
            onCancelled()
            return
        }
        cancellation?.invoke()
        continuation = onReady
        cancellation = onCancelled
        mutablePurpose.value = purpose
        val ready = backend.readiness()
        val needsPin = purpose.needsPin1 && heldPin == null && !pinCache.hasPin
        when {
            !ready.available -> {
                fail(Pin1VerificationResult.CARD_UNAVAILABLE)
            }

            ready.hasCertificate && (pinCache.hasPin || !purpose.needsPin1) -> {
                complete()
            }

            ready.needsCan || needsPin -> {
                mutableState.value = AuthenticationPreparationState.Credentials(ready.needsCan, needsPin)
            }

            else -> {
                submit(null, null)
            }
        }
    }

    fun submit(
        can: CanSubmission?,
        pin1: Pin1Submission?,
    ) {
        if (job?.isActive == true || continuation == null) {
            can?.close()
            pin1?.close()
            return
        }
        if (pin1 != null) {
            releasePin()
            heldPin = pin1
        }
        if (can != null) {
            heldCan?.close()
            heldCan = can
        }
        job =
            scope.launch {
                try {
                    if (heldPin?.let(pinCache::isRejected) == true) {
                        backend.invalidate()
                        fail(Pin1VerificationResult.WRONG_PIN)
                        return@launch
                    }
                    withTimeout(preparationTimeoutMs) {
                        while (attempt()) {
                            delay(REARM_PAUSE_MS)
                        }
                    }
                } catch (error: CancellationException) {
                    if (coroutineContext[Job]?.isActive == true) {
                        fail(Pin1VerificationResult.CARD_UNAVAILABLE)
                    } else {
                        throw error
                    }
                } catch (_: RuntimeException) {
                    fail(Pin1VerificationResult.BRIDGE_ERROR)
                }
            }
    }

    /**
     * One wait for the card and one verification with the held PIN. True
     * when no card answered, so the wait starts over; false when the
     * preparation ended, completed or failed, or asks for the PIN again.
     */
    private suspend fun attempt(): Boolean {
        mutableState.value = AuthenticationPreparationState.WaitingForCard
        when (backend.connect(heldCan?.copy())) {
            CardConnection.ABSENT -> {
                return true
            }

            CardConnection.WRONG_CAN -> {
                releaseCan()
                fail(Pin1VerificationResult.PACE_REJECTED)
                return false
            }

            CardConnection.REFUSED -> {
                fail(Pin1VerificationResult.CARD_UNAVAILABLE)
                return false
            }

            CardConnection.READY -> {}
        }
        if (!mutablePurpose.value.needsPin1) {
            complete()
            return false
        }
        val card = backend.connectedCard()
        val attempts = backend.pin1AttemptsLeft()
        if (attempts == 0) {
            lockedOut()
            return false
        }
        val held = pinFor(card, attempts)
        if (held == null) {
            mutableState.value = AuthenticationPreparationState.Credentials(false, true)
            return false
        }
        if (heldFor == null) heldFor = card
        if (answerLost && !pinMayGoAgain(held, attempts)) return false
        attemptsBeforeVerify = attempts
        mutableState.value = AuthenticationPreparationState.Verifying
        answerLost = true
        val result = verifyHeld(held)
        coroutineContext.ensureActive()
        when (result) {
            Pin1VerificationResult.CARD_UNAVAILABLE, Pin1VerificationResult.TRANSPORT_ERROR -> {
                return true
            }

            Pin1VerificationResult.VERIFIED -> {
                answerLost = false
                val retention = Pin1Retention.of(card, attempts)
                if (retention == null) {
                    // The PIN served this preparation only.
                    complete()
                    return false
                }
                val retained = held.copyBytes()
                val kept =
                    try {
                        backend.retainVerified(retained, retention)
                    } finally {
                        retained.fill(0)
                    }
                if (kept) complete() else fail(Pin1VerificationResult.CARD_UNAVAILABLE)
            }

            else -> {
                answerLost = false
                fail(result)
            }
        }
        return false
    }

    /**
     * The PIN to verify on [card]: the one in hand, or the one custody holds
     * for [card] while its counter reads pristine. A PIN in hand that belongs
     * to another card is dropped unsent; a counter below pristine or unread
     * leaves nothing held.
     */
    private fun pinFor(
        card: AuthenticationCardIdentity?,
        attempts: Int?,
    ): Pin1Submission? {
        val bound = heldFor
        if (bound != null && bound != card) releasePin()
        heldPin?.let { return it }
        val retention = Pin1Retention.of(card, attempts)
        if (retention == null) {
            pinCache.clear()
            return null
        }
        val taken = pinCache.take(retention.card) ?: return null
        if (pinCache.isRejected(taken)) {
            taken.close()
            return null
        }
        heldPin = taken
        heldFor = retention.card
        return taken
    }

    /** Sends the held PIN once; the copies the verifier takes are zeroed here on every path. */
    private suspend fun verifyHeld(held: Pin1Submission): Pin1VerificationResult {
        val candidate = held.copyBytes()
        val submitted = held.copyBytes()
        return try {
            backend.verify(
                Pin1Submission.fromOwnedBytes(submitted),
                Pin1VerificationOutcome(candidate, pinCache, backend::invalidate),
            )
        } finally {
            candidate.fill(0)
            submitted.fill(0)
        }
    }

    /**
     * Whether a PIN whose last answer was lost may go to the card again:
     * only when the card still allows as many attempts as before it left.
     * Fewer means the card tested and refused it; none readable means the
     * holder decides, with the PIN asked again.
     */
    private fun pinMayGoAgain(
        held: Pin1Submission,
        attempts: Int?,
    ): Boolean {
        val before = attemptsBeforeVerify
        if (attempts != null && before != null && attempts == before) return true
        if (attempts != null && before != null && attempts < before) {
            Pin1VerificationOutcome(held.copyBytes(), pinCache, backend::invalidate).use {
                it.report(Pin1VerificationResult.WRONG_PIN)
            }
        }
        releasePin()
        mutableState.value = AuthenticationPreparationState.Credentials(false, true, attempts)
        return false
    }

    /** The card allows no PIN 1 attempt: nothing is sent, custody is cleared, the holder is told. */
    private fun lockedOut() {
        backend.invalidate()
        releasePin()
        fail(Pin1VerificationResult.PIN_LOCKED)
    }

    fun retry() {
        val action = continuation ?: return
        val cancelled = cancellation ?: {}
        cancellation = null
        start(mutablePurpose.value, cancelled, action)
    }

    fun cancel() {
        val preparing =
            mutableState.value == AuthenticationPreparationState.WaitingForCard ||
                mutableState.value == AuthenticationPreparationState.Verifying
        job?.cancel()
        if (preparing) backend.cancel()
        job = null
        releasePin()
        releaseCan()
        continuation = null
        val cancelled = cancellation
        cancellation = null
        cancelled?.invoke()
        mutableState.value = AuthenticationPreparationState.Idle
    }

    private fun complete() {
        releasePin()
        releaseCan()
        mutableState.value = AuthenticationPreparationState.Ready
        val action = continuation
        continuation = null
        cancellation = null
        action?.invoke()
    }

    /** The card's answer about the PIN ends the hold; a card not reached keeps it for the retry. */
    private fun fail(result: Pin1VerificationResult) {
        if (result in PIN_ANSWERS) releasePin()
        mutableState.value = AuthenticationPreparationState.Failed(result)
    }

    private fun releasePin() {
        heldPin?.close()
        heldPin = null
        heldFor = null
        attemptsBeforeVerify = null
        answerLost = false
    }

    private fun releaseCan() {
        heldCan?.close()
        heldCan = null
    }

    private companion object {
        const val PREPARATION_TIMEOUT_MS = 60_000L

        /** Breath between a lost card and the next wait, so a busy reader is not asked in a tight loop. */
        const val REARM_PAUSE_MS = 250L
        val PIN_ANSWERS =
            setOf(
                Pin1VerificationResult.INVALID_PIN,
                Pin1VerificationResult.WRONG_PIN,
                Pin1VerificationResult.PIN_LOCKED,
                Pin1VerificationResult.SAFETY_REFUSED,
                Pin1VerificationResult.VERIFICATION_REJECTED,
            )
    }
}
