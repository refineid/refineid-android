package fi.refineid.android.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
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

internal interface AuthenticationPreparationBackend {
    fun readiness(): AuthenticationReadiness

    suspend fun connect(can: CanSubmission?): Boolean

    suspend fun verify(pin1: Pin1Submission): Pin1VerificationResult

    suspend fun retainVerified(pin: ByteArray): Boolean

    fun invalidate()

    fun cancel() = Unit
}

internal sealed interface AuthenticationPreparationState {
    data object Idle : AuthenticationPreparationState

    data class Credentials(
        val needsCan: Boolean,
        val needsPin: Boolean,
    ) : AuthenticationPreparationState

    data object WaitingForCard : AuthenticationPreparationState

    data object Verifying : AuthenticationPreparationState

    data object Ready : AuthenticationPreparationState

    data class Failed(
        val result: Pin1VerificationResult,
    ) : AuthenticationPreparationState
}

/** Owns preparation and continuation; no Android types or credentials in published state. */
internal class AuthenticationPreparation(
    private val scope: CoroutineScope,
    private val backend: AuthenticationPreparationBackend,
    private val pinCache: AuthenticationPinCache,
) {
    private val mutableState = MutableStateFlow<AuthenticationPreparationState>(AuthenticationPreparationState.Idle)
    val state: StateFlow<AuthenticationPreparationState> = mutableState.asStateFlow()
    private var job: Job? = null
    private var continuation: (() -> Unit)? = null

    fun start(onReady: () -> Unit) {
        if (job?.isActive == true) return
        continuation = onReady
        val ready = backend.readiness()
        when {
            !ready.available -> {
                fail(Pin1VerificationResult.CARD_UNAVAILABLE)
            }

            ready.hasCertificate && pinCache.hasPin -> {
                complete()
            }

            ready.needsCan || !pinCache.hasPin -> {
                mutableState.value = AuthenticationPreparationState.Credentials(ready.needsCan, !pinCache.hasPin)
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
        job =
            scope.launch {
                val candidate = pin1 ?: pinCache.take()
                var copy: ByteArray? = null
                try {
                    if (candidate == null) {
                        fail(Pin1VerificationResult.INVALID_PIN)
                        return@launch
                    }
                    if (pinCache.isRejected(candidate)) {
                        backend.invalidate()
                        fail(Pin1VerificationResult.WRONG_PIN)
                        return@launch
                    }
                    copy = candidate.copyBytes()
                    withTimeout(PREPARATION_TIMEOUT_MS) {
                        mutableState.value = AuthenticationPreparationState.WaitingForCard
                        if (!backend.connect(can)) {
                            fail(Pin1VerificationResult.CARD_UNAVAILABLE)
                            return@withTimeout
                        }
                        mutableState.value = AuthenticationPreparationState.Verifying
                        val result = backend.verify(candidate)
                        coroutineContext.ensureActive()
                        when (result) {
                            Pin1VerificationResult.VERIFIED -> {
                                val owned = checkNotNull(copy)
                                if (backend.retainVerified(
                                        owned,
                                    )
                                ) {
                                    complete()
                                } else {
                                    fail(Pin1VerificationResult.CARD_UNAVAILABLE)
                                }
                            }

                            Pin1VerificationResult.WRONG_PIN, Pin1VerificationResult.PIN_LOCKED -> {
                                pinCache.recordRejected(checkNotNull(copy))
                                copy = null
                                backend.invalidate()
                                fail(result)
                            }

                            else -> {
                                fail(result)
                            }
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
                } finally {
                    copy?.fill(0)
                    candidate?.close()
                    can?.close()
                }
            }
    }

    fun retry() {
        val action = continuation ?: return
        start(action)
    }

    fun cancel() {
        job?.cancel()
        backend.cancel()
        job = null
        continuation = null
        mutableState.value = AuthenticationPreparationState.Idle
    }

    private fun complete() {
        mutableState.value = AuthenticationPreparationState.Ready
        val action = continuation
        continuation = null
        action?.invoke()
    }

    private fun fail(result: Pin1VerificationResult) {
        mutableState.value = AuthenticationPreparationState.Failed(result)
    }

    private companion object {
        const val PREPARATION_TIMEOUT_MS = 60_000L
    }
}
