package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationSignature
import fi.refineid.android.core.Pin1Submission
import java.security.SignatureException
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock

internal enum class BrowserSignatureStatus {
    IDLE,
    PIN_REQUIRED,
    SIGNING,
    SUCCEEDED,
    WRONG_PIN,
    PIN_LOCKED,
    REFUSED,
    CANCELLED,
    TIMED_OUT,
    INTERRUPTED,
    ERROR,
}

/** One UI-owned PIN request. Late submissions are closed rather than retained. */
internal class BrowserPinRequest {
    private val completion = CompletableFuture<Pin1Submission>()

    fun submit(pin1: Pin1Submission) {
        if (!completion.complete(pin1)) {
            pin1.close()
        }
    }

    fun cancel() {
        completion.cancel(false)
    }

    internal fun await(timeoutMilliseconds: Long): Pin1Submission {
        return completion.get(timeoutMilliseconds, TimeUnit.MILLISECONDS)
    }

    override fun toString(): String = "BrowserPinRequest([redacted])"
}

/** Turns Chromium's synchronous JCA call into a terse PIN prompt plus serialized card use. */
internal class BrowserPinCoordinator(
    private val cardService: AuthenticationCardService,
    private val dispatchToUi: (() -> Unit) -> Unit,
    private val onPromptChanged: (BrowserPinRequest?) -> Unit,
    private val onStatusChanged: (BrowserSignatureStatus) -> Unit,
    private val pinCache: AuthenticationPinCache? = null,
    private val pinEntryTimeoutMilliseconds: Long = DEFAULT_PIN_ENTRY_TIMEOUT_MILLISECONDS,
) : CardSignatureOperation,
    AutoCloseable {
    private val operationLock = ReentrantLock(true)
    private val stateLock = Any()

    @Volatile
    private var isClosed = false
    private var pendingRequest: BrowserPinRequest? = null

    override fun sign(
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
    ): NativeAuthenticationSignature {
        try {
            operationLock.lockInterruptibly()
        } catch (error: InterruptedException) {
            publishStatus(BrowserSignatureStatus.INTERRUPTED)
            Thread.currentThread().interrupt()
            throw SignatureException("card signature was interrupted", error)
        }
        try {
            if (isClosed) {
                throw SignatureException("browser card signer is closed")
            }
            if (!cardService.requiresLocalPin) {
                return signWith(algorithm, message, Pin1Submission.from("0000"))
            }
            val cached = pinCache?.take()
            if (cached != null) {
                return signWith(algorithm, message, cached)
            }
            val request = BrowserPinRequest()
            synchronized(stateLock) {
                check(pendingRequest == null) {
                    "only one browser PIN request may be active"
                }
                pendingRequest = request
            }
            publishPrompt(request)
            val pin1 =
                try {
                    request.await(pinEntryTimeoutMilliseconds)
                } catch (error: TimeoutException) {
                    request.cancel()
                    publishStatus(BrowserSignatureStatus.TIMED_OUT)
                    throw SignatureException("PIN entry timed out", error)
                } catch (error: CancellationException) {
                    publishStatus(BrowserSignatureStatus.CANCELLED)
                    throw SignatureException("PIN entry was cancelled", error)
                } catch (error: InterruptedException) {
                    request.cancel()
                    publishStatus(BrowserSignatureStatus.INTERRUPTED)
                    Thread.currentThread().interrupt()
                    throw SignatureException("PIN entry was interrupted", error)
                } finally {
                    clearPrompt(request)
                }
            // A value the card already rejected this process is refused
            // locally rather than offered again to burn another retry.
            if (pinCache?.isRejected(pin1) == true) {
                pin1.close()
                publishStatus(BrowserSignatureStatus.WRONG_PIN)
                throw SignatureException("PIN1 was already rejected this session")
            }
            return signWith(algorithm, message, pin1)
        } finally {
            operationLock.unlock()
        }
    }

    private fun signWith(
        algorithm: AuthenticationSigningAlgorithm,
        message: ByteArray,
        pin1: Pin1Submission,
    ): NativeAuthenticationSignature {
        // Copy for the cache decision before the card call consumes the PIN.
        val pinCopy = pin1.copyBytes()
        publishStatus(BrowserSignatureStatus.SIGNING)
        return when (
            val result =
                cardService.signAuthenticationMessage(
                    algorithm = algorithm,
                    pin1 = pin1,
                    message = message,
                )
        ) {
            is AuthenticationSignResult.Success -> {
                retainOutcome(pinCopy, PinOutcome.VERIFIED)
                publishStatus(BrowserSignatureStatus.SUCCEEDED)
                result.signature
            }

            is AuthenticationSignResult.Failure -> {
                if (result.kind == AuthenticationSignFailure.WRONG_PIN ||
                    result.kind == AuthenticationSignFailure.PIN_LOCKED
                ) {
                    pinCache?.clear()
                }
                retainOutcome(
                    pinCopy,
                    if (result.kind == AuthenticationSignFailure.WRONG_PIN) {
                        PinOutcome.REJECTED
                    } else {
                        PinOutcome.DISCARD
                    },
                )
                publishStatus(result.kind.toBrowserStatus())
                throw SignatureException("card authentication signature failed")
            }
        }
    }

    private enum class PinOutcome { VERIFIED, REJECTED, DISCARD }

    private fun retainOutcome(
        pinCopy: ByteArray?,
        outcome: PinOutcome,
    ) {
        if (pinCopy == null) {
            return
        }
        val cache = pinCache
        if (cache == null) {
            pinCopy.fill(0)
            return
        }
        when (outcome) {
            PinOutcome.VERIFIED -> cache.recordVerified(pinCopy)
            PinOutcome.REJECTED -> cache.recordRejected(pinCopy)
            PinOutcome.DISCARD -> pinCopy.fill(0)
        }
    }

    override fun close() {
        val request =
            synchronized(stateLock) {
                if (isClosed) {
                    return
                }
                isClosed = true
                pendingRequest.also { pendingRequest = null }
            }
        request?.cancel()
        dispatchToUi {
            onPromptChanged(null)
            onStatusChanged(BrowserSignatureStatus.IDLE)
        }
    }

    private fun publishPrompt(request: BrowserPinRequest) {
        dispatchToUi {
            if (!isClosed) {
                onPromptChanged(request)
                onStatusChanged(BrowserSignatureStatus.PIN_REQUIRED)
            }
        }
    }

    private fun clearPrompt(request: BrowserPinRequest) {
        synchronized(stateLock) {
            if (pendingRequest === request) {
                pendingRequest = null
            }
        }
        dispatchToUi {
            onPromptChanged(null)
        }
    }

    private fun publishStatus(status: BrowserSignatureStatus) {
        dispatchToUi {
            if (!isClosed) {
                onStatusChanged(status)
            }
        }
    }

    private fun AuthenticationSignFailure.toBrowserStatus(): BrowserSignatureStatus =
        when (this) {
            AuthenticationSignFailure.WRONG_PIN -> BrowserSignatureStatus.WRONG_PIN

            AuthenticationSignFailure.PIN_LOCKED -> BrowserSignatureStatus.PIN_LOCKED

            AuthenticationSignFailure.SAFETY_REFUSED -> BrowserSignatureStatus.REFUSED

            AuthenticationSignFailure.CARD_UNAVAILABLE,
            AuthenticationSignFailure.TRANSPORT_ERROR,
            AuthenticationSignFailure.INVALID_PIN,
            AuthenticationSignFailure.VERIFICATION_REJECTED,
            AuthenticationSignFailure.SIGNING_REJECTED,
            AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
            AuthenticationSignFailure.BRIDGE_ERROR,
            -> BrowserSignatureStatus.ERROR
        }

    private companion object {
        const val MILLISECONDS_PER_SECOND = 1_000L
        const val DEFAULT_PIN_ENTRY_TIMEOUT_SECONDS = 120L
        const val DEFAULT_PIN_ENTRY_TIMEOUT_MILLISECONDS =
            DEFAULT_PIN_ENTRY_TIMEOUT_SECONDS * MILLISECONDS_PER_SECOND
    }
}
