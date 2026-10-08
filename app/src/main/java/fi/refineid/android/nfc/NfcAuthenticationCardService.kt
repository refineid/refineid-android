package fi.refineid.android.nfc

import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.usb.awaitPreservingInterrupt
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/**
 * The browser-facing card service over one holder-opened contactless
 * session. Certificate copies and signatures run on the session's
 * worker thread; a lost card is reported back to the controller so the
 * published snapshot returns to waiting.
 */
internal class NfcAuthenticationCardService(
    private val probeExecutor: ExecutorService,
    private val mainHandler: Handler,
    private val isReady: () -> Boolean,
    private val currentGeneration: () -> Int,
    private val activeSession: () -> ContactlessSession?,
    private val onCardLost: (Int) -> Unit,
    private val cachedCertificate: () -> NativeAuthenticationCertificate? = { null },
    private val awaitReady: suspend () -> Boolean = { false },
) : AuthenticationCardService {
    /** Copies the public leaf while preserving session thread confinement. */
    override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
        val generation = currentGeneration()
        try {
            probeExecutor.execute {
                val certificate =
                    if (generation == currentGeneration()) {
                        try {
                            activeSession()?.copyAuthenticationCertificate() ?: cachedCertificate()
                        } catch (_: IllegalStateException) {
                            null
                        }
                    } else {
                        null
                    }
                mainHandler.post {
                    if (generation == currentGeneration()) {
                        onResult(certificate)
                    } else {
                        certificate?.close()
                        onResult(null)
                    }
                }
            }
        } catch (_: RejectedExecutionException) {
            onResult(null)
        }
    }

    override fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        expectedGeneration: Int?,
    ): fi.refineid.android.core.Pin1VerificationResult {
        if (Looper.myLooper() == Looper.getMainLooper() ||
            (expectedGeneration == null && !isReady() && !kotlinx.coroutines.runBlocking { awaitReady() })
        ) {
            pin1.close()
            return fi.refineid.android.core.Pin1VerificationResult.CARD_UNAVAILABLE
        }
        val generation = expectedGeneration ?: currentGeneration()
        val isCurrent = { generation == currentGeneration() && isReady() }
        return fi.refineid.android.core.verifyQueuedPin1(
            pin1,
            probeExecutor,
            { isReady() },
            { currentGeneration() },
            generation,
        ) { submission ->
            val result = activeSession()?.verifyAuthenticationPin(submission, isCurrent)
            val isLost =
                result == null || result == fi.refineid.android.core.Pin1VerificationResult.CARD_UNAVAILABLE ||
                    result == fi.refineid.android.core.Pin1VerificationResult.TRANSPORT_ERROR ||
                    result == fi.refineid.android.core.Pin1VerificationResult.BRIDGE_ERROR
            // Superseded work leaves the session to whoever superseded it.
            if (isLost && generation == currentGeneration()) {
                onCardLost(generation)
            }
            result
        }
    }

    /** Blocks a browser crypto worker while one card operation runs on the NFC owner thread. */
    override fun signAuthenticationMessage(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult =
        signAuthenticationInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
        )

    override fun signAuthenticationDigest(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult =
        signAuthenticationInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
        )

    private fun signAuthenticationInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        if (!isReady() && !kotlinx.coroutines.runBlocking { awaitReady() }) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        val generation = currentGeneration()
        val completion = CompletableFuture<AuthenticationSignResult>()
        try {
            probeExecutor.execute {
                val result =
                    try {
                        val session = activeSession()
                        if (session == null || generation != currentGeneration()) {
                            pin1.close()
                            AuthenticationSignResult.Failure(
                                AuthenticationSignFailure.CARD_UNAVAILABLE,
                            )
                        } else {
                            session.authenticateAndSignInput(
                                algorithm = algorithm,
                                inputMode = inputMode,
                                pin1 = pin1,
                                input = input,
                            )
                        }
                    } catch (_: RuntimeException) {
                        pin1.close()
                        AuthenticationSignResult.Failure(AuthenticationSignFailure.BRIDGE_ERROR)
                    }
                val isCardLost =
                    result is AuthenticationSignResult.Failure &&
                        when (result.kind) {
                            AuthenticationSignFailure.WRONG_PIN,
                            AuthenticationSignFailure.PIN_LOCKED,
                            AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                            AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
                            -> false

                            else -> true
                        }
                if (isCardLost) {
                    onCardLost(generation)
                }
                completion.complete(result)
            }
        } catch (_: RejectedExecutionException) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        return completion.awaitPreservingInterrupt()
    }
}
