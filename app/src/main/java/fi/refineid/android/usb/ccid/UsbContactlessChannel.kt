package fi.refineid.android.usb.ccid

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.NativeAuthenticationSignFailure
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativePin1Preflight
import fi.refineid.android.core.NativePin2PreflightFailure
import fi.refineid.android.core.NativeQualifiedSignFailure
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1VerificationResult

/**
 * Native secure-channel primitives driven by [UsbContactlessChannel].
 *
 * Production uses [NativeContactlessSession]; unit tests supply a fake so the
 * held-channel teardown and reopen lifecycle is verified without JNI.
 */
internal interface UsbContactlessOps {
    fun connect(canCopy: ByteArray): NativeContactlessOpenResult

    fun authenticateAndSignOnSession(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): NativeAuthenticationSignResult

    fun closeHeldSession()
}

/**
 * Holds the contactless PACE state of one [CcidUsbSession].
 *
 * A card opened via [open] stays contactless for the rest of the session even
 * after a failed authentication signature tears down the held secure-messaging
 * channel. The retained CAN copy is zeroized on [close] and lets the next
 * operation reopen a fresh PACE channel instead of reusing an uncertain channel
 * or falling back to plain contact APDUs.
 */
internal class UsbContactlessChannel(
    private val ops: UsbContactlessOps,
) {
    private var can: ByteArray? = null
    private var heldSessionActive = false

    val isContactless: Boolean
        get() = can != null

    val hasHeldSession: Boolean
        get() = heldSessionActive

    fun open(canBytes: ByteArray): NativeContactlessOpenResult {
        val candidateCan = canBytes.copyOf()
        val result = ops.connect(canBytes)
        when (result) {
            is NativeContactlessOpenResult.Success,
            is NativeContactlessOpenResult.ActivationRequired,
            -> {
                can?.fill(0)
                can = candidateCan
                heldSessionActive = true
            }

            is NativeContactlessOpenResult.Failure -> {
                candidateCan.fill(0)
                can?.fill(0)
                can = null
                ops.closeHeldSession()
                heldSessionActive = false
            }
        }
        return result
    }

    fun releaseHeld() {
        if (heldSessionActive) {
            ops.closeHeldSession()
            heldSessionActive = false
        }
    }

    /**
     * Ensures a live held PACE channel exists on this contactless session,
     * reopening one with the retained CAN when a prior failure tore it down.
     *
     * Returns `null` when a live channel is ready, or the reopen failure kind.
     */
    fun ensureHeldSession(onPreflightRefreshed: (NativePin1Preflight) -> Unit = {}): NativeCertificateReadFailure? {
        if (heldSessionActive) {
            return null
        }
        val savedCan = can ?: return NativeCertificateReadFailure.BRIDGE_ERROR
        return when (val opened = ops.connect(savedCan.copyOf())) {
            is NativeContactlessOpenResult.Success -> {
                opened.certificate.close()
                onPreflightRefreshed(opened.preflight)
                heldSessionActive = true
                null
            }

            is NativeContactlessOpenResult.ActivationRequired -> {
                // Native connect retains the channel; fail closed for post-open callers.
                ops.closeHeldSession()
                heldSessionActive = false
                NativeCertificateReadFailure.ACTIVATION_REQUIRED
            }

            is NativeContactlessOpenResult.Failure -> {
                ops.closeHeldSession()
                heldSessionActive = false
                opened.kind
            }
        }
    }

    /**
     * Runs one authentication signature on the held PACE channel, reopening it
     * first if a prior failure tore it down. Any signing failure releases the
     * held channel (mirroring [fi.refineid.android.nfc.ContactlessSession]) so
     * the next operation starts from a fresh PACE handshake.
     */
    fun authenticateAndSign(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
        onBeforePinCommand: () -> Unit,
        onPin1Accepted: () -> Unit,
        onPreflightRefreshed: (NativePin1Preflight) -> Unit = {},
    ): NativeAuthenticationSignResult {
        ensureHeldSession(onPreflightRefreshed)?.let { failure ->
            pin1.close()
            return NativeAuthenticationSignResult.Failure(failure.toAuthenticationSignFailure())
        }
        onBeforePinCommand()
        val result =
            ops.authenticateAndSignOnSession(
                algorithm = algorithm,
                inputMode = inputMode,
                pin1 = pin1,
                input = input,
            )
        if (result is NativeAuthenticationSignResult.Failure) {
            // The native sign keeps the advanced channel even when it fails.
            releaseHeld()
        } else {
            // A signature proves the card accepted the VERIFY that preceded it.
            onPin1Accepted()
        }
        return result
    }

    fun close() {
        releaseHeld()
        can?.fill(0)
        can = null
    }
}

internal fun NativeCertificateReadFailure.toAuthenticationSignFailure(): NativeAuthenticationSignFailure =
    when (this) {
        NativeCertificateReadFailure.CARD_UNAVAILABLE -> NativeAuthenticationSignFailure.CARD_UNAVAILABLE

        NativeCertificateReadFailure.TRANSPORT_ERROR -> NativeAuthenticationSignFailure.TRANSPORT_ERROR

        NativeCertificateReadFailure.PACE_REJECTED -> NativeAuthenticationSignFailure.PACE_REJECTED

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> NativeAuthenticationSignFailure.SAFETY_REFUSED

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        NativeCertificateReadFailure.ORGANIZATION_CARD,
        -> NativeAuthenticationSignFailure.BRIDGE_ERROR
    }

internal fun NativeCertificateReadFailure.toPin1VerificationResult(): Pin1VerificationResult =
    when (this) {
        NativeCertificateReadFailure.CARD_UNAVAILABLE -> Pin1VerificationResult.CARD_UNAVAILABLE

        NativeCertificateReadFailure.TRANSPORT_ERROR -> Pin1VerificationResult.TRANSPORT_ERROR

        NativeCertificateReadFailure.PACE_REJECTED -> Pin1VerificationResult.PACE_REJECTED

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> Pin1VerificationResult.SAFETY_REFUSED

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        NativeCertificateReadFailure.ORGANIZATION_CARD,
        -> Pin1VerificationResult.BRIDGE_ERROR
    }

internal fun NativeCertificateReadFailure.toPin2PreflightFailure(): NativePin2PreflightFailure =
    when (this) {
        NativeCertificateReadFailure.CARD_UNAVAILABLE -> NativePin2PreflightFailure.CARD_UNAVAILABLE

        NativeCertificateReadFailure.TRANSPORT_ERROR,
        NativeCertificateReadFailure.PACE_REJECTED,
        -> NativePin2PreflightFailure.TRANSPORT_ERROR

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        NativeCertificateReadFailure.ACTIVATION_REQUIRED,
        NativeCertificateReadFailure.ORGANIZATION_CARD,
        -> NativePin2PreflightFailure.BRIDGE_ERROR
    }

internal fun NativeCertificateReadFailure.toQualifiedSignFailure(): NativeQualifiedSignFailure =
    when (this) {
        NativeCertificateReadFailure.CARD_UNAVAILABLE -> NativeQualifiedSignFailure.CARD_UNAVAILABLE

        NativeCertificateReadFailure.TRANSPORT_ERROR,
        NativeCertificateReadFailure.PACE_REJECTED,
        -> NativeQualifiedSignFailure.TRANSPORT_ERROR

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> NativeQualifiedSignFailure.SAFETY_REFUSED

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        NativeCertificateReadFailure.ORGANIZATION_CARD,
        -> NativeQualifiedSignFailure.BRIDGE_ERROR
    }

internal fun NativeCertificateReadFailure.toCardManagementFailure(): CardManagementFailure =
    when (this) {
        NativeCertificateReadFailure.CARD_UNAVAILABLE -> CardManagementFailure.CARD_UNAVAILABLE

        NativeCertificateReadFailure.TRANSPORT_ERROR -> CardManagementFailure.TRANSPORT_ERROR

        NativeCertificateReadFailure.PACE_REJECTED -> CardManagementFailure.PACE_REJECTED

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> CardManagementFailure.SAFETY_REFUSED

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        NativeCertificateReadFailure.ORGANIZATION_CARD,
        -> CardManagementFailure.BRIDGE_ERROR
    }
