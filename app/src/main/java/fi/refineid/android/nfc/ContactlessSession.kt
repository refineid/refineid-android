@file:Suppress("TooManyFunctions")

package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.HeldPin1Channel
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardManagement
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.core.NativeContactlessSession
import fi.refineid.android.core.NativePin2PreflightFailure
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningInputMode
import fi.refineid.android.core.attemptsLeft
import fi.refineid.android.core.verifyPin1OnHeldChannel
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException

/**
 * One holder-opened contactless card session, confined to the probe
 * worker thread. The session retains the tag handle, the CAN for its
 * lifetime only, and the cached public material.
 *
 * When [heldSession] is set, a PACE secure-messaging session opened at
 * connect is live on the still-connected field: authentication signing
 * reuses that channel with no second handshake, and the field is held
 * across operations. If the field drops and the stack re-polls the card
 * ([adopt]), the held session is dropped and signing falls back to the
 * resting-tag path that reconnects ISO-DEP and re-runs PACE per operation.
 * Qualified (PIN2) operations always take that per-operation path.
 */
internal class ContactlessSession(
    private var isoDep: IsoDep,
    private val can: ByteArray,
    private val material: NativeCardSessionMaterial,
    private var heldSession: Boolean = false,
) : ContactlessCardSession {
    private val ownerThread = Thread.currentThread()
    private var isClosed = false

    /**
     * Replace the tag handle after the stack re-polled the resting
     * card; the previous handle is dead once the field cycled.
     */
    override fun adopt(freshIsoDep: IsoDep) {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The replaced handle is expected to be gone already.
        } catch (_: SecurityException) {
            // The replaced handle is out of date.
        } catch (_: IllegalStateException) {
            // Tag service unavailable.
        }
        // The field cycled, so the card dropped its half of the secure
        // channel; the next operation must re-run PACE on the fresh handle.
        releaseHeldSession()
        isoDep = freshIsoDep
    }

    /**
     * PIN 1 attempts the card allows: the count the last open of the channel
     * read, or the try limit once the card accepted PIN 1 since; null when
     * the card did not say, when the session is closed, or when another PIN
     * command has left on this channel since, so the count is not known.
     */
    override fun pin1AttemptsLeft(): Int? {
        checkOwnerThread()
        if (isClosed) return null
        return material.cachedPin1Preflight()?.state?.attemptsLeft()
    }

    override fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        return material.copyAuthenticationCertificate()
    }

    /**
     * Verifies PIN1 on the held secure channel, reopening it when the field
     * dropped. [isCurrent] gates the credential command after any handshake.
     */
    override fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        isCurrent: () -> Boolean,
    ): fi.refineid.android.core.Pin1Verification {
        checkOwnerThread()
        if (isClosed) {
            pin1.close()
            return fi.refineid.android.core.Pin1Verification(
                fi.refineid.android.core.Pin1VerificationResult.CARD_UNAVAILABLE,
            )
        }
        return verifyPin1OnHeldChannel(pin1Channel, pin1, isCurrent)
    }

    private val pin1Channel =
        object : HeldPin1Channel {
            override val isLive: Boolean get() = heldSession && tagReachable { isoDep.isConnected }

            override fun releaseHeld() = releaseHeldSession()

            override fun reopen(): fi.refineid.android.core.Pin1VerificationResult? {
                if (!reconnect()) return fi.refineid.android.core.Pin1VerificationResult.CARD_UNAVAILABLE
                return when (
                    val opened =
                        NativeContactlessSession.connect(
                            can.copyOf(),
                            NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
                        )
                ) {
                    is fi.refineid.android.core.NativeContactlessOpenResult.Success -> {
                        opened.certificate.close()
                        material.cachePin1Preflight(opened.preflight)
                        heldSession = true
                        null
                    }

                    is fi.refineid.android.core.NativeContactlessOpenResult.ActivationRequired -> {
                        // The native open retains this channel; nothing here will use it.
                        NativeContactlessSession.close()
                        closeIsoDep()
                        fi.refineid.android.core.Pin1VerificationResult.SAFETY_REFUSED
                    }

                    is fi.refineid.android.core.NativeContactlessOpenResult.Failure -> {
                        // A bridge fault can follow a native open that kept its channel.
                        NativeContactlessSession.close()
                        closeIsoDep()
                        fi.refineid.android.core.Pin1VerificationResult.TRANSPORT_ERROR
                    }
                }
            }

            override fun closeField() = closeIsoDep()

            override fun verify(pin1: Pin1Submission): fi.refineid.android.core.Pin1Verification {
                material.pin1CountUnknown()
                val verification =
                    fi.refineid.android.core.NativePin1Verification.verify(
                        pin1 = pin1,
                        exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
                        heldSession = true,
                    )
                if (verification.result == fi.refineid.android.core.Pin1VerificationResult.VERIFIED) {
                    material.pin1Accepted()
                }
                return verification
            }
        }

    /** Clears the held channel's native keys; the shared native slot holds them until then. */
    private fun releaseHeldSession() {
        if (heldSession) {
            NativeContactlessSession.close()
            heldSession = false
        }
    }

    override fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        val certificate = material.requireAuthenticationCertificate()
        if (certificate.keyProfile != algorithm.keyProfile) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }
        val nativeResult =
            if (heldSession && tagReachable { isoDep.isConnected }) {
                // The PACE channel opened at connect is still live on the held
                // field: VERIFY and sign on it with no second handshake, and
                // leave the field up for any further operation.
                material.pin1CountUnknown()
                val result =
                    NativeContactlessSession.authenticateAndSignOnSession(
                        algorithm = algorithm,
                        inputMode = inputMode,
                        pin1 = pin1,
                        input = input,
                        exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
                    )
                if (result is NativeAuthenticationSignResult.Failure) {
                    // The native sign keeps the advanced channel even when it fails.
                    releaseHeldSession()
                    closeIsoDep()
                } else {
                    // A signature proves the card accepted the VERIFY that preceded it.
                    material.pin1Accepted()
                }
                result
            } else {
                // The field dropped and was re-polled: re-run PACE on the
                // resting tag for this one operation, then drop it again.
                if (!reconnect()) {
                    pin1.close()
                    AppTrace.nfcSessionOpenFailed()
                    return AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.CARD_UNAVAILABLE,
                    )
                }
                material.pin1CountUnknown()
                val result =
                    NativeContactlessCore.authenticateAndSign(
                        canCopy = can.copyOf(),
                        algorithm = algorithm,
                        inputMode = inputMode,
                        pin1 = pin1,
                        input = input,
                        exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
                    )
                closeIsoDep()
                if (result !is NativeAuthenticationSignResult.Failure) {
                    // A signature proves the card accepted the VERIFY that preceded it.
                    material.pin1Accepted()
                }
                result
            }
        return verifiedAuthenticationResult(certificate, inputMode, input, nativeResult)
    }

    /**
     * Read EF.4332 under a fresh PACE handshake. The one-shot channel
     * needs no auth-context restore: the next operation opens its own.
     */
    override fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate> {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        if (!reconnect()) {
            return NativeCertificateReadResult.Failure(
                NativeCertificateReadFailure.CARD_UNAVAILABLE,
            )
        }
        val result =
            NativeContactlessCore.readQualifiedCertificate(
                canCopy = can.copyOf(),
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun probePin2Status(): NativePin2PreflightResult {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        if (!reconnect()) {
            return NativePin2PreflightResult.Failure(
                NativePin2PreflightFailure.CARD_UNAVAILABLE,
            )
        }
        val result =
            NativeContactlessCore.probePin2(
                canCopy = can.copyOf(),
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun qualifiedSignInput(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        if (expectedCertificate.keyProfile != algorithm.keyProfile) {
            pin2.close()
            return QualifiedSignResult.Failure(QualifiedSignFailure.KEY_PROFILE_MISMATCH)
        }
        if (!reconnect()) {
            pin2.close()
            return QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)
        }
        val nativeResult =
            NativeContactlessCore.qualifiedSignInput(
                canCopy = can.copyOf(),
                algorithm = algorithm,
                inputMode = inputMode,
                pin2 = pin2,
                input = input,
                expectedCertificate = expectedCertificate,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return verifiedQualifiedResult(expectedCertificate, inputMode, input, nativeResult)
    }

    /** Ensure the resting tag is connected before one card operation. */
    private fun reconnect(): Boolean =
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            }
            true
        } catch (_: IOException) {
            AppTrace.nfcSessionOpenFailed()
            false
        } catch (_: SecurityException) {
            AppTrace.nfcSessionOpenFailed()
            false
        } catch (_: IllegalStateException) {
            AppTrace.nfcSessionOpenFailed()
            false
        }

    private fun closeIsoDep() {
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The tag may already be gone; the operation result stands.
        } catch (_: SecurityException) {
            // The tag handle is out of date.
        } catch (_: IllegalStateException) {
            // Tag service unavailable.
        }
        AppTrace.nfcSessionClosed()
    }

    /** The credential health, with the card's PIN and PUK lengths when [readPinLengths] asks for them. */
    override fun probeCredentialHealth(readPinLengths: Boolean): CardManagementResult<CredentialHealth> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessProbeCredentialHealth(
                can = can.copyOf(),
                readPinLengths = readPinLengths,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            currentPin.fill(0)
            newPin.fill(0)
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessChangePin1(
                can = can.copyOf(),
                currentPin = currentPin,
                newPin = newPin,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            currentPin.fill(0)
            newPin.fill(0)
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessChangePin2(
                can = can.copyOf(),
                currentPin = currentPin,
                newPin = newPin,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            puk.fill(0)
            newPin.fill(0)
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessUnblockPin1(
                can = can.copyOf(),
                puk = puk,
                newPin = newPin,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            puk.fill(0)
            newPin.fill(0)
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessUnblockPin2(
                can = can.copyOf(),
                puk = puk,
                newPin = newPin,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
    ): CardManagementResult<ActivationReport> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            code.fill(0)
            newPin1?.fill(0)
            newPin2?.fill(0)
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessActivateCard(
                can = can.copyOf(),
                scheme = scheme,
                code = code,
                newPin1 = newPin1,
                newPin2 = newPin2,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    override fun close() {
        checkOwnerThread()
        if (isClosed) {
            return
        }
        isClosed = true
        can.fill(0)
        material.close()
        releaseHeldSession()
        try {
            isoDep.close()
        } catch (_: IOException) {
            // Closing a lost tag is a no-op.
        } catch (_: SecurityException) {
            // Tag handle out of date.
        } catch (_: IllegalStateException) {
            // Tag service unavailable.
        }
    }

    override fun toString(): String = "ContactlessSession(closed=" + isClosed + ")"

    private fun checkOwnerThread() {
        check(Thread.currentThread() === ownerThread) {
            "contactless session used from a different thread"
        }
    }

    private companion object {
        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 15_000
    }
}
