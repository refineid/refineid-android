@file:Suppress("TooManyFunctions")

package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSignatureVerifier
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignFailure
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
import fi.refineid.android.core.NativeQualifiedSignFailure
import fi.refineid.android.core.NativeQualifiedSignResult
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSignatureVerifier
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningInputMode
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
) : AutoCloseable {
    private val ownerThread = Thread.currentThread()
    private var isClosed = false

    /**
     * Replace the tag handle after the stack re-polled the resting
     * card; the previous handle is dead once the field cycled.
     */
    fun adopt(freshIsoDep: IsoDep) {
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
        if (heldSession) {
            NativeContactlessSession.close()
            heldSession = false
        }
        isoDep = freshIsoDep
    }

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        return material.copyAuthenticationCertificate()
    }

    fun readFacePhoto(): ByteArray? {
        checkOwnerThread()
        check(!isClosed) {
            "contactless session is closed"
        }
        return if (heldSession && isoDep.isConnected) {
            NativeContactlessSession.readFacePhotoOnSession(
                NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        } else if (isoDep.isConnected) {
            NativeContactlessSession.readFacePhotoWithCan(
                can.copyOf(),
                NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        } else {
            null
        }
    }

    fun authenticateAndSignInput(
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
            if (heldSession && isoDep.isConnected) {
                // The PACE channel opened at connect is still live on the held
                // field: VERIFY and sign on it with no second handshake, and
                // leave the field up for any further operation.
                val result =
                    NativeContactlessSession.authenticateAndSignOnSession(
                        algorithm = algorithm,
                        inputMode = inputMode,
                        pin1 = pin1,
                        input = input,
                        exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
                    )
                if (result is NativeAuthenticationSignResult.Failure) {
                    heldSession = false
                    closeIsoDep()
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
                result
            }
        return verifyAndMapSignature(certificate, inputMode, input, nativeResult)
    }

    private fun verifyAndMapSignature(
        certificate: NativeAuthenticationCertificate,
        inputMode: AuthenticationSigningInputMode,
        input: ByteArray,
        nativeResult: NativeAuthenticationSignResult,
    ): AuthenticationSignResult =
        when (nativeResult) {
            is NativeAuthenticationSignResult.Success -> {
                val isVerified =
                    when (inputMode) {
                        AuthenticationSigningInputMode.MESSAGE -> {
                            AuthenticationSignatureVerifier.verify(
                                certificate = certificate,
                                message = input,
                                signature = nativeResult.signature,
                            )
                        }

                        AuthenticationSigningInputMode.PREHASHED -> {
                            AuthenticationSignatureVerifier.verifyPrehashed(
                                certificate = certificate,
                                digest = input,
                                signature = nativeResult.signature,
                            )
                        }
                    }
                AppTrace.authenticationSignatureVerificationCompleted(
                    inputMode = inputMode,
                    isVerified = isVerified,
                )
                if (isVerified) {
                    AuthenticationSignResult.Success(nativeResult.signature)
                } else {
                    nativeResult.signature.close()
                    AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                    )
                }
            }

            is NativeAuthenticationSignResult.Failure -> {
                AuthenticationSignResult.Failure(nativeResult.kind.toContactlessFailure())
            }
        }

    /**
     * Read EF.4332 under a fresh PACE handshake. The one-shot channel
     * needs no auth-context restore: the next operation opens its own.
     */
    fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate> {
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

    fun probePin2Status(): NativePin2PreflightResult {
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

    fun qualifiedSignPrehashed(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        digest: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult =
        qualifiedSignInput(
            algorithm = algorithm,
            inputMode = QualifiedSigningInputMode.PREHASHED,
            pin2 = pin2,
            input = digest,
            expectedCertificate = expectedCertificate,
        )

    fun qualifiedSign(
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        content: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult =
        qualifiedSignInput(
            algorithm = algorithm,
            inputMode = QualifiedSigningInputMode.MESSAGE,
            pin2 = pin2,
            input = content,
            expectedCertificate = expectedCertificate,
        )

    fun qualifiedSignInput(
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
        return when (nativeResult) {
            is NativeQualifiedSignResult.Success -> {
                val isVerified =
                    when (inputMode) {
                        QualifiedSigningInputMode.MESSAGE -> {
                            QualifiedSignatureVerifier.verify(
                                certificate = expectedCertificate,
                                content = input,
                                signature = nativeResult.signature,
                            )
                        }

                        QualifiedSigningInputMode.PREHASHED -> {
                            QualifiedSignatureVerifier.verifyPrehashed(
                                certificate = expectedCertificate,
                                digest = input,
                                signature = nativeResult.signature,
                            )
                        }
                    }
                AppTrace.qualifiedSignatureVerificationCompleted(isVerified)
                if (isVerified) {
                    QualifiedSignResult.Success(nativeResult.signature)
                } else {
                    nativeResult.signature.close()
                    QualifiedSignResult.Failure(QualifiedSignFailure.LOCAL_VERIFICATION_FAILED)
                }
            }

            is NativeQualifiedSignResult.Failure -> {
                QualifiedSignResult.Failure(nativeResult.kind.toContactlessQualifiedFailure())
            }
        }
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

    fun probeCredentialHealth(): CardManagementResult<CredentialHealth> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        }
        val result =
            NativeCardManagement.contactlessProbeCredentialHealth(
                can = can.copyOf(),
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        closeIsoDep()
        return result
    }

    fun changePin1(
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

    fun changePin2(
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

    fun unblockPin1(
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

    fun unblockPin2(
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

    fun activateCard(
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
        if (heldSession) {
            NativeContactlessSession.close()
            heldSession = false
        }
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

private fun NativeAuthenticationSignFailure.toContactlessFailure(): AuthenticationSignFailure =
    when (this) {
        NativeAuthenticationSignFailure.CARD_UNAVAILABLE -> {
            AuthenticationSignFailure.CARD_UNAVAILABLE
        }

        NativeAuthenticationSignFailure.TRANSPORT_ERROR -> {
            AuthenticationSignFailure.TRANSPORT_ERROR
        }

        NativeAuthenticationSignFailure.INVALID_PIN -> {
            AuthenticationSignFailure.INVALID_PIN
        }

        NativeAuthenticationSignFailure.SAFETY_REFUSED -> {
            AuthenticationSignFailure.SAFETY_REFUSED
        }

        NativeAuthenticationSignFailure.PIN_LOCKED -> {
            AuthenticationSignFailure.PIN_LOCKED
        }

        NativeAuthenticationSignFailure.WRONG_PIN -> {
            AuthenticationSignFailure.WRONG_PIN
        }

        NativeAuthenticationSignFailure.VERIFICATION_REJECTED -> {
            AuthenticationSignFailure.VERIFICATION_REJECTED
        }

        NativeAuthenticationSignFailure.SIGNING_REJECTED -> {
            AuthenticationSignFailure.SIGNING_REJECTED
        }

        // The session CAN was proven at connect; a later channel refusal
        // is a transport anomaly, not a holder-facing CAN outcome.
        NativeAuthenticationSignFailure.PACE_REJECTED -> {
            AuthenticationSignFailure.TRANSPORT_ERROR
        }

        NativeAuthenticationSignFailure.BRIDGE_ERROR -> {
            AuthenticationSignFailure.BRIDGE_ERROR
        }
    }

// The contactless qualified path folds a channel refusal to a transport
// anomaly natively, so its coarse vocabulary carries no CAN-facing code.
private fun NativeQualifiedSignFailure.toContactlessQualifiedFailure(): QualifiedSignFailure =
    when (this) {
        NativeQualifiedSignFailure.CARD_UNAVAILABLE -> QualifiedSignFailure.CARD_UNAVAILABLE
        NativeQualifiedSignFailure.TRANSPORT_ERROR -> QualifiedSignFailure.TRANSPORT_ERROR
        NativeQualifiedSignFailure.INVALID_PIN -> QualifiedSignFailure.INVALID_PIN
        NativeQualifiedSignFailure.SAFETY_REFUSED -> QualifiedSignFailure.SAFETY_REFUSED
        NativeQualifiedSignFailure.PIN_LOCKED -> QualifiedSignFailure.PIN_LOCKED
        NativeQualifiedSignFailure.WRONG_PIN -> QualifiedSignFailure.WRONG_PIN
        NativeQualifiedSignFailure.VERIFICATION_REJECTED -> QualifiedSignFailure.VERIFICATION_REJECTED
        NativeQualifiedSignFailure.CERTIFICATE_REJECTED -> QualifiedSignFailure.CERTIFICATE_REJECTED
        NativeQualifiedSignFailure.INVALID_CERTIFICATE -> QualifiedSignFailure.INVALID_CERTIFICATE
        NativeQualifiedSignFailure.CERTIFICATE_MISMATCH -> QualifiedSignFailure.CERTIFICATE_MISMATCH
        NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH -> QualifiedSignFailure.KEY_PROFILE_MISMATCH
        NativeQualifiedSignFailure.SIGNING_REJECTED -> QualifiedSignFailure.SIGNING_REJECTED
        NativeQualifiedSignFailure.BRIDGE_ERROR -> QualifiedSignFailure.BRIDGE_ERROR
    }
