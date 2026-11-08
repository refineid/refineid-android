// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSignatureVerifier
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignFailure
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignFailure
import fi.refineid.android.core.NativeQualifiedSignResult
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSignatureVerifier
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningInputMode
import fi.refineid.android.diagnostics.AppTrace

/**
 * One holder-opened contactless card session, confined to the NFC worker
 * thread: a citizen card's channel opened by its access number
 * ([ContactlessSession]), or an organization card's, where each operation
 * opens its own with the credential it spends
 * ([OrganizationContactlessSession]).
 */
@Suppress("TooManyFunctions")
internal interface ContactlessCardSession : AutoCloseable {
    /** Replace the tag handle after the stack re-polled the resting card. */
    fun adopt(freshIsoDep: IsoDep)

    /** PIN 1 attempts the card allows, read without a VERIFY; null when not known. */
    fun pin1AttemptsLeft(): Int?

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate

    fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        isCurrent: () -> Boolean,
    ): Pin1Verification

    fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult

    fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate>

    fun probePin2Status(): NativePin2PreflightResult

    fun qualifiedSignInput(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult

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

    fun probeCredentialHealth(readPinLengths: Boolean): CardManagementResult<CredentialHealth>

    fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome>

    fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
    ): CardManagementResult<ActivationReport>

    override fun close()
}

/** The card's authentication signature, checked against its certificate before it is returned. */
internal fun verifiedAuthenticationResult(
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
                AuthenticationSignResult.Failure(AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED)
            }
        }

        is NativeAuthenticationSignResult.Failure -> {
            AuthenticationSignResult.Failure(
                nativeResult.kind.toContactlessFailure(),
                nativeResult.remainingRetries,
            )
        }
    }

/** The card's qualified signature, checked against its certificate before it is returned. */
internal fun verifiedQualifiedResult(
    expectedCertificate: NativeQualifiedCertificate,
    inputMode: QualifiedSigningInputMode,
    input: ByteArray,
    nativeResult: NativeQualifiedSignResult,
): QualifiedSignResult =
    when (nativeResult) {
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
            QualifiedSignResult.Failure(
                nativeResult.kind.toContactlessQualifiedFailure(),
                nativeResult.remainingRetries,
            )
        }
    }

private fun NativeAuthenticationSignFailure.toContactlessFailure(): AuthenticationSignFailure =
    when (this) {
        NativeAuthenticationSignFailure.CARD_UNAVAILABLE -> AuthenticationSignFailure.CARD_UNAVAILABLE

        NativeAuthenticationSignFailure.TRANSPORT_ERROR -> AuthenticationSignFailure.TRANSPORT_ERROR

        NativeAuthenticationSignFailure.INVALID_PIN -> AuthenticationSignFailure.INVALID_PIN

        NativeAuthenticationSignFailure.SAFETY_REFUSED -> AuthenticationSignFailure.SAFETY_REFUSED

        NativeAuthenticationSignFailure.PIN_LOCKED -> AuthenticationSignFailure.PIN_LOCKED

        NativeAuthenticationSignFailure.WRONG_PIN -> AuthenticationSignFailure.WRONG_PIN

        NativeAuthenticationSignFailure.VERIFICATION_REJECTED -> AuthenticationSignFailure.VERIFICATION_REJECTED

        NativeAuthenticationSignFailure.SIGNING_REJECTED -> AuthenticationSignFailure.SIGNING_REJECTED

        // The channel's password was proven at connect, or the card in the
        // field changed; either way a later refusal is no holder-facing fault.
        NativeAuthenticationSignFailure.PACE_REJECTED -> AuthenticationSignFailure.TRANSPORT_ERROR

        NativeAuthenticationSignFailure.BRIDGE_ERROR -> AuthenticationSignFailure.BRIDGE_ERROR
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
