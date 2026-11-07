// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

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
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeOrganizationCard
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.NativePin2PreflightFailure
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningInputMode
import fi.refineid.android.core.attemptsLeft
import fi.refineid.android.core.organizationPin1Refused
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException

/**
 * An organization card on the phone's antenna. The card has no access number
 * and answers nothing but EF.CardAccess until PACE, so no channel is held:
 * each operation connects the tag, runs its own PACE with the credential it
 * spends, and drops the field. The certificates are those PIN 1's channel
 * read at the first open; a card awaiting its first PIN holds none.
 *
 * The native boundary refuses a card that is not an organization card before
 * any password is named, so a substituted citizen card never sees a PIN. A
 * substituted organization card cannot be told apart before PACE; its refusal
 * reaches the holder with the card's count.
 *
 * [onUnlocked] reports that a card not yet read has a PIN 1 the floor serves and
 * no blocked PIN 2 any more, so the controller can read it with PIN 1.
 */
@Suppress("TooManyFunctions")
internal class OrganizationContactlessSession(
    private var isoDep: IsoDep,
    private val authenticationCertificate: NativeAuthenticationCertificate?,
    private val qualifiedCertificate: NativeQualifiedCertificate?,
    private val onUnlocked: () -> Unit = {},
) : ContactlessCardSession {
    private val ownerThread = Thread.currentThread()
    private var isClosed = false

    override fun adopt(freshIsoDep: IsoDep) {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        closeIsoDep()
        isoDep = freshIsoDep
    }

    /** The counter `MSE:Set AT` reports now, read fresh on every call. */
    override fun pin1AttemptsLeft(): Int? {
        checkOwnerThread()
        if (isClosed || !reconnect()) return null
        val result = NativeOrganizationCard.probePin1(exchange())
        return (result as? NativePin1PreflightResult.Success)?.preflight?.state?.attemptsLeft()
    }

    override fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        return checkNotNull(authenticationCertificate) { "no certificate was read from this card" }.copyOwned()
    }

    override fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        isCurrent: () -> Boolean,
    ): Pin1Verification {
        checkOwnerThread()
        if (isClosed || !reconnect() || !isCurrent()) {
            pin1.close()
            return Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
        }
        val verification = NativeOrganizationCard.verifyPin1(pin1, exchange())
        closeIsoDep()
        // A card that is not an organization card was named no PIN; it says
        // nothing about one, and no access number is at stake here.
        return if (verification.result == Pin1VerificationResult.PACE_REJECTED) {
            Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
        } else {
            verification
        }
    }

    override fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        val certificate = authenticationCertificate
        if (certificate == null || certificate.keyProfile != algorithm.keyProfile) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.KEY_PROFILE_MISMATCH)
        }
        if (!reconnect()) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        val nativeResult =
            NativeOrganizationCard.authenticateAndSign(
                algorithm = algorithm,
                inputMode = inputMode,
                pin1 = pin1,
                input = input,
                exchange = exchange(),
            )
        closeIsoDep()
        return verifiedAuthenticationResult(certificate, inputMode, input, nativeResult)
    }

    /** The certificate PIN 1's channel read; no channel opens without a PIN. */
    override fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        val certificate =
            qualifiedCertificate
                ?: return NativeCertificateReadResult.Failure(NativeCertificateReadFailure.REJECTED)
        return NativeCertificateReadResult.Success(certificate.copyOwned())
    }

    override fun probePin2Status(): NativePin2PreflightResult {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) {
            return NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)
        }
        return NativeOrganizationCard.probePin2(exchange())
    }

    override fun qualifiedSignInput(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
    ): QualifiedSignResult {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (expectedCertificate.keyProfile != algorithm.keyProfile) {
            pin2.close()
            return QualifiedSignResult.Failure(QualifiedSignFailure.KEY_PROFILE_MISMATCH)
        }
        if (!reconnect()) {
            pin2.close()
            return QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)
        }
        val nativeResult =
            NativeOrganizationCard.qualifiedSign(
                algorithm = algorithm,
                inputMode = inputMode,
                pin2 = pin2,
                input = input,
                expectedCertificate = expectedCertificate,
                exchange = exchange(),
            )
        closeIsoDep()
        return verifiedQualifiedResult(expectedCertificate, inputMode, input, nativeResult)
    }

    override fun probeCredentialHealth(readPinLengths: Boolean): CardManagementResult<CredentialHealth> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
        val result = NativeOrganizationCard.probeHealth(exchange())
        if (authenticationCertificate == null && result is CardManagementResult.Success) {
            val health = result.value
            val pin1Offered = !organizationPin1Refused(health.pin1State.attemptsLeft())
            if (pin1Offered && health.pin2State !is NativePin2State.Locked) onUnlocked()
        }
        return result
    }

    override fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) return unavailable(currentPin, newPin)
        val result = NativeOrganizationCard.changePin1(currentPin, newPin, exchange())
        closeIsoDep()
        return result
    }

    /**
     * No record-floored PIN 2 change exists for this channel, and the plain one
     * floors on the header-only VERIFY this card does not answer over secure
     * messaging, so nothing is sent. [CredentialHealth.changesPin2] keeps the
     * form from being offered.
     */
    override fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        currentPin.fill(0)
        newPin.fill(0)
        return CardManagementResult.Failure(CardManagementFailure.SAFETY_REFUSED)
    }

    override fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) return unavailable(puk, newPin)
        val result = NativeOrganizationCard.resetPin1(puk, newPin, exchange())
        closeIsoDep()
        return result
    }

    override fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) { "contactless session is closed" }
        if (!reconnect()) return unavailable(puk, newPin)
        val result = NativeOrganizationCard.resetPin2(puk, newPin, exchange())
        closeIsoDep()
        return result
    }

    /**
     * Nothing activates this card but the PUK resets: its health names a blocked
     * PIN, and the reset form sets it.
     */
    override fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
    ): CardManagementResult<ActivationReport> {
        code.fill(0)
        newPin1?.fill(0)
        newPin2?.fill(0)
        return CardManagementResult.Failure(CardManagementFailure.SAFETY_REFUSED)
    }

    override fun close() {
        checkOwnerThread()
        if (isClosed) return
        isClosed = true
        authenticationCertificate?.close()
        qualifiedCertificate?.close()
        closeIsoDep()
    }

    override fun toString(): String = "OrganizationContactlessSession(closed=" + isClosed + ")"

    private fun unavailable(
        first: ByteArray,
        second: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        first.fill(0)
        second.fill(0)
        return CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
    }

    private fun exchange(): NfcNativeBlockExchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep))

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
    }

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
