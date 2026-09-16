package fi.refineid.android.usb.ccid

import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.AtrValidation
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
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCardManagement
import fi.refineid.android.core.NativeCardOperationResult
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeContactlessSession
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.NativePin1PreflightFailure
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedCore
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
import kotlin.concurrent.thread

internal sealed interface CcidSessionOpenResult {
    class Ready(
        val session: CcidUsbSession,
    ) : CcidSessionOpenResult {
        override fun toString(): String = "Ready"
    }

    /**
     * A contactless card was activated but rejects plain access; it holds the
     * open session so PACE can run once the access number arrives.
     */
    class AccessNumberRequired(
        val session: CcidUsbSession,
    ) : CcidSessionOpenResult {
        override fun toString(): String = "AccessNumberRequired"
    }

    class ActivationRequired(
        val session: CcidUsbSession,
    ) : CcidSessionOpenResult {
        override fun toString(): String = "ActivationRequired"
    }

    data object NoCard : CcidSessionOpenResult

    data object CardError : CcidSessionOpenResult

    data object TransportError : CcidSessionOpenResult
}

/** One claimed CCID interface, confined to the worker thread that opened it. */
@Suppress("TooManyFunctions")
internal class CcidUsbSession(
    private val connection: UsbDeviceConnection,
    private val usbInterface: UsbInterface,
    descriptor: CcidFunctionalDescriptor,
    private val exchange: CcidCommandExchange,
    private val sequenceCounter: CcidSequenceCounter,
    private val interruptIn: UsbEndpoint? = null,
) : AutoCloseable {
    private val ownerThread = Thread.currentThread()
    private val exchangeLevel =
        when (descriptor.exchangeLevel) {
            CcidExchangeLevel.TPDU -> NativeCardExchangeLevel.T0_TPDU

            CcidExchangeLevel.SHORT_APDU,
            CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
            -> NativeCardExchangeLevel.APDU
        }
    private val nativeExchange =
        CcidNativeBlockExchange(
            CcidBlockTransport(
                exchange = exchange,
                maximumBlockLength = descriptor.maximumTransferBlockLength,
                sequenceCounter = sequenceCounter,
            ),
        )

    @Volatile
    private var isClosed = false

    @Volatile
    private var cardRemoved = false

    @Volatile
    private var cardRemovalListener: (() -> Unit)? = null

    @Volatile
    private var interruptThread: Thread? = null

    val hasInterruptEndpoint: Boolean
        get() = interruptIn != null

    // True once openContactless has run PACE and a live secure-messaging
    // session is held natively. It routes signing over the retained channel
    // (no second PACE) and asks the native side to drop the session at close.
    private var contactlessSessionActive = false
    private val sessionMaterial = NativeCardSessionMaterial()

    fun startRemovalListener(onCardRemoved: () -> Unit) {
        checkOwnerThread()
        if (isClosed || cardRemoved || interruptIn == null) {
            return
        }
        cardRemovalListener = onCardRemoved
        if (interruptThread != null) {
            return
        }
        val thread =
            thread(
                name = "refineid-ccid-interrupt",
                isDaemon = true,
            ) {
                val maxPacketSize = interruptIn.maxPacketSize.coerceAtLeast(8)
                val buffer = ByteArray(maxPacketSize)
                while (!isClosed && !cardRemoved && !Thread.currentThread().isInterrupted) {
                    val bytesRead =
                        try {
                            connection.bulkTransfer(
                                interruptIn,
                                buffer,
                                0,
                                buffer.size,
                                INTERRUPT_POLL_TIMEOUT_MILLISECONDS,
                            )
                        } catch (_: Exception) {
                            -1
                        }
                    if (!isClosed && !cardRemoved) {
                        handleInterruptBuffer(buffer, bytesRead)
                    }
                }
            }
        interruptThread = thread
    }

    private fun handleInterruptBuffer(
        buffer: ByteArray,
        bytesRead: Int,
    ) {
        if (bytesRead < 2) {
            return
        }
        val messageType = buffer[0].toInt() and 0xFF
        val isRemoval =
            when (messageType) {
                CcidWire.RDR_TO_PC_NOTIFY_SLOT_CHANGE -> {
                    val slotIccState = buffer[1].toInt() and 0xFF
                    (slotIccState and 0x01) == 0
                }

                CcidWire.RDR_TO_PC_HARDWARE_ERROR -> {
                    true
                }

                else -> {
                    false
                }
            }
        if (isRemoval) {
            cardRemoved = true
            AppTrace.ccidCardRemovalDetected()
            cardRemovalListener?.invoke()
        }
    }

    fun selectPkcs15Application(): NativeCardOperationResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCore.selectPkcs15Application(
            exchangeLevel = exchangeLevel,
            exchange = nativeExchange,
        )
    }

    /**
     * PACE with the access number over the CCID channel, then the PKCS#15
     * select, certificate read, and PIN1 preflight inside secure messaging -
     * the contactless open a card on the reader's PICC antenna requires, run
     * over USB exactly as the NFC path runs it over ISO-DEP.
     *
     * The reader holds the RF field for the session's whole lifetime, so on
     * success the live secure-messaging session is retained natively: signing
     * reuses this channel and never runs PACE a second time.
     */
    fun openContactless(canBytes: ByteArray): NativeContactlessOpenResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result = NativeContactlessSession.connect(canBytes, nativeExchange)
        if (result is NativeContactlessOpenResult.Success) {
            contactlessSessionActive = true
            sessionMaterial.cacheAuthenticationCertificate(result.certificate)
            sessionMaterial.cachePin1Preflight(result.preflight)
        } else if (result is NativeContactlessOpenResult.ActivationRequired) {
            contactlessSessionActive = true
            sessionMaterial.cacheAuthenticationCertificate(result.certificate)
        }
        return result
    }

    /**
     * Face photo over the secure-messaging channel a prior
     * [openContactless] left open, without a second PACE handshake; null
     * when no contactless session is held.
     */
    fun readFacePhoto(): ByteArray? {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return if (contactlessSessionActive) {
            NativeContactlessSession.readFacePhotoOnSession(nativeExchange)
        } else {
            null
        }
    }

    fun cacheAuthenticationCertificate(): NativeCertificateReadResult<NativeAuthenticationCertificate> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result =
            NativeCore.readAuthenticationCertificate(
                exchangeLevel = exchangeLevel,
                exchange = nativeExchange,
            )
        if (result is NativeCertificateReadResult.Success) {
            sessionMaterial.cacheAuthenticationCertificate(result.certificate)
        }
        return result
    }

    /** Reads EF.4332, then restores the PKCS#15 authentication context. */
    fun readQualifiedCertificate(): NativeCertificateReadResult<NativeQualifiedCertificate> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result =
            NativeQualifiedCore.readQualifiedCertificate(
                exchangeLevel = exchangeLevel,
                exchange = nativeExchange,
            )
        if (!result.allowsContextRestore()) {
            return result
        }
        return when (selectPkcs15Application()) {
            NativeCardOperationResult.SUCCEEDED -> {
                result
            }

            NativeCardOperationResult.CARD_UNAVAILABLE -> {
                result.closeCertificate()
                NativeCertificateReadResult.Failure(
                    NativeCertificateReadFailure.CARD_UNAVAILABLE,
                )
            }

            NativeCardOperationResult.REJECTED -> {
                result.closeCertificate()
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.REJECTED)
            }

            NativeCardOperationResult.TRANSPORT_ERROR -> {
                result.closeCertificate()
                NativeCertificateReadResult.Failure(
                    NativeCertificateReadFailure.TRANSPORT_ERROR,
                )
            }

            NativeCardOperationResult.BRIDGE_ERROR -> {
                result.closeCertificate()
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
            }
        }
    }

    fun cachePin1Preflight(): NativePin1PreflightResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val result =
            NativeCore.probePin1Status(
                exchangeLevel = exchangeLevel,
                exchange = nativeExchange,
            )
        if (result is NativePin1PreflightResult.Success) {
            sessionMaterial.cachePin1Preflight(result.preflight)
        }
        return result
    }

    fun probePin2Status(): NativePin2PreflightResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeQualifiedCore.probePin2Status(
            exchangeLevel = exchangeLevel,
            exchange = nativeExchange,
        )
    }

    fun isCardPresent(): Boolean {
        checkOwnerThread()
        if (isClosed || cardRemoved) {
            return false
        }
        val command =
            CcidCommand.getSlotStatus(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
            )
        return try {
            when (val result = exchange.exchange(command)) {
                is CcidExchangeResult.Failure -> {
                    AppTrace.ccidSlotExchangeFailed(result.kind)
                    false
                }

                is CcidExchangeResult.Response -> {
                    when (val response = result.value) {
                        is CcidSlotStatus -> {
                            if (response.cardStatus == CcidCardStatus.NOT_PRESENT) {
                                AppTrace.ccidCardState(response.cardStatus)
                            }
                            response.cardStatus != CcidCardStatus.NOT_PRESENT
                        }

                        is CcidCommandFailure -> {
                            AppTrace.ccidCommandFailed(response.errorCode, response.cardStatus)
                            response.cardStatus != CcidCardStatus.NOT_PRESENT
                        }

                        is CcidTimeExtension -> {
                            false
                        }

                        is CcidDataBlock -> {
                            response.close()
                            false
                        }

                        is CcidParameters -> {
                            response.close()
                            false
                        }
                    }
                }
            }
        } finally {
            command.close()
        }
    }

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return sessionMaterial.copyAuthenticationCertificate()
    }

    fun authenticateAndSign(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult =
        authenticateAndSignInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
        )

    fun authenticateAndSignPrehashed(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult =
        authenticateAndSignInput(
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
        )

    private fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val certificate = sessionMaterial.requireAuthenticationCertificate()
        if (certificate.keyProfile != algorithm.keyProfile) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }

        return when (
            val result =
                if (contactlessSessionActive) {
                    // The PICC card requires secure messaging; the session was
                    // already proven under PACE at connect, so signing rebuilds
                    // that channel and skips the handshake.
                    NativeContactlessSession.authenticateAndSignOnSession(
                        algorithm = algorithm,
                        inputMode = inputMode,
                        pin1 = pin1,
                        input = input,
                        exchange = nativeExchange,
                    )
                } else {
                    when (inputMode) {
                        AuthenticationSigningInputMode.MESSAGE -> {
                            NativeCore.authenticateAndSign(
                                exchangeLevel = exchangeLevel,
                                algorithm = algorithm,
                                pin1 = pin1,
                                message = input,
                                exchange = nativeExchange,
                            )
                        }

                        AuthenticationSigningInputMode.PREHASHED -> {
                            NativeCore.authenticateAndSignPrehashed(
                                exchangeLevel = exchangeLevel,
                                algorithm = algorithm,
                                pin1 = pin1,
                                digest = input,
                                exchange = nativeExchange,
                            )
                        }
                    }
                }
        ) {
            is NativeAuthenticationSignResult.Success -> {
                val isVerified =
                    when (inputMode) {
                        AuthenticationSigningInputMode.MESSAGE -> {
                            AuthenticationSignatureVerifier.verify(
                                certificate = certificate,
                                message = input,
                                signature = result.signature,
                            )
                        }

                        AuthenticationSigningInputMode.PREHASHED -> {
                            AuthenticationSignatureVerifier.verifyPrehashed(
                                certificate = certificate,
                                digest = input,
                                signature = result.signature,
                            )
                        }
                    }
                AppTrace.authenticationSignatureVerificationCompleted(
                    inputMode = inputMode,
                    isVerified = isVerified,
                )
                if (isVerified) {
                    AuthenticationSignResult.Success(result.signature)
                } else {
                    result.signature.close()
                    AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                    )
                }
            }

            is NativeAuthenticationSignResult.Failure -> {
                AuthenticationSignResult.Failure(result.kind.toAuthenticationFailure())
            }
        }
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
            "CCID session is closed"
        }
        if (expectedCertificate.keyProfile != algorithm.keyProfile) {
            pin2.close()
            return QualifiedSignResult.Failure(QualifiedSignFailure.KEY_PROFILE_MISMATCH)
        }

        val nativeResult =
            NativeQualifiedCore.qualifiedSignInput(
                exchangeLevel = exchangeLevel,
                algorithm = algorithm,
                inputMode = inputMode,
                pin2 = pin2,
                input = input,
                expectedCertificate = expectedCertificate,
                exchange = nativeExchange,
            )
        val verifiedResult =
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
                        QualifiedSignResult.Failure(
                            QualifiedSignFailure.LOCAL_VERIFICATION_FAILED,
                        )
                    }
                }

                is NativeQualifiedSignResult.Failure -> {
                    QualifiedSignResult.Failure(nativeResult.kind.toQualifiedFailure())
                }
            }
        if (!nativeResult.allowsQualifiedContextRestore()) {
            return verifiedResult
        }
        return when (selectPkcs15Application()) {
            NativeCardOperationResult.SUCCEEDED -> {
                verifiedResult
            }

            NativeCardOperationResult.CARD_UNAVAILABLE -> {
                verifiedResult.closeSignature()
                QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)
            }

            NativeCardOperationResult.TRANSPORT_ERROR -> {
                verifiedResult.closeSignature()
                QualifiedSignResult.Failure(QualifiedSignFailure.TRANSPORT_ERROR)
            }

            NativeCardOperationResult.REJECTED,
            NativeCardOperationResult.BRIDGE_ERROR,
            -> {
                verifiedResult.closeSignature()
                QualifiedSignResult.Failure(QualifiedSignFailure.BRIDGE_ERROR)
            }
        }
    }

    fun authenticateAndSignWithDiagnosticAlgorithm(
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        val algorithm =
            when (sessionMaterial.requireAuthenticationCertificate().keyProfile) {
                NativeCardKeyProfile.RSA_3072 -> {
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256
                }

                NativeCardKeyProfile.ECDSA_P384 -> {
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
                }

                NativeCardKeyProfile.RSA_2048,
                NativeCardKeyProfile.ECDSA_P256,
                -> {
                    null
                }
            }
        if (algorithm == null) {
            pin1.close()
            return AuthenticationSignResult.Failure(
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
            )
        }
        return authenticateAndSign(
            algorithm = algorithm,
            pin1 = pin1,
            message = message,
        )
    }

    override fun close() {
        checkOwnerThread()
        if (isClosed) {
            return
        }
        isClosed = true
        cardRemovalListener = null
        interruptThread?.interrupt()
        interruptThread = null
        if (contactlessSessionActive) {
            // The card's half dies with the field; drop the host's keys too.
            NativeContactlessSession.close()
            contactlessSessionActive = false
        }
        sessionMaterial.close()

        val interfaceReleased =
            try {
                connection.releaseInterface(usbInterface)
            } catch (_: SecurityException) {
                false
            }
        try {
            connection.close()
        } finally {
            AppTrace.ccidSessionClosed(interfaceReleased)
        }
    }

    fun probeCredentialHealth(): CardManagementResult<CredentialHealth> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.probeCredentialHealth(exchangeLevel, nativeExchange)
    }

    fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.changePin1(
            exchangeLevel,
            currentPin,
            newPin,
            nativeExchange,
        )
    }

    fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.changePin2(
            exchangeLevel,
            currentPin,
            newPin,
            nativeExchange,
        )
    }

    fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.unblockPin1(
            exchangeLevel,
            puk,
            newPin,
            nativeExchange,
        )
    }

    fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
    ): CardManagementResult<ManageOutcome> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.unblockPin2(
            exchangeLevel,
            puk,
            newPin,
            nativeExchange,
        )
    }

    fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
    ): CardManagementResult<ActivationReport> {
        checkOwnerThread()
        check(!isClosed) {
            "CCID session is closed"
        }
        return NativeCardManagement.activateCard(
            exchangeLevel,
            scheme,
            code,
            newPin1,
            newPin2,
            nativeExchange,
        )
    }

    override fun toString(): String = "CcidUsbSession(closed=" + isClosed + ")"

    private fun checkOwnerThread() {
        check(Thread.currentThread() === ownerThread) {
            "CCID session used from a different thread"
        }
    }

    private companion object {
        const val FIRST_SLOT = 0
        const val INTERRUPT_POLL_TIMEOUT_MILLISECONDS = 500
    }
}

private fun NativeCertificateReadResult<NativeQualifiedCertificate>.allowsContextRestore(): Boolean =
    when (this) {
        is NativeCertificateReadResult.Success -> {
            true
        }

        is NativeCertificateReadResult.Failure -> {
            kind == NativeCertificateReadFailure.REJECTED ||
                kind == NativeCertificateReadFailure.INVALID_CERTIFICATE
        }
    }

private fun NativeCertificateReadResult<NativeQualifiedCertificate>.closeCertificate() {
    if (this is NativeCertificateReadResult.Success) {
        certificate.close()
    }
}

private fun NativeAuthenticationSignFailure.toAuthenticationFailure(): AuthenticationSignFailure =
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

        // The USB path opens no PACE channel; a channel refusal reaching
        // it is a local impossibility.
        NativeAuthenticationSignFailure.PACE_REJECTED,
        NativeAuthenticationSignFailure.BRIDGE_ERROR,
        -> {
            AuthenticationSignFailure.BRIDGE_ERROR
        }
    }

private fun NativeQualifiedSignResult.allowsQualifiedContextRestore(): Boolean =
    when (this) {
        is NativeQualifiedSignResult.Success -> {
            true
        }

        is NativeQualifiedSignResult.Failure -> {
            when (kind) {
                NativeQualifiedSignFailure.PIN_LOCKED,
                NativeQualifiedSignFailure.WRONG_PIN,
                NativeQualifiedSignFailure.VERIFICATION_REJECTED,
                NativeQualifiedSignFailure.CERTIFICATE_REJECTED,
                NativeQualifiedSignFailure.INVALID_CERTIFICATE,
                NativeQualifiedSignFailure.CERTIFICATE_MISMATCH,
                NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH,
                NativeQualifiedSignFailure.SIGNING_REJECTED,
                -> true

                NativeQualifiedSignFailure.CARD_UNAVAILABLE,
                NativeQualifiedSignFailure.TRANSPORT_ERROR,
                NativeQualifiedSignFailure.INVALID_PIN,
                NativeQualifiedSignFailure.SAFETY_REFUSED,
                NativeQualifiedSignFailure.BRIDGE_ERROR,
                -> false
            }
        }
    }

private fun QualifiedSignResult.closeSignature() {
    if (this is QualifiedSignResult.Success) {
        signature.close()
    }
}

private fun NativeQualifiedSignFailure.toQualifiedFailure(): QualifiedSignFailure =
    when (this) {
        NativeQualifiedSignFailure.CARD_UNAVAILABLE -> {
            QualifiedSignFailure.CARD_UNAVAILABLE
        }

        NativeQualifiedSignFailure.TRANSPORT_ERROR -> {
            QualifiedSignFailure.TRANSPORT_ERROR
        }

        NativeQualifiedSignFailure.INVALID_PIN -> {
            QualifiedSignFailure.INVALID_PIN
        }

        NativeQualifiedSignFailure.SAFETY_REFUSED -> {
            QualifiedSignFailure.SAFETY_REFUSED
        }

        NativeQualifiedSignFailure.PIN_LOCKED -> {
            QualifiedSignFailure.PIN_LOCKED
        }

        NativeQualifiedSignFailure.WRONG_PIN -> {
            QualifiedSignFailure.WRONG_PIN
        }

        NativeQualifiedSignFailure.VERIFICATION_REJECTED -> {
            QualifiedSignFailure.VERIFICATION_REJECTED
        }

        NativeQualifiedSignFailure.CERTIFICATE_REJECTED -> {
            QualifiedSignFailure.CERTIFICATE_REJECTED
        }

        NativeQualifiedSignFailure.INVALID_CERTIFICATE -> {
            QualifiedSignFailure.INVALID_CERTIFICATE
        }

        NativeQualifiedSignFailure.CERTIFICATE_MISMATCH -> {
            QualifiedSignFailure.CERTIFICATE_MISMATCH
        }

        NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH -> {
            QualifiedSignFailure.KEY_PROFILE_MISMATCH
        }

        NativeQualifiedSignFailure.SIGNING_REJECTED -> {
            QualifiedSignFailure.SIGNING_REJECTED
        }

        NativeQualifiedSignFailure.BRIDGE_ERROR -> {
            QualifiedSignFailure.BRIDGE_ERROR
        }
    }

internal class CcidUsbSessionOpener(
    private val usbManager: UsbManager,
    private val validateAtr: (ByteArray) -> AtrValidation,
) {
    fun open(device: UsbDevice): CcidSessionOpenResult {
        val candidates = CcidUsbEndpointFinder.findAll(device)
        AppTrace.ccidUsbSurvey(
            interfaceCount = device.interfaceCount,
            ccidCount = candidates.size,
        )
        if (candidates.isEmpty()) {
            AppTrace.ccidEndpointsMissing()
            return CcidSessionOpenResult.TransportError
        }

        // Probe every CCID interface until one yields a usable session: a
        // dual reader lists the contactless PICC before the contact ICC
        // slot, and an empty SAM slot also reports no card. Errors do not
        // end the scan -- a foreign object resting on the contactless pad
        // must never mask a properly inserted card -- but the first error
        // is retained and reported when no interface opens.
        var firstFailure: CcidSessionOpenResult? = null
        for (endpoints in candidates) {
            val connection =
                usbManager.openDevice(device)
                    ?: run {
                        AppTrace.ccidOpenFailed()
                        return firstFailure ?: CcidSessionOpenResult.TransportError
                    }
            when (val attempt = connection.openClaimed(endpoints, device)) {
                is CcidSessionOpenResult.Ready,
                is CcidSessionOpenResult.AccessNumberRequired,
                is CcidSessionOpenResult.ActivationRequired,
                -> {
                    return attempt
                }

                CcidSessionOpenResult.NoCard -> {
                    // This interface has no card; probe the next one.
                }

                CcidSessionOpenResult.CardError,
                CcidSessionOpenResult.TransportError,
                -> {
                    if (firstFailure == null) {
                        firstFailure = attempt
                    }
                }
            }
        }
        return firstFailure ?: CcidSessionOpenResult.NoCard
    }

    private fun UsbDeviceConnection.openClaimed(
        endpoints: CcidUsbEndpoints,
        device: UsbDevice,
    ): CcidSessionOpenResult {
        var ownsConnection = true
        var isClaimed = false
        return try {
            val descriptor =
                CcidFunctionalDescriptor.parse(
                    rawDescriptors = rawDescriptors,
                    interfaceNumber = endpoints.usbInterface.id,
                    alternateSetting = endpoints.usbInterface.alternateSetting,
                )
            AppTrace.ccidDescriptorAccepted(
                level = descriptor.exchangeLevel,
                maximumMessageLength = descriptor.maximumMessageLength,
                features = descriptor.features,
                interfaceNumber = endpoints.usbInterface.id,
                vendorId = device.vendorId,
                productId = device.productId,
                productName = device.productName,
            )
            AppTrace.ccidEndpoints(
                interfaceNumber = endpoints.usbInterface.id,
                bulkInMaxPacketSize = endpoints.bulkIn.maxPacketSize,
                bulkOutMaxPacketSize = endpoints.bulkOut.maxPacketSize,
                interruptInMaxPacketSize = endpoints.interruptIn?.maxPacketSize,
            )

            isClaimed = claimInterface(endpoints.usbInterface, true)
            if (!isClaimed) {
                AppTrace.ccidClaimFailed()
                CcidSessionOpenResult.TransportError
            } else {
                val sequenceCounter = CcidSequenceCounter()
                val exchange =
                    CcidCommandExchange(
                        bulkIo = AndroidCcidBulkIo(this, endpoints),
                        maximumMessageLength = descriptor.maximumMessageLength,
                    )
                val activation =
                    CcidCardActivator(
                        validateAtr = validateAtr,
                        sequenceCounter = sequenceCounter,
                        hostPpsRequired = descriptor.hostPpsExchangeRequired,
                    ).activate(
                        exchange = exchange,
                        exchangeLevel = descriptor.exchangeLevel,
                    )
                when (activation) {
                    CcidActivationResult.READY -> {
                        val session =
                            CcidUsbSession(
                                connection = this,
                                usbInterface = endpoints.usbInterface,
                                descriptor = descriptor,
                                exchange = exchange,
                                sequenceCounter = sequenceCounter,
                                interruptIn = endpoints.interruptIn,
                            )
                        ownsConnection = false
                        isClaimed = false
                        prepareSession(session)
                    }

                    CcidActivationResult.NO_CARD -> {
                        CcidSessionOpenResult.NoCard
                    }

                    CcidActivationResult.CARD_ERROR -> {
                        CcidSessionOpenResult.CardError
                    }

                    CcidActivationResult.TRANSPORT_ERROR -> {
                        CcidSessionOpenResult.TransportError
                    }
                }
            }
        } catch (error: CcidDescriptorException) {
            AppTrace.ccidDescriptorRejected(error.kind, detail = error.detail)
            CcidSessionOpenResult.TransportError
        } catch (_: SecurityException) {
            AppTrace.ccidSecurityFailure()
            CcidSessionOpenResult.TransportError
        } finally {
            if (isClaimed) {
                try {
                    releaseInterface(endpoints.usbInterface)
                } catch (_: SecurityException) {
                    // The connection is closed below regardless.
                }
            }
            if (ownsConnection) {
                close()
            }
        }
    }

    /** After a certificate is read successfully, check activation needs then PIN1 preflight. */
    private fun preparePastCertificate(session: CcidUsbSession): CcidSessionOpenResult {
        val healthResult = session.probeCredentialHealth()
        if (healthResult is fi.refineid.android.core.CardManagementResult.Success) {
            AppTrace.credentialHealth(healthResult.value)
            if (healthResult.value.activationNeeds.any) {
                return CcidSessionOpenResult.ActivationRequired(session)
            }
        }
        return when (val preflight = session.cachePin1Preflight()) {
            is NativePin1PreflightResult.Success -> {
                CcidSessionOpenResult.Ready(session)
            }

            is NativePin1PreflightResult.Failure -> {
                when (preflight.kind) {
                    NativePin1PreflightFailure.CARD_UNAVAILABLE -> CcidSessionOpenResult.NoCard

                    NativePin1PreflightFailure.TRANSPORT_ERROR,
                    NativePin1PreflightFailure.BRIDGE_ERROR,
                    -> CcidSessionOpenResult.TransportError
                }
            }
        }
    }

    private fun prepareSession(session: CcidUsbSession): CcidSessionOpenResult {
        var retainSession = false
        return try {
            when (session.selectPkcs15Application()) {
                NativeCardOperationResult.SUCCEEDED -> {
                    when (val result = session.cacheAuthenticationCertificate()) {
                        is NativeCertificateReadResult.Success -> {
                            preparePastCertificate(session).also { result ->
                                if (result is CcidSessionOpenResult.Ready ||
                                    result is CcidSessionOpenResult.ActivationRequired
                                ) {
                                    retainSession = true
                                }
                            }
                        }

                        is NativeCertificateReadResult.Failure -> {
                            when (result.kind) {
                                NativeCertificateReadFailure.ACTIVATION_REQUIRED -> {
                                    retainSession = true
                                    CcidSessionOpenResult.ActivationRequired(session)
                                }

                                NativeCertificateReadFailure.CARD_UNAVAILABLE -> {
                                    CcidSessionOpenResult.NoCard
                                }

                                NativeCertificateReadFailure.REJECTED,
                                NativeCertificateReadFailure.INVALID_CERTIFICATE,
                                -> {
                                    CcidSessionOpenResult.CardError
                                }

                                NativeCertificateReadFailure.TRANSPORT_ERROR,
                                NativeCertificateReadFailure.PACE_REJECTED,
                                NativeCertificateReadFailure.BRIDGE_ERROR,
                                -> {
                                    CcidSessionOpenResult.TransportError
                                }
                            }
                        }
                    }
                }

                NativeCardOperationResult.CARD_UNAVAILABLE -> {
                    CcidSessionOpenResult.NoCard
                }

                NativeCardOperationResult.REJECTED -> {
                    // A contactless card rejects the plain PKCS#15 select: it
                    // requires PACE first. Keep the activated session so the
                    // access number can open it over secure messaging.
                    retainSession = true
                    CcidSessionOpenResult.AccessNumberRequired(session)
                }

                NativeCardOperationResult.TRANSPORT_ERROR,
                NativeCardOperationResult.BRIDGE_ERROR,
                -> {
                    CcidSessionOpenResult.TransportError
                }
            }
        } finally {
            if (!retainSession) {
                session.close()
            }
        }
    }
}
