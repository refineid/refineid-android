package fi.refineid.android.diagnostics

import fi.refineid.android.browser.BrowserClientCertificateOutcome
import fi.refineid.android.browser.BrowserSignatureStatus
import fi.refineid.android.core.AtrValidation
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignResult
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardOperationResult
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.document.QualifiedPdfArchivalResult
import fi.refineid.android.document.QualifiedPdfArchivalStage
import fi.refineid.android.document.QualifiedPdfPreparationResult
import fi.refineid.android.document.QualifiedPdfSigningResult
import fi.refineid.android.keychain.ExternalKeyPinAuthorization
import fi.refineid.android.keychain.ExternalKeySignResult
import fi.refineid.android.network.SigningTimestampAttemptOutcome
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.usb.AuthenticationStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.ccid.CcidBlockFailureKind
import fi.refineid.android.usb.ccid.CcidCardStatus
import fi.refineid.android.usb.ccid.CcidDescriptorErrorKind
import fi.refineid.android.usb.ccid.CcidExchangeFailureKind
import fi.refineid.android.usb.ccid.CcidExchangeLevel
import fi.refineid.android.usb.ccid.CcidProtocolErrorKind
import fi.refineid.android.usb.ccid.CcidSessionOpenResult

/** Release sink: deliberately empty. */
internal object AppTrace {
    fun activityCreated() = Unit

    fun activityReceivedIntent() = Unit

    fun activityDestroyed() = Unit

    fun externalKeyProviderServiceCreated() = Unit

    fun externalKeyProviderServiceBound(isAccepted: Boolean) = Unit

    fun externalKeyProviderServiceDestroyed() = Unit

    fun externalKeyIdentityQueried(isAvailable: Boolean) = Unit

    fun externalKeySignStarted(algorithm: AuthenticationSigningAlgorithm) = Unit

    fun externalKeySignCompleted(result: ExternalKeySignResult) = Unit

    fun externalKeyIdentityRemovalCompleted(isRemoved: Boolean) = Unit

    fun externalKeyPinPromptDispatched() = Unit

    fun externalKeyPinPromptCompleted(authorization: ExternalKeyPinAuthorization) = Unit

    fun nativeLibraryLoadCompleted(isSuccessful: Boolean) = Unit

    fun nativeAtrValidationCompleted(result: AtrValidation) = Unit

    fun nativePkcs15SelectionStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativePkcs15SelectionCompleted(
        startedAt: Long,
        result: NativeCardOperationResult,
    ) = Unit

    fun nativeAuthenticationCertificateReadStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativeAuthenticationCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeAuthenticationCertificate>,
    ) = Unit

    fun nativeQualifiedCertificateReadStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativeQualifiedCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeQualifiedCertificate>,
    ) = Unit

    fun nativePin1StatusProbeStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativePin1StatusProbeCompleted(
        startedAt: Long,
        result: NativePin1PreflightResult,
    ) = Unit

    fun nativePin2StatusProbeStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativePin2StatusProbeCompleted(
        startedAt: Long,
        result: NativePin2PreflightResult,
    ) = Unit

    fun nativeCardAccessProbeStarted(level: NativeCardExchangeLevel): Long = 0L

    fun nativeCardAccessProbeCompleted(
        startedAt: Long,
        result: NativeCardAccessResult,
    ) = Unit

    fun nativeContactlessOpenStarted(): Long = 0L

    fun nativeContactlessOpenCompleted(
        startedAt: Long,
        result: NativeContactlessOpenResult,
    ) = Unit

    fun nativeContactlessSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long = 0L

    fun nativeContactlessSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) = Unit

    fun nativeAuthenticationSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long = 0L

    fun nativeAuthenticationSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) = Unit

    fun nativeQualifiedSignStarted(
        algorithm: QualifiedSigningAlgorithm,
        contentLength: Int,
    ): Long = 0L

    fun nativeQualifiedSignCompleted(
        startedAt: Long,
        result: NativeQualifiedSignResult,
    ) = Unit

    fun qualifiedSignatureVerificationCompleted(isVerified: Boolean) = Unit

    fun qualifiedPdfSigningStarted(documentLength: Int): Long = 0L

    fun qualifiedPdfSigningCompleted(
        startedAt: Long,
        result: QualifiedPdfSigningResult,
    ) = Unit

    fun qualifiedPdfPreparationStarted(documentLength: Int): Long = 0L

    fun qualifiedPdfPreparationCompleted(
        startedAt: Long,
        result: QualifiedPdfPreparationResult,
    ) = Unit

    fun qualifiedPdfArchivalStarted(): Long = 0L

    fun qualifiedPdfArchivalStage(stage: QualifiedPdfArchivalStage) = Unit

    fun qualifiedPdfArchivalCompleted(
        startedAt: Long,
        result: QualifiedPdfArchivalResult,
    ) = Unit

    fun signingTimestampAttemptStarted(
        authorityOrdinal: Int,
        authorityCount: Int,
    ) = Unit

    fun signingTimestampAttemptCompleted(
        authorityOrdinal: Int,
        outcome: SigningTimestampAttemptOutcome,
    ) = Unit

    fun signingTimestampRetryScheduled(delaySeconds: Long) = Unit

    fun authenticationSignatureVerificationCompleted(
        inputMode: AuthenticationSigningInputMode,
        isVerified: Boolean,
    ) = Unit

    fun authenticationRequestIgnored() = Unit

    fun authenticationRequestStarted() = Unit

    fun authenticationRequestCompleted(status: AuthenticationStatus) = Unit

    fun usbContactlessConnectIgnored() = Unit

    fun usbContactlessConnectStarted() = Unit

    fun usbContactlessConnectCompleted(opened: Boolean) = Unit

    fun documentInputStarted() = Unit

    fun documentInputCompleted(
        isAccepted: Boolean,
        documentLength: Int?,
    ) = Unit

    fun documentDestinationSelected(isAccepted: Boolean) = Unit

    fun documentOutputCompleted(
        isSuccessful: Boolean,
        documentLength: Int,
    ) = Unit

    fun browserOpened() = Unit

    fun browserClosed() = Unit

    fun browserInitialized(
        providerReady: Boolean,
        issuerCount: Int,
    ) = Unit

    fun browserNavigationBlocked() = Unit

    fun browserTlsError(
        host: String,
        primaryError: Int,
        issuedBy: String,
        issuedTo: String,
    ) = Unit

    fun browserClientCertificateRequested(
        originAllowed: Boolean,
        keyTypeCount: Int,
        issuerCount: Int,
    ) = Unit

    fun browserClientCertificateUnlockRequested() = Unit

    fun browserClientCertificateCompleted(outcome: BrowserClientCertificateOutcome) = Unit

    fun browserSignatureStatus(status: BrowserSignatureStatus) = Unit

    fun usbControllerStartIgnored() = Unit

    fun usbControllerStarted() = Unit

    fun usbControllerStopIgnored() = Unit

    fun usbControllerStopped() = Unit

    fun usbRefreshIgnored() = Unit

    fun usbRefreshSessionKept() = Unit

    fun usbPermissionResult(isGranted: Boolean) = Unit

    fun usbDeviceAttached() = Unit

    fun usbDeviceDetached() = Unit

    fun usbReadersRefreshed(
        deviceCount: Int,
        hasCcidReader: Boolean,
        hasPermission: Boolean?,
    ) = Unit

    fun usbPermissionRequestWithoutReader() = Unit

    fun usbPermissionAlreadyGranted() = Unit

    fun usbPermissionRequested() = Unit

    fun rappListenerStarted(port: Int) = Unit

    fun rappListenerServiceRegistered(serviceName: String) = Unit

    fun rappListenerFailed(error: String) = Unit

    fun rappConnectionAccepted(remoteAddress: String) = Unit

    fun rappConnectionRejected(
        remoteAddress: String,
        reason: String,
    ) = Unit

    fun rappConnectionDropped(reason: String) = Unit

    fun rappOperationReceived(
        opType: String,
        opIdHex: String,
    ) = Unit

    fun rappOperationApproved(opIdHex: String) = Unit

    fun rappOperationDenied(
        opIdHex: String,
        reason: String,
    ) = Unit

    fun rappOperationCompleted(
        opType: String,
        opIdHex: String,
        durationUs: Long,
    ) = Unit

    fun rappOperationFailed(
        opType: String,
        opIdHex: String,
        failureKind: String,
    ) = Unit

    fun rappCardPromptShown(
        opIdHex: String,
        action: String,
    ) = Unit

    fun rappCardPromptDismissed(opIdHex: String) = Unit

    fun rappPairingCodeDisplayed() = Unit

    fun rappPairingCompleted(peerName: String) = Unit

    fun rappOperationApproveFailed(error: String) = Unit

    fun rappOperationDenyFailed(error: String) = Unit

    fun rappProgressReportFailed(
        stage: String,
        error: String,
    ) = Unit

    fun usbPermissionRequestFailed() = Unit

    fun usbSessionOpenStarted() = Unit

    fun usbSessionOpenCompleted(result: CcidSessionOpenResult) = Unit

    fun usbSessionOpenResultDiscarded() = Unit

    fun usbSnapshotPublished(
        status: ReaderConnectionStatus,
        cardPresence: CardPresence?,
    ) = Unit

    fun usbCardRemoved() = Unit

    fun nfcAdapterMissing() = Unit

    fun nfcAdapterStateChanged() = Unit

    fun nfcReaderModeChanged(isEnabled: Boolean) = Unit

    fun nfcTagDiscovered(isIsoDep: Boolean) = Unit

    fun nfcSessionOpenFailed() = Unit

    fun nfcSessionClosed() = Unit

    fun nfcTagLost() = Unit

    fun nfcTransceiveFailed() = Unit

    fun nfcTransceive(
        commandLength: Int,
        responseLength: Int,
        durationMicros: Long,
        sw: Int = 0,
        cla: Int = -1,
        ins: Int = -1,
        p1: Int = -1,
        p2: Int = -1,
    ) = Unit

    fun getTraceLog(): List<String> = emptyList()

    fun clearTraceLog(): Unit = Unit

    fun nfcProbeResultDiscarded() = Unit

    fun nfcSnapshotPublished(status: NfcReaderStatus) = Unit

    fun nfcSettingsUnavailable() = Unit

    fun documentValidationStarted() = Unit

    fun documentValidationCompleted(read: Boolean) = Unit

    fun nfcConnectStarted() = Unit

    fun nfcConnectIgnored() = Unit

    fun nfcTagAdopted() = Unit

    fun nfcPrimedOpenStarted() = Unit

    fun nfcPrimedMinted() = Unit

    fun nfcPrimedForgotten() = Unit

    fun nfcAwaitCardReady(
        isCardReady: Boolean,
        status: String,
        hasResting: Boolean,
    ) = Unit

    fun nfcOpenSessionStarted(
        hasTarget: Boolean,
        generation: Int,
        mintOnSuccess: Boolean,
    ) = Unit

    fun ccidEndpointsMissing() = Unit

    fun ccidOpenFailed() = Unit

    fun ccidDescriptorRejected(
        kind: CcidDescriptorErrorKind,
        detail: String = "",
    ) = Unit

    fun ccidDescriptorAccepted(
        level: CcidExchangeLevel,
        maximumMessageLength: Int,
        features: Long = 0L,
        interfaceNumber: Int = -1,
        vendorId: Int = -1,
        productId: Int = -1,
        productName: String? = null,
    ) = Unit

    fun credentialHealth(health: CredentialHealth) = Unit

    fun ccidClaimFailed() = Unit

    fun ccidSecurityFailure() = Unit

    fun ccidSessionClosed(interfaceReleased: Boolean) = Unit

    fun ccidSlotExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun ccidPowerExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun ccidParameters(
        protocolNum: Int,
        dataHex: String,
    ) = Unit

    fun ccidParametersFailure(errorCode: Int) = Unit

    fun ccidParametersExchangeFailed(kind: CcidExchangeFailureKind) = Unit

    fun ccidSetParametersResult(
        succeeded: Boolean,
        detail: String = "",
    ) = Unit

    fun ccidPpsLinkCheck(alive: Boolean) = Unit

    fun ccidPpsExchange(detail: String) = Unit

    fun ccidCardState(state: CcidCardStatus) = Unit

    fun ccidCommandFailed(
        errorCode: Int,
        cardStatus: CcidCardStatus,
    ) = Unit

    fun ccidAtrResult(
        length: Int,
        validation: AtrValidation,
        isSupported: Boolean,
        atrHex: String = "",
    ) = Unit

    fun ccidTimeExtension(
        count: Int,
        multiplier: Int,
    ) = Unit

    fun ccidResponseRejected(
        kind: CcidProtocolErrorKind,
        expected: Int = -1,
        actual: Int = -1,
        frameLength: Int = -1,
        detail: String = "",
    ) = Unit

    fun ccidExchangeStarted(
        messageType: Int,
        slot: Int,
        sequence: Int,
        length: Int,
    ) = Unit

    fun ccidCommandExchangeFailed(
        kind: CcidExchangeFailureKind,
        messageType: Int = -1,
        slot: Int = -1,
        sequence: Int = -1,
    ) = Unit

    fun ccidBulkTransfer(
        direction: String,
        requested: Int,
        transferred: Int,
    ) = Unit

    fun ccidUsbSurvey(
        interfaceCount: Int,
        ccidCount: Int,
    ) = Unit

    fun ccidEndpoints(
        interfaceNumber: Int,
        bulkInMaxPacketSize: Int,
        bulkOutMaxPacketSize: Int,
        interruptInMaxPacketSize: Int?,
    ) = Unit

    fun nfcAwaitingCard() = Unit

    fun ccidPowerResult(
        cardStatus: CcidCardStatus,
        chainParameter: String,
        payloadLength: Int,
    ) = Unit

    fun ccidCardRemovalDetected() = Unit

    fun cardPublicCommandStarted(
        classByte: Int,
        instruction: Int,
        parameterOne: Int,
        parameterTwo: Int,
        commandLength: Int,
    ): Long = 0L

    fun cardPublicMalformedCommandStarted(commandLength: Int): Long = 0L

    fun cardPublicCommandResponded(
        startedAt: Long,
        statusWord: Int,
        responseBodyLength: Int,
    ) = Unit

    fun cardPublicCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit

    fun cardSensitiveCommandStarted(): Long = 0L

    fun cardSensitiveCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) = Unit

    fun cardSensitiveCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit

    fun cardCredentialCommandStarted(): Long = 0L

    fun cardCredentialCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) = Unit

    fun cardCredentialCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) = Unit

    fun uncaughtException(
        thread: Thread,
        throwable: Throwable,
    ) = Unit
}
