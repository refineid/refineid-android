package fi.refineid.android.diagnostics

import android.util.Log
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
import fi.refineid.android.core.NativePin1State
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

/** Debug-only application trace. Arguments must already be sanitized. */
internal object AppTrace {
    fun activityCreated() {
        debug(
            "app:activity-created version=" + fi.refineid.android.BuildConfig.VERSION_NAME +
                " (" + fi.refineid.android.BuildConfig.BUILD_NUMBER + ")",
        )
    }

    fun activityReceivedIntent() {
        debug("app:activity-intent")
    }

    fun activityDestroyed() {
        debug("app:activity-destroyed")
    }

    fun externalKeyProviderServiceCreated() {
        debug("external-key:service-created")
    }

    fun externalKeyProviderServiceBound(isAccepted: Boolean) {
        debug("external-key:service-bind accepted=" + isAccepted)
    }

    fun externalKeyProviderServiceDestroyed() {
        debug("external-key:service-destroyed")
    }

    fun externalKeyIdentityQueried(isAvailable: Boolean) {
        debug("external-key:identity-query available=" + isAvailable)
    }

    fun externalKeySignStarted(algorithm: AuthenticationSigningAlgorithm) {
        debug("external-key:sign-started algorithm=" + algorithm)
    }

    fun externalKeySignCompleted(result: ExternalKeySignResult) {
        debug("external-key:sign-completed result=" + result)
    }

    fun externalKeyIdentityRemovalCompleted(isRemoved: Boolean) {
        debug("external-key:identity-removal removed=" + isRemoved)
    }

    fun externalKeyPinPromptDispatched() {
        debug("external-key:pin-prompt-dispatched")
    }

    fun externalKeyPinPromptCompleted(authorization: ExternalKeyPinAuthorization) {
        val outcome =
            when (authorization) {
                is ExternalKeyPinAuthorization.Approved -> "approved"
                ExternalKeyPinAuthorization.Cancelled -> "cancelled"
                ExternalKeyPinAuthorization.TimedOut -> "timed-out"
                ExternalKeyPinAuthorization.Interrupted -> "interrupted"
                ExternalKeyPinAuthorization.Unavailable -> "unavailable"
            }
        debug("external-key:pin-prompt-completed outcome=" + outcome)
    }

    fun nativeLibraryLoadCompleted(isSuccessful: Boolean) {
        debug("native:library-loaded successful=" + isSuccessful)
    }

    fun nativeAtrValidationCompleted(result: AtrValidation) {
        debug("native:atr-validation result=" + result)
    }

    fun nativePkcs15SelectionStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pkcs15-select start level=" + level)
        }

    fun nativePkcs15SelectionCompleted(
        startedAt: Long,
        result: NativeCardOperationResult,
    ) {
        debug(
            "native:pkcs15-select result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeAuthenticationCertificateReadStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:authentication-certificate-read start level=" + level)
        }

    fun nativeAuthenticationCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeAuthenticationCertificate>,
    ) {
        val outcome =
            when (result) {
                is NativeCertificateReadResult.Success -> {
                    "success profile=" + result.certificate.keyProfile +
                        " length=" + result.certificate.derLength
                }

                is NativeCertificateReadResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:authentication-certificate-read " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeQualifiedCertificateReadStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:qualified-certificate-read start level=" + level)
        }

    fun nativeQualifiedCertificateReadCompleted(
        startedAt: Long,
        result: NativeCertificateReadResult<NativeQualifiedCertificate>,
    ) {
        val outcome =
            when (result) {
                is NativeCertificateReadResult.Success -> {
                    "success profile=" + result.certificate.keyProfile +
                        " length=" + result.certificate.derLength
                }

                is NativeCertificateReadResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:qualified-certificate-read " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativePin1StatusProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pin1-status-probe start level=" + level)
        }

    fun nativePin1StatusProbeCompleted(
        startedAt: Long,
        result: NativePin1PreflightResult,
    ) {
        val outcome =
            when (result) {
                is NativePin1PreflightResult.Success -> {
                    "success scheme=" + result.preflight.referenceScheme +
                        " state=" + result.preflight.state +
                        " permitted=" + result.preflight.consumerAuthenticationPermitted
                }

                is NativePin1PreflightResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:pin1-status-probe " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativePin2StatusProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:pin2-status-probe start level=" + level)
        }

    fun nativePin2StatusProbeCompleted(
        startedAt: Long,
        result: NativePin2PreflightResult,
    ) {
        val outcome =
            when (result) {
                is NativePin2PreflightResult.Success -> {
                    "success scheme=" + result.preflight.referenceScheme +
                        " state=" + result.preflight.state +
                        " permitted=" + result.preflight.qualifiedSignaturePermitted
                }

                is NativePin2PreflightResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:pin2-status-probe " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeCardAccessProbeStarted(level: NativeCardExchangeLevel): Long =
        System.nanoTime().also {
            debug("native:card-access-probe start level=" + level)
        }

    fun nativeCardAccessProbeCompleted(
        startedAt: Long,
        result: NativeCardAccessResult,
    ) {
        debug(
            "native:card-access-probe result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeContactlessOpenStarted(): Long =
        System.nanoTime().also {
            debug("native:contactless-open start")
        }

    fun nativeContactlessOpenCompleted(
        startedAt: Long,
        result: NativeContactlessOpenResult,
    ) {
        debug(
            "native:contactless-open result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeContactlessSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:contactless-sign start algorithm=" + algorithm +
                    " mode=" + inputMode +
                    " input-length=" + inputLength,
            )
        }

    fun nativeContactlessSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) {
        debug(
            "native:contactless-sign result=" + result +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeAuthenticationSignStarted(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        inputLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:authentication-sign start algorithm=" + algorithm +
                    " input-mode=" + inputMode +
                    " input-length=" + inputLength,
            )
        }

    fun nativeAuthenticationSignCompleted(
        startedAt: Long,
        result: NativeAuthenticationSignResult,
    ) {
        val outcome =
            when (result) {
                is NativeAuthenticationSignResult.Success -> {
                    "success algorithm=" + result.signature.algorithm +
                        " length=" + result.signature.length
                }

                is NativeAuthenticationSignResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:authentication-sign " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun nativeQualifiedSignStarted(
        algorithm: QualifiedSigningAlgorithm,
        contentLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "native:qualified-sign start algorithm=" + algorithm +
                    " content-length=" + contentLength,
            )
        }

    fun nativeQualifiedSignCompleted(
        startedAt: Long,
        result: NativeQualifiedSignResult,
    ) {
        val outcome =
            when (result) {
                is NativeQualifiedSignResult.Success -> {
                    "success algorithm=" + result.signature.algorithm +
                        " length=" + result.signature.length
                }

                is NativeQualifiedSignResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "native:qualified-sign " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedSignatureVerificationCompleted(isVerified: Boolean) {
        debug("qualified-signature:local-verification verified=" + isVerified)
    }

    fun qualifiedPdfSigningStarted(documentLength: Int): Long =
        System.nanoTime().also {
            debug("qualified-pdf:signing-started document-length=" + documentLength)
        }

    fun qualifiedPdfSigningCompleted(
        startedAt: Long,
        result: QualifiedPdfSigningResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfSigningResult.Success -> {
                    "success document-length=" + result.document.length
                }

                is QualifiedPdfSigningResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:signing-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedPdfPreparationStarted(documentLength: Int): Long =
        System.nanoTime().also {
            debug("qualified-pdf:preparation-started document-length=" + documentLength)
        }

    fun qualifiedPdfPreparationCompleted(
        startedAt: Long,
        result: QualifiedPdfPreparationResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfPreparationResult.Success -> {
                    "success document-length=" + result.prepared.documentLength
                }

                is QualifiedPdfPreparationResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:preparation-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun qualifiedPdfArchivalStarted(): Long =
        System.nanoTime().also {
            debug("qualified-pdf:archival-started")
        }

    fun qualifiedPdfArchivalStage(stage: QualifiedPdfArchivalStage) {
        debug("qualified-pdf:archival-stage stage=" + stage)
    }

    fun qualifiedPdfArchivalCompleted(
        startedAt: Long,
        result: QualifiedPdfArchivalResult,
    ) {
        val outcome =
            when (result) {
                is QualifiedPdfArchivalResult.Success -> {
                    "success document-length=" + result.document.length
                }

                is QualifiedPdfArchivalResult.Failure -> {
                    "failure kind=" + result.kind
                }
            }
        debug(
            "qualified-pdf:archival-completed " + outcome +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun signingTimestampAttemptStarted(
        authorityOrdinal: Int,
        authorityCount: Int,
    ) {
        debug(
            "signing-network:timestamp-attempt-started authority=" + authorityOrdinal +
                " of=" + authorityCount,
        )
    }

    fun signingTimestampAttemptCompleted(
        authorityOrdinal: Int,
        outcome: SigningTimestampAttemptOutcome,
    ) {
        debug(
            "signing-network:timestamp-attempt-completed authority=" + authorityOrdinal +
                " outcome=" + outcome,
        )
    }

    fun signingTimestampRetryScheduled(delaySeconds: Long) {
        debug("signing-network:timestamp-retry-scheduled delay-seconds=" + delaySeconds)
    }

    fun documentInputStarted() {
        debug("qualified-pdf:input-started")
    }

    fun documentInputCompleted(
        isAccepted: Boolean,
        documentLength: Int?,
    ) {
        debug(
            "qualified-pdf:input-completed accepted=" + isAccepted +
                " document-length=" + (documentLength ?: "none"),
        )
    }

    fun documentDestinationSelected(isAccepted: Boolean) {
        debug("qualified-pdf:destination-selected accepted=" + isAccepted)
    }

    fun documentOutputCompleted(
        isSuccessful: Boolean,
        documentLength: Int,
    ) {
        debug(
            "qualified-pdf:output-completed successful=" + isSuccessful +
                " document-length=" + documentLength,
        )
    }

    fun authenticationSignatureVerificationCompleted(
        inputMode: AuthenticationSigningInputMode,
        isVerified: Boolean,
    ) {
        debug(
            "authentication:local-verification input-mode=" + inputMode +
                " verified=" + isVerified,
        )
    }

    fun authenticationRequestIgnored() {
        debug("authentication:request ignored=not-ready")
    }

    fun authenticationRequestStarted() {
        debug("authentication:request-started")
    }

    fun authenticationRequestCompleted(status: AuthenticationStatus) {
        debug("authentication:request-completed status=" + status)
    }

    fun usbContactlessConnectIgnored() {
        debug("usb:contactless-connect ignored=not-awaiting-can")
    }

    fun usbContactlessConnectStarted() {
        debug("usb:contactless-connect-started")
    }

    fun usbContactlessConnectCompleted(opened: Boolean) {
        debug("usb:contactless-connect-completed opened=" + opened)
    }

    fun rappListenerStarted(port: Int) {
        debug("rapp:listener-started port=" + port)
    }

    fun rappListenerServiceRegistered(serviceName: String) {
        debug("rapp:service-registered name=" + serviceName)
    }

    fun rappListenerFailed(error: String) {
        debug("rapp:listener-failed error=" + error)
    }

    fun rappConnectionAccepted(remoteAddress: String) {
        debug("rapp:connection-accepted remote=" + remoteAddress)
    }

    fun rappConnectionRejected(
        remoteAddress: String,
        reason: String,
    ) {
        debug("rapp:connection-rejected remote=" + remoteAddress + " reason=" + reason)
    }

    fun rappConnectionDropped(reason: String) {
        debug("rapp:connection-dropped reason=" + reason)
    }

    fun rappOperationReceived(
        opType: String,
        opIdHex: String,
    ) {
        debug("rapp:operation-received type=" + opType + " id=" + opIdHex)
    }

    fun rappOperationApproved(opIdHex: String) {
        debug("rapp:operation-approved id=" + opIdHex)
    }

    fun rappOperationDenied(
        opIdHex: String,
        reason: String,
    ) {
        debug("rapp:operation-denied id=" + opIdHex + " reason=" + reason)
    }

    fun rappOperationCompleted(
        opType: String,
        opIdHex: String,
        durationUs: Long,
    ) {
        debug("rapp:operation-completed type=" + opType + " id=" + opIdHex + " duration-us=" + durationUs)
    }

    fun rappOperationFailed(
        opType: String,
        opIdHex: String,
        failureKind: String,
    ) {
        debug("rapp:operation-failed type=" + opType + " id=" + opIdHex + " failure=" + failureKind)
    }

    fun rappCardPromptShown(
        opIdHex: String,
        action: String,
    ) {
        debug("rapp:card-prompt-shown id=" + opIdHex + " action=" + action)
    }

    fun rappCardPromptDismissed(opIdHex: String) {
        debug("rapp:card-prompt-dismissed id=" + opIdHex)
    }

    fun rappPairingCodeDisplayed() {
        debug("rapp:pairing-code-displayed")
    }

    fun rappPairingCompleted(peerName: String) {
        debug("rapp:pairing-completed peer=" + peerName)
    }

    fun rappOperationApproveFailed(error: String) {
        debug("rapp:approve-failed error=" + error)
    }

    fun rappOperationDenyFailed(error: String) {
        debug("rapp:deny-failed error=" + error)
    }

    fun rappProgressReportFailed(
        stage: String,
        error: String,
    ) {
        debug("rapp:progress-failed stage=" + stage + " error=" + error)
    }

    fun browserOpened() {
        debug("browser:opened")
    }

    fun browserClosed() {
        debug("browser:closed")
    }

    fun browserInitialized(
        providerReady: Boolean,
        issuerCount: Int,
    ) {
        debug(
            "browser:initialized provider-ready=" + providerReady +
                " issuer-count=" + issuerCount,
        )
    }

    fun browserNavigationBlocked() {
        debug("browser:navigation-blocked")
    }

    fun browserTlsError(
        host: String,
        primaryError: Int,
        issuedBy: String,
        issuedTo: String,
    ) {
        debug(
            "browser:tls-error host=" + host +
                " primary-error=" + primaryError +
                " issued-by=" + issuedBy +
                " issued-to=" + issuedTo,
        )
    }

    fun browserClientCertificateRequested(
        originAllowed: Boolean,
        keyTypeCount: Int,
        issuerCount: Int,
    ) {
        debug(
            "browser:client-certificate-request origin-allowed=" + originAllowed +
                " key-type-count=" + keyTypeCount +
                " issuer-count=" + issuerCount,
        )
    }

    fun browserClientCertificateUnlockRequested() {
        debug("browser:client-certificate-unlock-requested")
    }

    fun browserClientCertificateCompleted(outcome: BrowserClientCertificateOutcome) {
        debug("browser:client-certificate-completed outcome=" + outcome)
    }

    fun browserSignatureStatus(status: BrowserSignatureStatus) {
        debug("browser:signature status=" + status)
    }

    fun usbControllerStartIgnored() {
        debug("usb:controller-start ignored=already-started")
    }

    fun usbControllerStarted() {
        debug("usb:controller-started")
    }

    fun usbControllerStopIgnored() {
        debug("usb:controller-stop ignored=not-started")
    }

    fun usbControllerStopped() {
        debug("usb:controller-stopped")
    }

    fun usbRefreshIgnored() {
        debug("usb:refresh ignored=not-started")
    }

    fun usbPermissionResult(isGranted: Boolean) {
        debug("usb:permission-result granted=" + isGranted)
    }

    fun usbDeviceAttached() {
        debug("usb:device-attached")
    }

    fun usbDeviceDetached() {
        debug("usb:device-detached")
    }

    fun usbReadersRefreshed(
        deviceCount: Int,
        hasCcidReader: Boolean,
        hasPermission: Boolean?,
    ) {
        debug(
            "usb:refresh devices=" + deviceCount +
                " ccid=" + hasCcidReader +
                " permission=" + (hasPermission ?: "none"),
        )
    }

    fun usbPermissionRequestWithoutReader() {
        debug("usb:permission-request ignored=no-reader")
    }

    fun usbPermissionAlreadyGranted() {
        debug("usb:permission-request ignored=already-granted")
    }

    fun usbPermissionRequested() {
        debug("usb:permission-requested")
    }

    fun usbPermissionRequestFailed() {
        debug("usb:permission-request-failed")
    }

    fun usbSessionOpenStarted() {
        debug("usb:session-open-started")
    }

    fun usbSessionOpenCompleted(result: CcidSessionOpenResult) {
        debug("usb:session-open-completed result=" + result)
    }

    fun usbSessionOpenResultDiscarded() {
        debug("usb:session-open-result-discarded")
    }

    fun usbSnapshotPublished(
        status: ReaderConnectionStatus,
        cardPresence: CardPresence?,
    ) {
        debug(
            "usb:snapshot status=" + status +
                " card=" + (cardPresence ?: "unknown"),
        )
    }

    fun usbCardRemoved() {
        debug("usb:card-removed")
    }

    fun nfcAdapterMissing() {
        debug("nfc:adapter-missing")
    }

    fun nfcAdapterStateChanged() {
        debug("nfc:adapter-state-changed")
    }

    fun nfcReaderModeChanged(isEnabled: Boolean) {
        debug("nfc:reader-mode enabled=" + isEnabled)
    }

    fun nfcTagDiscovered(isIsoDep: Boolean) {
        debug("nfc:tag-discovered iso-dep=" + isIsoDep)
    }

    fun nfcSessionOpenFailed() {
        debug("nfc:session-open-failed")
    }

    fun nfcSessionClosed() {
        debug("nfc:session-closed")
    }

    fun nfcTagLost() {
        debug("nfc:tag-lost")
    }

    fun nfcTransceiveFailed() {
        debug("nfc:transceive-failed")
    }

    /**
     * One ISO-DEP exchange. The APDU header (CLA/INS/P1/P2) is public
     * routing data and is logged; command/response bodies never are, so a
     * CAN, PIN, or certificate body can never reach the trace. A negative
     * header byte means the command was shorter than a header.
     */
    fun nfcTransceive(
        commandLength: Int,
        responseLength: Int,
        durationMicros: Long,
        sw: Int = 0,
        cla: Int = -1,
        ins: Int = -1,
        p1: Int = -1,
        p2: Int = -1,
    ) {
        val header =
            if (cla < 0 || ins < 0 || p1 < 0 || p2 < 0) {
                "header=short"
            } else {
                "cla=" + hexByte(cla) +
                    " ins=" + hexByte(ins) +
                    " p1=" + hexByte(p1) +
                    " p2=" + hexByte(p2)
            }
        val swString = if (sw != 0) " sw=" + hexStatus(sw) else ""
        debug(
            "nfc:transceive " + header +
                " cmd=" + commandLength +
                " rsp=" + responseLength +
                swString +
                " us=" + durationMicros,
        )
    }

    fun nfcProbeResultDiscarded() {
        debug("nfc:probe-result-discarded")
    }

    fun nfcSnapshotPublished(status: NfcReaderStatus) {
        debug("nfc:snapshot status=" + status)
    }

    fun nfcSettingsUnavailable() {
        debug("nfc:settings-unavailable")
    }

    fun documentValidationStarted() {
        debug("document:validation-started")
    }

    fun documentValidationCompleted(read: Boolean) {
        debug("document:validation-completed read=" + read)
    }

    fun nfcConnectStarted() {
        debug("nfc:connect-started")
    }

    fun nfcConnectIgnored() {
        debug("nfc:connect ignored=not-recognized")
    }

    fun nfcTagAdopted() {
        debug("nfc:tag-adopted")
    }

    fun nfcPrimedOpenStarted() {
        debug("nfc:primed-open-started")
    }

    fun nfcPrimedMinted() {
        debug("nfc:primed-minted")
    }

    fun nfcPrimedForgotten() {
        debug("nfc:primed-forgotten")
    }

    fun nfcAwaitCardReady(
        isCardReady: Boolean,
        status: String,
        hasResting: Boolean,
    ) {
        debug("nfc:await-card-ready ready=" + isCardReady + " status=" + status + " resting=" + hasResting)
    }

    fun nfcOpenSessionStarted(
        hasTarget: Boolean,
        generation: Int,
        mintOnSuccess: Boolean,
    ) {
        debug("nfc:open-session-started target=" + hasTarget + " gen=" + generation + " mint=" + mintOnSuccess)
    }

    fun ccidEndpointsMissing() {
        debug("ccid:endpoints-missing")
    }

    fun ccidOpenFailed() {
        debug("ccid:open-failed")
    }

    fun ccidDescriptorRejected(
        kind: CcidDescriptorErrorKind,
        detail: String = "",
    ) {
        var line = "ccid:descriptor-rejected kind=" + kind
        if (detail.isNotEmpty()) {
            line += " " + detail
        }
        debug(line)
    }

    fun ccidDescriptorAccepted(
        level: CcidExchangeLevel,
        maximumMessageLength: Int,
        features: Long = 0L,
        interfaceNumber: Int = -1,
        vendorId: Int = -1,
        productId: Int = -1,
        productName: String? = null,
    ) {
        var line =
            "ccid:descriptor-accepted level=" + level +
                " max-message=" + maximumMessageLength
        if (features != 0L) {
            line += " features=" + features.toString(HEX_RADIX)
        }
        if (interfaceNumber >= 0) {
            line += " iface=" + interfaceNumber
        }
        if (vendorId >= 0 && productId >= 0) {
            line += " vid=" + hexShort(vendorId) + " pid=" + hexShort(productId)
        }
        if (!productName.isNullOrBlank()) {
            line += " reader=" + productName.take(READER_NAME_TRACE_LIMIT)
        }
        debug(line)
    }

    fun credentialHealth(health: CredentialHealth) {
        debug(
            "card:credential-health pin1=" + pinStateName(health.pin1State) +
                " pin2=" + health.pin2State +
                " puk=" + pinStateName(health.pukState) +
                " scheme=" + health.scheme +
                " activation-scheme=" + health.activationScheme +
                " needs-pin1=" + health.activationNeeds.pin1 +
                " needs-pin2=" + health.activationNeeds.pin2,
        )
    }

    fun ccidClaimFailed() {
        debug("ccid:claim-failed")
    }

    fun ccidSecurityFailure() {
        debug("ccid:security-failure")
    }

    fun ccidSessionClosed(interfaceReleased: Boolean) {
        debug("ccid:session-closed interface-released=" + interfaceReleased)
    }

    fun ccidSlotExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:slot-failed kind=" + kind)
    }

    fun ccidPowerExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:power-failed kind=" + kind)
    }

    fun ccidParameters(
        protocolNum: Int,
        dataHex: String,
    ) {
        debug("ccid:parameters protocol=" + protocolNum + " data=" + dataHex)
    }

    fun ccidParametersFailure(errorCode: Int) {
        debug("ccid:parameters-failure error=" + errorCode)
    }

    fun ccidParametersExchangeFailed(kind: CcidExchangeFailureKind) {
        debug("ccid:parameters-exchange-failed kind=" + kind)
    }

    fun ccidSetParametersResult(
        succeeded: Boolean,
        detail: String = "",
    ) {
        val extra = if (detail.isNotEmpty()) " " + detail else ""
        debug("ccid:set-parameters succeeded=" + succeeded + extra)
    }

    fun ccidPpsLinkCheck(alive: Boolean) {
        debug("ccid:pps-link-check alive=" + alive)
    }

    fun ccidCardState(state: CcidCardStatus) {
        debug("ccid:card-state " + state)
    }

    fun ccidCardRemovalDetected() {
        debug("ccid:card-removal-detected")
    }

    fun ccidCommandFailed(
        errorCode: Int,
        cardStatus: CcidCardStatus,
    ) {
        debug(
            "ccid:command-failed error=" + errorCode +
                " card=" + cardStatus,
        )
    }

    /**
     * The ATR is emitted by the card at reset before any application is
     * selected, so its hex is safe to log and identifies the card model.
     */
    fun ccidAtrResult(
        length: Int,
        validation: AtrValidation,
        isSupported: Boolean,
        atrHex: String = "",
    ) {
        var line =
            "ccid:atr length=" + length +
                " validation=" + validation +
                " supported=" + isSupported
        if (atrHex.isNotEmpty()) {
            line += " atr=" + atrHex
        }
        debug(line)
    }

    fun ccidTimeExtension(
        count: Int,
        multiplier: Int,
    ) {
        debug(
            "ccid:time-extension count=" + count +
                " multiplier=" + multiplier,
        )
    }

    /**
     * A CCID framing violation. Expected/actual carry the response message
     * type bytes when the kind is UNEXPECTED_MESSAGE_TYPE, otherwise -1.
     * Detail carries integers only (slots, sequences, status bytes,
     * lengths) — never response payloads.
     */
    fun ccidResponseRejected(
        kind: CcidProtocolErrorKind,
        expected: Int = -1,
        actual: Int = -1,
        frameLength: Int = -1,
        detail: String = "",
    ) {
        var line = "ccid:response-rejected kind=" + kind
        if (expected >= 0 && actual >= 0) {
            line += " expected=" + hexByte(expected) + " actual=" + hexByte(actual)
        }
        if (frameLength >= 0) {
            line += " frame-length=" + frameLength
        }
        if (detail.isNotEmpty()) {
            line += " " + detail
        }
        debug(line)
    }

    /**
     * One CCID command submitted to bulk out. Only the message type,
     * slot, sequence, and total length are logged — never block bytes,
     * which may carry a CAN, PIN, PUK, or activation code.
     */
    fun ccidExchangeStarted(
        messageType: Int,
        slot: Int,
        sequence: Int,
        length: Int,
    ) {
        debug(
            "ccid:exchange cmd=" + hexByte(messageType) +
                " slot=" + slot +
                " seq=" + sequence +
                " length=" + length,
        )
    }

    fun ccidCommandExchangeFailed(
        kind: CcidExchangeFailureKind,
        messageType: Int = -1,
        slot: Int = -1,
        sequence: Int = -1,
    ) {
        var line = "ccid:exchange-failed kind=" + kind
        if (messageType >= 0) {
            line += " cmd=" + hexByte(messageType) + " slot=" + slot + " seq=" + sequence
        }
        debug(line)
    }

    /**
     * One bulk transfer outcome. Counts only: a short or negative
     * transfer distinguishes a timeout from a framing violation.
     */
    fun ccidBulkTransfer(
        direction: String,
        requested: Int,
        transferred: Int,
    ) {
        debug(
            "ccid:bulk dir=" + direction +
                " requested=" + requested +
                " transferred=" + transferred,
        )
    }

    /** USB interface survey before claiming: which interfaces are CCID. */
    fun ccidUsbSurvey(
        interfaceCount: Int,
        ccidCount: Int,
    ) {
        debug(
            "ccid:usb-survey interfaces=" + interfaceCount +
                " ccid=" + ccidCount,
        )
    }

    /** Bulk endpoint packet sizes of one claimed CCID interface. */
    fun ccidEndpoints(
        interfaceNumber: Int,
        bulkInMaxPacketSize: Int,
        bulkOutMaxPacketSize: Int,
        interruptInMaxPacketSize: Int?,
    ) {
        debug(
            "ccid:endpoints iface=" + interfaceNumber +
                " in-max=" + bulkInMaxPacketSize +
                " out-max=" + bulkOutMaxPacketSize +
                " interrupt-max=" + interruptInMaxPacketSize,
        )
    }

    /** The holder was prompted to present the card (Apple-sheet equivalent). */
    fun nfcAwaitingCard() {
        debug("nfc:awaiting-card")
    }

    /**
     * A power-on answered with a data block the activator rejects:
     * card/chain state plus ATR length. The ATR bytes themselves stay
     * out — an over-long payload may carry more than reset bytes.
     */
    fun ccidPowerResult(
        cardStatus: CcidCardStatus,
        chainParameter: String,
        payloadLength: Int,
    ) {
        debug(
            "ccid:power-result card=" + cardStatus +
                " chain=" + chainParameter +
                " payload-length=" + payloadLength,
        )
    }

    fun cardPublicCommandStarted(
        classByte: Int,
        instruction: Int,
        parameterOne: Int,
        parameterTwo: Int,
        commandLength: Int,
    ): Long =
        System.nanoTime().also {
            debug(
                "card:public tx cla=" + hexByte(classByte) +
                    " ins=" + hexByte(instruction) +
                    " p1=" + hexByte(parameterOne) +
                    " p2=" + hexByte(parameterTwo) +
                    " length=" + commandLength,
            )
        }

    fun cardPublicMalformedCommandStarted(commandLength: Int): Long =
        System.nanoTime().also {
            debug("card:public tx malformed length=" + commandLength)
        }

    fun cardPublicCommandResponded(
        startedAt: Long,
        statusWord: Int,
        responseBodyLength: Int,
    ) {
        debug(
            "card:public rx sw=" + hexStatus(statusWord) +
                " body-length=" + responseBodyLength +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardPublicCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:public failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardSensitiveCommandStarted(): Long =
        System.nanoTime().also {
            debug("card:sensitive tx redacted")
        }

    fun cardSensitiveCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) {
        debug(
            "card:sensitive rx sw=" + hexStatus(statusWord) +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardSensitiveCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:sensitive failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardCredentialCommandStarted(): Long =
        System.nanoTime().also {
            debug("card:credential tx redacted")
        }

    fun cardCredentialCommandResponded(
        startedAt: Long,
        statusWord: Int,
    ) {
        debug(
            "card:credential rx sw=" + hexStatus(statusWord) +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    fun cardCredentialCommandFailed(
        startedAt: Long,
        kind: CcidBlockFailureKind,
    ) {
        debug(
            "card:credential failed kind=" + kind +
                " duration-us=" + elapsedMicroseconds(startedAt),
        )
    }

    private fun elapsedMicroseconds(startedAt: Long): Long =
        (System.nanoTime() - startedAt).coerceAtLeast(0) / NANOSECONDS_PER_MICROSECOND

    private fun hexByte(value: Int): String =
        value.and(UNSIGNED_BYTE_MASK).toString(HEX_RADIX).padStart(BYTE_HEX_DIGITS, '0')

    private fun hexShort(value: Int): String =
        value.and(UNSIGNED_SHORT_MASK).toString(HEX_RADIX).padStart(HEX_DIGITS_SHORT, '0')

    private fun hexStatus(value: Int): String =
        value.and(UNSIGNED_SHORT_MASK).toString(HEX_RADIX).padStart(STATUS_HEX_DIGITS, '0')

    private fun pinStateName(state: NativePin1State): String =
        when (state) {
            NativePin1State.Verified -> "verified"
            is NativePin1State.Remaining -> "remaining-" + state.attempts
            NativePin1State.Locked -> "locked"
            NativePin1State.NoInformation -> "no-info"
            NativePin1State.Unrecognized -> "unrecognized"
        }

    fun uncaughtException(
        thread: Thread,
        throwable: Throwable,
    ) {
        try {
            Log.e(TAG, "FATAL EXCEPTION in thread " + thread.name, throwable)
        } catch (_: RuntimeException) {
            // Local JVM tests
        }
    }

    private const val MAX_TRACE_LINES = 500
    private const val READER_NAME_TRACE_LIMIT = 48
    private val traceLogBuffer = ArrayDeque<String>(MAX_TRACE_LINES)

    fun getTraceLog(): List<String> =
        synchronized(traceLogBuffer) {
            traceLogBuffer.toList()
        }

    fun clearTraceLog(): Unit =
        synchronized(traceLogBuffer) {
            traceLogBuffer.clear()
        }

    /**
     * Every trace line carries a wall-clock timestamp so a pasted report
     * stays self-describing; the app version is logged at session start
     * (see [activityCreated]).
     */
    private fun debug(message: String) {
        val line = timestampPrefix() + " " + message
        synchronized(traceLogBuffer) {
            if (traceLogBuffer.size >= MAX_TRACE_LINES) {
                traceLogBuffer.removeFirst()
            }
            traceLogBuffer.addLast(line)
        }
        try {
            Log.d(TAG, message)
        } catch (_: RuntimeException) {
            // Local JVM tests use the Android stub; a device implementation logs.
        }
    }

    private fun timestampPrefix(): String = UTC_TRACE_FORMAT.format(java.time.Instant.now())

    private val UTC_TRACE_FORMAT =
        java.time.format.DateTimeFormatter
            .ofPattern("MM-dd HH:mm:ss.SSS'Z'")
            .withZone(java.time.ZoneOffset.UTC)

    private const val TAG = "RefineID"
    private const val HEX_RADIX = 16
    private const val BYTE_HEX_DIGITS = 2
    private const val HEX_DIGITS_SHORT = 4
    private const val STATUS_HEX_DIGITS = 4
    private const val UNSIGNED_BYTE_MASK = 0xFF
    private const val UNSIGNED_SHORT_MASK = 0xFFFF
    private const val NANOSECONDS_PER_MICROSECOND = 1_000L
}
