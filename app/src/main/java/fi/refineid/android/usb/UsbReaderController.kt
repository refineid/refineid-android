package fi.refineid.android.usb

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardPhotoStore
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.NativeVerification
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.keychain.nextProviderGeneration
import fi.refineid.android.usb.ccid.CcidSessionOpenResult
import fi.refineid.android.usb.ccid.CcidUsbSession
import fi.refineid.android.usb.ccid.CcidUsbSessionOpener
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import kotlin.coroutines.resume

internal enum class ReaderConnectionStatus {
    NOT_CONNECTED,
    PERMISSION_REQUIRED,
    CHECKING,
    READY,
    PERMISSION_REQUEST_FAILED,
    CARD_ERROR,
    TRANSPORT_ERROR,

    /** A contactless card sits on the reader; PACE needs the access number. */
    ACCESS_NUMBER_REQUIRED,

    /** The entered access number did not open the contactless card. */
    WRONG_ACCESS_NUMBER,

    /** The card sits on the reader and requires factory activation. */
    ACTIVATION_REQUIRED,
}

internal enum class CardPresence {
    PRESENT,
    NOT_PRESENT,
}

internal enum class AuthenticationStatus {
    IDLE,
    SIGNING,
    SUCCEEDED,
    WRONG_PIN,
    PIN_LOCKED,
    REFUSED,
    ERROR,
}

internal data class UsbReaderInfo(
    val deviceId: Int,
    val name: String,
    val isSelected: Boolean = false,
    val hasPermission: Boolean = false,
    val cardPresence: CardPresence? = null,
    val holderName: String? = null,
    val isActivationRequired: Boolean = false,
)

internal data class UsbReaderSnapshot(
    val status: ReaderConnectionStatus = ReaderConnectionStatus.NOT_CONNECTED,
    val cardPresence: CardPresence? = null,
    val authenticationStatus: AuthenticationStatus = AuthenticationStatus.IDLE,
    val holderName: String? = null,
    val cardDetails: PersonCardDetails? = null,
    val availableReaders: List<UsbReaderInfo> = emptyList(),
)

@Suppress("TooManyFunctions")
internal class UsbReaderController(
    context: Context,
) : AuthenticationCardService {
    private val applicationContext = context.applicationContext
    private val usbManager =
        requireNotNull(applicationContext.getSystemService(UsbManager::class.java))
    private val permissionAction =
        applicationContext.packageName + ".action.USB_PERMISSION"
    private val ccidSessionOpener =
        CcidUsbSessionOpener(
            usbManager = usbManager,
            validateAtr = NativeCore::validateAtr,
        )
    private val mainHandler = Handler(Looper.getMainLooper())
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val providerGenerationRandom = SecureRandom()
    private val stateListeners = linkedSetOf<(UsbReaderSnapshot) -> Unit>()

    @Volatile
    private var isStarted = false
    private var selectedDevice: UsbDevice? = null
    private var preferredDeviceId: Int? = null

    @Volatile
    private var latestSnapshot = UsbReaderSnapshot()

    @Volatile
    private var probeGeneration = 0

    private val cardPresencePollRunnable: Runnable =
        Runnable {
            if (isStarted) {
                val device = selectedDevice
                if (device != null && usbManager.hasPermission(device)) {
                    if (latestSnapshot.authenticationStatus == AuthenticationStatus.SIGNING) {
                        mainHandler.postDelayed(cardPresencePollRunnable, CARD_POLL_INTERVAL_MILLISECONDS)
                        return@Runnable
                    }
                    if (latestSnapshot.cardPresence != CardPresence.PRESENT) {
                        beginSessionOpen(device, probeGeneration)
                    } else if (activeSession?.hasInterruptEndpoint != true) {
                        checkCardPresence(device, probeGeneration)
                    }
                }
            }
        }

    // Worker-thread confined. Main-thread state never owns a USB connection.
    private var activeSession: CcidUsbSession? = null
    private var activeProviderGeneration: Long? = null

    internal val externalKeyCardSession =
        UsbExternalKeyCardSession(
            ioExecutor = ioExecutor,
            isAvailable = {
                isStarted &&
                    latestSnapshot.status == ReaderConnectionStatus.READY &&
                    latestSnapshot.cardPresence == CardPresence.PRESENT
            },
            activeSession = { activeSession },
            activeProviderGeneration = { activeProviderGeneration },
        )

    internal val qualifiedCardService =
        UsbQualifiedCardService(
            ioExecutor = ioExecutor,
            mainHandler = mainHandler,
            isReady = {
                isStarted &&
                    latestSnapshot.status == ReaderConnectionStatus.READY &&
                    latestSnapshot.cardPresence == CardPresence.PRESENT
            },
            currentGeneration = { probeGeneration },
            isCurrentGeneration = { generation ->
                isStarted && generation == probeGeneration
            },
            activeSession = { activeSession },
        )

    internal val cardManagementService =
        UsbCardManagementService(
            ioExecutor = ioExecutor,
            mainHandler = mainHandler,
            isReady = {
                isStarted &&
                    (
                        latestSnapshot.status == ReaderConnectionStatus.READY ||
                            latestSnapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED
                    ) &&
                    latestSnapshot.cardPresence == CardPresence.PRESENT
            },
            currentGeneration = { probeGeneration },
            isCurrentGeneration = { generation ->
                isStarted && generation == probeGeneration
            },
            activeSession = { activeSession },
        )

    private val permissionReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                if (intent?.action == permissionAction) {
                    AppTrace.usbPermissionResult(
                        isGranted =
                            intent.getBooleanExtra(
                                UsbManager.EXTRA_PERMISSION_GRANTED,
                                false,
                            ),
                    )
                    refresh()
                }
            }
        }

    private val usbEventReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                when (intent?.action) {
                    UsbManager.ACTION_USB_DEVICE_ATTACHED -> {
                        AppTrace.usbDeviceAttached()
                        refresh()
                    }

                    UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                        AppTrace.usbDeviceDetached()
                        refresh()
                    }
                }
            }
        }

    fun start() {
        if (isStarted) {
            AppTrace.usbControllerStartIgnored()
            return
        }

        applicationContext.registerReceiver(
            permissionReceiver,
            IntentFilter(permissionAction),
            Context.RECEIVER_NOT_EXPORTED,
        )

        val usbEventFilter =
            IntentFilter().apply {
                addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED)
                addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
            }
        applicationContext.registerReceiver(
            usbEventReceiver,
            usbEventFilter,
            Context.RECEIVER_EXPORTED,
        )

        isStarted = true
        AppTrace.usbControllerStarted()
        refresh()
    }

    fun addStateListener(listener: (UsbReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners += listener
        listener(latestSnapshot)
    }

    fun removeStateListener(listener: (UsbReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners -= listener
    }

    val snapshot: UsbReaderSnapshot
        get() = latestSnapshot

    val isCardReady: Boolean
        get() =
            isStarted &&
                latestSnapshot.status == ReaderConnectionStatus.READY &&
                latestSnapshot.cardPresence == CardPresence.PRESENT

    suspend fun awaitCardReady(timeoutMs: Long = 30_000L): Boolean {
        if (isCardReady) {
            return true
        }
        val storedCan = CanSessionStore.currentCan
        if (
            storedCan != null &&
            (
                latestSnapshot.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                    latestSnapshot.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
            )
        ) {
            mainHandler.post {
                connect(CanSubmission.from(storedCan))
            }
        }
        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine { continuation ->
                lateinit var listener: (UsbReaderSnapshot) -> Unit
                listener = { snapshot ->
                    if (
                        isStarted &&
                        snapshot.status == ReaderConnectionStatus.READY &&
                        snapshot.cardPresence == CardPresence.PRESENT &&
                        continuation.isActive
                    ) {
                        removeStateListener(listener)
                        continuation.resume(true)
                    }
                }
                mainHandler.post { addStateListener(listener) }
                continuation.invokeOnCancellation {
                    mainHandler.post { removeStateListener(listener) }
                }
            }
        } ?: false
    }

    fun stop() {
        if (!isStarted) {
            AppTrace.usbControllerStopIgnored()
            return
        }

        applicationContext.unregisterReceiver(permissionReceiver)
        applicationContext.unregisterReceiver(usbEventReceiver)
        isStarted = false
        mainHandler.removeCallbacks(cardPresencePollRunnable)
        probeGeneration += 1
        ioExecutor.execute(::closeActiveSession)
        ioExecutor.shutdown()
        AppTrace.usbControllerStopped()
    }

    fun selectDevice(deviceId: Int) {
        checkMainThread()
        if (preferredDeviceId == deviceId && selectedDevice?.deviceId == deviceId) {
            return
        }
        preferredDeviceId = deviceId
        refresh()
    }

    fun refresh() {
        if (!isStarted) {
            AppTrace.usbRefreshIgnored()
            return
        }
        probeGeneration += 1
        val devices = usbManager.deviceList.values.toList()
        val descriptors = devices.map { device -> device.toDescriptor() }
        val allMatches = CcidReaderClassifier.classifyAll(descriptors)
        val ccidDevices = devices.filter { dev -> allMatches.any { it.deviceId == dev.deviceId } }
        val match = CcidReaderClassifier.selectPreferred(descriptors, preferredDeviceId)
        selectedDevice = ccidDevices.firstOrNull { it.deviceId == match?.deviceId }

        val device = selectedDevice
        AppTrace.usbReadersRefreshed(
            deviceCount = devices.size,
            hasCcidReader = match != null && device != null,
            hasPermission = device?.let(usbManager::hasPermission),
        )
        publish(
            when {
                device == null || match == null -> {
                    closeActiveSessionAsync()
                    UsbReaderSnapshot()
                }

                usbManager.hasPermission(device) -> {
                    beginSessionOpen(device, probeGeneration)
                    return
                }

                else -> {
                    closeActiveSessionAsync()
                    requestPermission(device)
                    UsbReaderSnapshot(
                        status = ReaderConnectionStatus.PERMISSION_REQUIRED,
                    )
                }
            },
        )
    }

    fun requestPermission(targetDevice: UsbDevice? = null) {
        val device =
            targetDevice
                ?: selectedDevice
                ?: run {
                    AppTrace.usbPermissionRequestWithoutReader()
                    return
                }
        if (usbManager.hasPermission(device)) {
            AppTrace.usbPermissionAlreadyGranted()
            if (targetDevice != null && targetDevice.deviceId != selectedDevice?.deviceId) {
                selectDevice(targetDevice.deviceId)
            } else {
                refresh()
            }
            return
        }

        val permissionIntent =
            Intent(permissionAction).setPackage(applicationContext.packageName)
        val pendingIntent =
            PendingIntent.getBroadcast(
                applicationContext,
                USB_PERMISSION_REQUEST_CODE,
                permissionIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

        try {
            AppTrace.usbPermissionRequested()
            usbManager.requestPermission(device, pendingIntent)
        } catch (_: SecurityException) {
            AppTrace.usbPermissionRequestFailed()
            publish(
                latestSnapshot.copy(
                    status = ReaderConnectionStatus.PERMISSION_REQUEST_FAILED,
                ),
            )
        }
    }

    fun authenticate(pin1: Pin1Submission) {
        if (
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            pin1.close()
            AppTrace.authenticationRequestIgnored()
            return
        }
        val generation = probeGeneration
        publish(
            latestSnapshot.copy(
                authenticationStatus = AuthenticationStatus.SIGNING,
            ),
        )
        AppTrace.authenticationRequestStarted()
        ioExecutor.execute {
            if (!isStarted || generation != probeGeneration) {
                pin1.close()
                return@execute
            }
            val message = DIAGNOSTIC_AUTHENTICATION_MESSAGE.encodeToByteArray()
            val result =
                activeSession?.authenticateAndSignWithDiagnosticAlgorithm(
                    pin1 = pin1,
                    message = message,
                ) ?: run {
                    pin1.close()
                    AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
                }
            message.fill(0)
            val status = result.toAuthenticationStatus()
            if (result is AuthenticationSignResult.Success) {
                result.signature.close()
            }
            AppTrace.authenticationRequestCompleted(status)
            mainHandler.post {
                if (isStarted && generation == probeGeneration) {
                    publish(
                        latestSnapshot.copy(
                            authenticationStatus = status,
                        ),
                    )
                }
            }
        }
    }

    /**
     * Run PACE with the entered access number on the held contactless
     * session, opening the card once. On success the session is retained
     * under secure messaging so the browser and diagnostic signs reuse it
     * without a second handshake; a wrong access number stays on the CAN
     * prompt for retry.
     */
    @Suppress("CyclomaticComplexMethod")
    fun connect(
        can: CanSubmission,
        onPhotoRead: ((ByteArray?) -> Unit)? = null,
    ) {
        val cardAwaitsAccessNumber =
            latestSnapshot.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                latestSnapshot.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        // A plain contact session is already open without PACE; the access
        // number re-opens it under PACE so the eMRTD face photo can be read.
        val cardIsOpenWithoutPace =
            (
                latestSnapshot.status == ReaderConnectionStatus.READY ||
                    latestSnapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED
            ) && latestSnapshot.cardPresence == CardPresence.PRESENT
        if (!isStarted || (!cardAwaitsAccessNumber && !cardIsOpenWithoutPace)) {
            can.close()
            AppTrace.usbContactlessConnectIgnored()
            onPhotoRead?.invoke(null)
            return
        }
        // An identity already read on this session stays valid even when
        // the PACE pass fails; only a card change may replace it.
        val previousHolderName = latestSnapshot.holderName
        val previousCardDetails = latestSnapshot.cardDetails
        val generation = probeGeneration
        publish(
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.CHECKING,
                cardPresence = CardPresence.PRESENT,
            ),
        )
        AppTrace.usbContactlessConnectStarted()
        ioExecutor.execute {
            if (!isStarted || generation != probeGeneration) {
                can.close()
                mainHandler.post { onPhotoRead?.invoke(null) }
                return@execute
            }
            can.peekDigits()?.let {
                CanSessionStore.remember(it)
            }
            val canBytes = can.transfer()
            val result =
                activeSession?.openContactless(canBytes) ?: run {
                    canBytes.fill(0)
                    NativeContactlessOpenResult.Failure(
                        NativeCertificateReadFailure.CARD_UNAVAILABLE,
                    )
                }
            if (result is NativeContactlessOpenResult.Success) {
                activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
            }
            val photoBytes = NativeCore.readCardFacePhoto()
            val documentNumber = NativeCore.readCardDocumentNumber()
            val tamperProofVerified = NativeVerification.readCardVerificationPassed()
            val certificate =
                when (result) {
                    is NativeContactlessOpenResult.Success -> result.certificate
                    is NativeContactlessOpenResult.ActivationRequired -> result.certificate
                    is NativeContactlessOpenResult.Failure -> null
                }
            val holderNameFromCert = certificate?.let(CertificateHolderName::fromCertificate)
            var cardDetails: PersonCardDetails? = null
            val holder =
                if (certificate != null) {
                    try {
                        cardDetails =
                            PersonCardDetails.fromDer(
                                certificate.copyDer(),
                                photoBytes,
                                documentNumber,
                                tamperProofVerified,
                            )
                        cardDetails?.holderName ?: holderNameFromCert
                    } catch (_: Exception) {
                        holderNameFromCert
                    }
                } else {
                    null
                }
            val effectiveHolder = holder ?: holderNameFromCert ?: previousHolderName
            if (photoBytes != null && photoBytes.isNotEmpty()) {
                CardPhotoStore.savePhoto(photoBytes, effectiveHolder, documentNumber)
            }
            val snapshot =
                when (result) {
                    is NativeContactlessOpenResult.Success -> {
                        UsbReaderSnapshot(
                            status = ReaderConnectionStatus.READY,
                            cardPresence = CardPresence.PRESENT,
                            holderName = effectiveHolder,
                            cardDetails = cardDetails ?: previousCardDetails,
                        )
                    }

                    is NativeContactlessOpenResult.ActivationRequired -> {
                        UsbReaderSnapshot(
                            status = ReaderConnectionStatus.ACTIVATION_REQUIRED,
                            cardPresence = CardPresence.PRESENT,
                            holderName = effectiveHolder,
                            cardDetails = cardDetails ?: previousCardDetails,
                        )
                    }

                    is NativeContactlessOpenResult.Failure -> {
                        val status = result.kind.toContactlessConnectStatus()
                        if (status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER) {
                            val canDigits = can.peekDigits()
                            CanSessionStore.recordRejected(canDigits)
                        }
                        UsbReaderSnapshot(
                            status = status,
                            cardPresence = CardPresence.PRESENT,
                            holderName = previousHolderName,
                            cardDetails = previousCardDetails,
                        )
                    }
                }
            AppTrace.usbContactlessConnectCompleted(
                result is NativeContactlessOpenResult.Success ||
                    result is NativeContactlessOpenResult.ActivationRequired,
            )
            mainHandler.post {
                if (isStarted && generation == probeGeneration) {
                    publish(snapshot)
                    onPhotoRead?.invoke(photoBytes)
                } else {
                    onPhotoRead?.invoke(null)
                }
            }
        }
    }

    /**
     * Read the face photo on demand via PACE if CAN is known.
     */
    fun readPhoto(onResult: (ByteArray?) -> Unit) {
        val existingPhoto =
            latestSnapshot.cardDetails?.photoBytes
                ?: latestSnapshot.holderName?.let(CardPhotoStore::getPhoto)
        if (existingPhoto != null) {
            onResult(existingPhoto)
            return
        }
        val storedCan = CanSessionStore.currentCan
        if (storedCan != null && activeSession != null && isStarted) {
            connect(CanSubmission.from(storedCan), onResult)
        } else {
            mainHandler.post { onResult(null) }
        }
    }

    /** Copies the public leaf while preserving session thread confinement. */
    override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
        if (
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            onResult(null)
            return
        }
        val generation = probeGeneration
        try {
            ioExecutor.execute {
                val certificate =
                    if (isStarted && generation == probeGeneration) {
                        try {
                            activeSession?.copyAuthenticationCertificate()
                        } catch (_: IllegalStateException) {
                            null
                        }
                    } else {
                        null
                    }
                mainHandler.post {
                    if (isStarted && generation == probeGeneration) {
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

    /** Blocks a browser crypto worker while one card operation runs on the USB owner thread. */
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
        if (
            Looper.myLooper() == Looper.getMainLooper() ||
            !isStarted ||
            latestSnapshot.status != ReaderConnectionStatus.READY ||
            latestSnapshot.cardPresence != CardPresence.PRESENT
        ) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        val generation = probeGeneration
        val completion = CompletableFuture<AuthenticationSignResult>()
        try {
            ioExecutor.execute {
                val result =
                    try {
                        if (isStarted && generation == probeGeneration) {
                            activeSession?.let { session ->
                                when (inputMode) {
                                    AuthenticationSigningInputMode.MESSAGE -> {
                                        session.authenticateAndSign(
                                            algorithm = algorithm,
                                            pin1 = pin1,
                                            message = input,
                                        )
                                    }

                                    AuthenticationSigningInputMode.PREHASHED -> {
                                        session.authenticateAndSignPrehashed(
                                            algorithm = algorithm,
                                            pin1 = pin1,
                                            digest = input,
                                        )
                                    }
                                }
                            } ?: run {
                                pin1.close()
                                AuthenticationSignResult.Failure(
                                    AuthenticationSignFailure.CARD_UNAVAILABLE,
                                )
                            }
                        } else {
                            pin1.close()
                            AuthenticationSignResult.Failure(
                                AuthenticationSignFailure.CARD_UNAVAILABLE,
                            )
                        }
                    } catch (_: RuntimeException) {
                        pin1.close()
                        AuthenticationSignResult.Failure(
                            AuthenticationSignFailure.BRIDGE_ERROR,
                        )
                    }
                completion.complete(result)
            }
        } catch (_: RejectedExecutionException) {
            pin1.close()
            return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
        }
        return completion.awaitPreservingInterrupt()
    }

    private fun beginSessionOpen(
        device: UsbDevice,
        generation: Int,
    ) {
        mainHandler.removeCallbacks(cardPresencePollRunnable)
        AppTrace.usbSessionOpenStarted()
        publish(
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.CHECKING,
            ),
        )
        ioExecutor.execute {
            closeActiveSession()
            val result = ccidSessionOpener.open(device)
            var holder: String? = null
            var cardDetails: PersonCardDetails? = null
            if (result is CcidSessionOpenResult.Ready) {
                activeSession = result.session
                activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
                setupRemovalListener(result.session, device, generation)
                try {
                    val cert = result.session.copyAuthenticationCertificate()
                    try {
                        cardDetails = PersonCardDetails.fromDer(cert.copyDer())
                        holder = cardDetails?.holderName ?: CertificateHolderName.fromCertificate(cert)
                    } finally {
                        cert.close()
                    }
                } catch (_: Exception) {
                    // Fallback
                }
            } else if (result is CcidSessionOpenResult.AccessNumberRequired) {
                // Hold the contactless session so a CAN entry can run PACE on it.
                // No provider generation until connect() actually opens the card.
                activeSession = result.session
                setupRemovalListener(result.session, device, generation)
            } else if (result is CcidSessionOpenResult.ActivationRequired) {
                activeSession = result.session
                activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
                setupRemovalListener(result.session, device, generation)
                try {
                    val cert = result.session.copyAuthenticationCertificate()
                    try {
                        cardDetails = PersonCardDetails.fromDer(cert.copyDer())
                        holder = cardDetails?.holderName ?: CertificateHolderName.fromCertificate(cert)
                    } finally {
                        cert.close()
                    }
                } catch (_: Exception) {
                    // Fallback
                }
            }
            mainHandler.post {
                if (
                    isStarted &&
                    generation == probeGeneration &&
                    selectedDevice?.deviceId == device.deviceId
                ) {
                    AppTrace.usbSessionOpenCompleted(result)
                    publish(
                        when (result) {
                            is CcidSessionOpenResult.Ready -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.READY,
                                    cardPresence = CardPresence.PRESENT,
                                    holderName = holder,
                                    cardDetails = cardDetails,
                                )
                            }

                            is CcidSessionOpenResult.AccessNumberRequired -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                                    cardPresence = CardPresence.PRESENT,
                                )
                            }

                            is CcidSessionOpenResult.ActivationRequired -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.ACTIVATION_REQUIRED,
                                    cardPresence = CardPresence.PRESENT,
                                    holderName = holder,
                                    cardDetails = cardDetails,
                                )
                            }

                            CcidSessionOpenResult.NoCard -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.READY,
                                    cardPresence = CardPresence.NOT_PRESENT,
                                )
                            }

                            CcidSessionOpenResult.CardError -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.CARD_ERROR,
                                )
                            }

                            CcidSessionOpenResult.TransportError -> {
                                UsbReaderSnapshot(
                                    status = ReaderConnectionStatus.TRANSPORT_ERROR,
                                )
                            }
                        },
                    )
                    if (result is CcidSessionOpenResult.Ready ||
                        result is CcidSessionOpenResult.ActivationRequired
                    ) {
                        // A plain contact read never opens the eMRTD
                        // application: the face photo sits behind PACE. When
                        // the holder has already trusted this session with
                        // the card access number, fetch the photo once.
                        val storedCan = CanSessionStore.currentCan
                        if (
                            storedCan != null &&
                            holder != null &&
                            CardPhotoStore.getPhoto(holder) == null
                        ) {
                            connect(CanSubmission.from(storedCan))
                        }
                    } else if (result is CcidSessionOpenResult.AccessNumberRequired) {
                        // Contactless sessions on dual/contactless pads require
                        // the card access number (PACE) before card applications
                        // can be read. If CAN is already cached for this reader,
                        // unlock immediately without re-prompting.
                        val storedCan = CanSessionStore.currentCan
                        if (storedCan != null) {
                            connect(CanSubmission.from(storedCan))
                        }
                    }
                } else {
                    AppTrace.usbSessionOpenResultDiscarded()
                }
            }
        }
    }

    private fun checkCardPresence(
        device: UsbDevice,
        generation: Int,
    ) {
        ioExecutor.execute {
            if (!isStarted || generation != probeGeneration || selectedDevice?.deviceId != device.deviceId) {
                return@execute
            }
            val session = activeSession
            if (session == null) {
                mainHandler.post {
                    if (isStarted && generation == probeGeneration && selectedDevice?.deviceId == device.deviceId) {
                        publish(
                            UsbReaderSnapshot(
                                status = ReaderConnectionStatus.READY,
                                cardPresence = CardPresence.NOT_PRESENT,
                            ),
                        )
                    }
                }
                return@execute
            }
            val isPresent = session.isCardPresent()
            if (!isPresent) {
                closeActiveSession()
                mainHandler.post {
                    if (isStarted && generation == probeGeneration && selectedDevice?.deviceId == device.deviceId) {
                        publish(
                            UsbReaderSnapshot(
                                status = ReaderConnectionStatus.READY,
                                cardPresence = CardPresence.NOT_PRESENT,
                            ),
                        )
                    }
                }
            } else if (session.hasInterruptEndpoint != true) {
                mainHandler.post {
                    if (
                        isStarted &&
                        generation == probeGeneration &&
                        selectedDevice?.deviceId == device.deviceId &&
                        latestSnapshot.cardPresence == CardPresence.PRESENT
                    ) {
                        mainHandler.removeCallbacks(cardPresencePollRunnable)
                        mainHandler.postDelayed(cardPresencePollRunnable, CARD_POLL_INTERVAL_MILLISECONDS)
                    }
                }
            }
        }
    }

    private fun setupRemovalListener(
        session: CcidUsbSession,
        device: UsbDevice,
        generation: Int,
    ) {
        if (!session.hasInterruptEndpoint) {
            return
        }
        session.startRemovalListener {
            mainHandler.post {
                if (
                    !isStarted ||
                    generation != probeGeneration ||
                    selectedDevice?.deviceId != device.deviceId
                ) {
                    return@post
                }
                AppTrace.usbCardRemoved()
                closeActiveSessionAsync()
                publish(
                    UsbReaderSnapshot(
                        status = ReaderConnectionStatus.READY,
                        cardPresence = CardPresence.NOT_PRESENT,
                    ),
                )
            }
        }
    }

    private fun closeActiveSessionAsync() {
        ioExecutor.execute(::closeActiveSession)
    }

    private fun closeActiveSession() {
        activeProviderGeneration = null
        activeSession?.close()
        activeSession = null
    }

    private fun buildCurrentReaderInfos(snapshot: UsbReaderSnapshot): List<UsbReaderInfo> {
        val devices = usbManager.deviceList.values.toList()
        val descriptors = devices.map { it.toDescriptor() }
        val allMatches = CcidReaderClassifier.classifyAll(descriptors)
        val ccidDevices = devices.filter { dev -> allMatches.any { it.deviceId == dev.deviceId } }
        return ccidDevices.map { dev ->
            val isSelected = dev.deviceId == selectedDevice?.deviceId
            val name =
                dev.productName?.ifBlank { null }
                    ?: dev.manufacturerName?.let { "$it Smart Card Reader" }
                    ?: ("Smart Card Reader (" + dev.deviceId + ")")
            UsbReaderInfo(
                deviceId = dev.deviceId,
                name = name,
                isSelected = isSelected,
                hasPermission = usbManager.hasPermission(dev),
                cardPresence = if (isSelected) snapshot.cardPresence else null,
                holderName = if (isSelected) snapshot.holderName else null,
                isActivationRequired =
                    if (isSelected) {
                        snapshot.status == ReaderConnectionStatus.ACTIVATION_REQUIRED
                    } else {
                        false
                    },
            )
        }
    }

    private fun publish(snapshot: UsbReaderSnapshot) {
        val enrichedSnapshot =
            if (snapshot.availableReaders.isEmpty()) {
                snapshot.copy(availableReaders = buildCurrentReaderInfos(snapshot))
            } else {
                snapshot
            }
        latestSnapshot = enrichedSnapshot
        AppTrace.usbSnapshotPublished(
            status = enrichedSnapshot.status,
            cardPresence = enrichedSnapshot.cardPresence,
        )
        mainHandler.removeCallbacks(cardPresencePollRunnable)
        if (shouldPoll(enrichedSnapshot)) {
            mainHandler.postDelayed(cardPresencePollRunnable, CARD_POLL_INTERVAL_MILLISECONDS)
        }
        stateListeners.toList().forEach { listener -> listener(enrichedSnapshot) }
    }

    private fun shouldPoll(snapshot: UsbReaderSnapshot): Boolean {
        if (!isStarted || selectedDevice == null) {
            return false
        }
        val isPollableStatus =
            when (snapshot.status) {
                ReaderConnectionStatus.READY,
                ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                ReaderConnectionStatus.ACTIVATION_REQUIRED,
                ReaderConnectionStatus.CARD_ERROR,
                ReaderConnectionStatus.TRANSPORT_ERROR,
                -> true

                else -> false
            }
        if (!isPollableStatus) {
            return false
        }
        return snapshot.cardPresence != CardPresence.PRESENT ||
            activeSession?.hasInterruptEndpoint != true
    }

    private companion object {
        const val USB_PERMISSION_REQUEST_CODE = 0x5246
        const val CARD_POLL_INTERVAL_MILLISECONDS = 1000L
        const val DIAGNOSTIC_AUTHENTICATION_MESSAGE = "RefineID signing test"
    }
}

private fun checkMainThread() {
    check(Looper.myLooper() == Looper.getMainLooper()) {
        "USB reader listeners must be changed on the main thread"
    }
}

private fun UsbDevice.toDescriptor(): UsbDeviceDescriptor =
    UsbDeviceDescriptor(
        deviceId = deviceId,
        interfaces =
            List(interfaceCount) { index ->
                UsbInterfaceDescriptor(
                    interfaceClass = getInterface(index).interfaceClass,
                )
            },
    )

internal fun <T> CompletableFuture<T>.awaitPreservingInterrupt(): T {
    var wasInterrupted = false
    while (true) {
        try {
            return get()
        } catch (_: InterruptedException) {
            wasInterrupted = true
        } finally {
            if (isDone && wasInterrupted) {
                Thread.currentThread().interrupt()
            }
        }
    }
}

private fun AuthenticationSignResult.toAuthenticationStatus(): AuthenticationStatus =
    when (this) {
        is AuthenticationSignResult.Success -> {
            AuthenticationStatus.SUCCEEDED
        }

        is AuthenticationSignResult.Failure -> {
            when (kind) {
                AuthenticationSignFailure.WRONG_PIN -> AuthenticationStatus.WRONG_PIN

                AuthenticationSignFailure.PIN_LOCKED -> AuthenticationStatus.PIN_LOCKED

                AuthenticationSignFailure.SAFETY_REFUSED -> AuthenticationStatus.REFUSED

                AuthenticationSignFailure.CARD_UNAVAILABLE,
                AuthenticationSignFailure.TRANSPORT_ERROR,
                AuthenticationSignFailure.INVALID_PIN,
                AuthenticationSignFailure.VERIFICATION_REJECTED,
                AuthenticationSignFailure.SIGNING_REJECTED,
                AuthenticationSignFailure.KEY_PROFILE_MISMATCH,
                AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED,
                AuthenticationSignFailure.BRIDGE_ERROR,
                -> AuthenticationStatus.ERROR
            }
        }
    }

/** Coarse holder-facing status for one contactless connect attempt. */
private fun NativeCertificateReadFailure.toContactlessConnectStatus(): ReaderConnectionStatus =
    when (this) {
        NativeCertificateReadFailure.PACE_REJECTED -> {
            ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        }

        NativeCertificateReadFailure.CARD_UNAVAILABLE,
        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        -> {
            ReaderConnectionStatus.CARD_ERROR
        }

        NativeCertificateReadFailure.TRANSPORT_ERROR,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        -> {
            ReaderConnectionStatus.TRANSPORT_ERROR
        }

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> {
            ReaderConnectionStatus.ACTIVATION_REQUIRED
        }
    }
