package fi.refineid.android.nfc

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import fi.refineid.android.RefineIdApplication
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardPhotoStore
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardCa
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeContactlessSession
import fi.refineid.android.core.NativeCore
import fi.refineid.android.core.NativeVerification
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.keychain.nextProviderGeneration
import fi.refineid.android.prime.PrimedCanStore
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import kotlin.coroutines.resume

/**
 * Contactless discovery and card sessions bound to one foreground
 * activity. Reader mode delivers each discovered tag once; recognition
 * runs a credential-free EF.CardAccess probe, and a holder-entered CAN
 * opens a contactless session whose every operation re-runs PACE inside
 * one bounded ISO-DEP connection on a dedicated worker thread.
 */
@Suppress("TooManyFunctions", "LargeClass")
internal class NfcReaderController(
    context: Context,
    private val primedCanStore: PrimedCanStore,
    private val pinCache: AuthenticationPinCache,
) {
    private val applicationContext = context.applicationContext
    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(applicationContext)
    internal val hasNfc: Boolean get() = adapter != null
    private val mainHandler = Handler(Looper.getMainLooper())
    private val probeExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val stateListeners = linkedSetOf<(NfcReaderSnapshot) -> Unit>()

    @Volatile
    private var primedCardStored = primedCanStore.isPrimed()

    @Volatile
    private var rememberedHolderName: String? = if (primedCardStored) primedCanStore.readHolderName() else null

    @Volatile
    private var rememberedDetails: PersonCardDetails? =
        rememberedHolderName?.let { PersonCardDetails.fromHolderName(it) }

    @Volatile
    private var latestSnapshot =
        NfcReaderSnapshot(
            isPrimed = primedCardStored,
            holderName = rememberedHolderName,
            cardDetails = rememberedDetails,
        )

    @Volatile
    private var attachedActivity: Activity? = null

    @Volatile
    private var probeGeneration = 0

    /** Last ISO-DEP tag left resting in the field; worker-thread I/O only. */
    @Volatile
    private var latestIsoDep: IsoDep? = null

    /** Suppresses redundant recognition re-probes of a resting card. */
    private val reprobeThrottle = NfcReprobeThrottle()

    // Worker-thread confined. Main-thread state never owns a session.
    private var activeSession: ContactlessSession? = null
    private var activeProviderGeneration: Long? = null
    private val providerGenerationRandom = SecureRandom()

    @Volatile
    private var isOpeningSession = false

    @Volatile
    private var currentAuthCertDer: ByteArray? = null

    val currentAuthenticationCertificateDer: ByteArray?
        get() = currentAuthCertDer?.copyOf()

    private val feedback = NfcFeedback(applicationContext)

    // Tap-to-sign: a qualified signature waits for the holder to present
    // the card instead of requiring a pre-opened session. Confined to the
    // shared worker thread for session mutation; the transient session it
    // opens is the same one the qualified card service serves.
    internal val tapToSign =
        NfcTapToSign(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            latestIsoDep = { latestIsoDep },
            primedCan = { primedCanStore.read() },
            activeSession = { activeSession },
            adoptSession = { session -> activeSession = session },
            closeSession = { closeActiveSession() },
        )

    internal val authenticationCardService =
        NfcAuthenticationCardService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = { latestSnapshot.status == NfcReaderStatus.CARD_READY },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
            onCardLost = { generation ->
                val sessionWasActive = activeSession != null
                closeActiveSession()
                publishAsync(
                    generation,
                    NfcReaderStatus.WAITING_FOR_CARD,
                    awaitingCard = sessionWasActive,
                )
            },
        )

    internal val qualifiedCardService =
        NfcQualifiedCardService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = {
                latestSnapshot.status == NfcReaderStatus.CARD_READY || tapToSign.inProgress
            },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
        )

    internal val cardManagementService =
        NfcCardManagementService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = {
                latestSnapshot.status == NfcReaderStatus.CARD_READY ||
                    latestSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED
            },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
        )

    internal val externalKeyCardSession =
        NfcExternalKeyCardSession(
            probeExecutor = probeExecutor,
            isAvailable = { latestSnapshot.status == NfcReaderStatus.CARD_READY },
            activeSession = { activeSession },
            activeProviderGeneration = { activeProviderGeneration },
            onCardLost = {
                val generation = probeGeneration
                val sessionWasActive = activeSession != null
                closeActiveSession()
                publishAsync(
                    generation,
                    NfcReaderStatus.WAITING_FOR_CARD,
                    awaitingCard = sessionWasActive,
                )
            },
        )

    private val adapterStateReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                if (intent?.action == NfcAdapter.ACTION_ADAPTER_STATE_CHANGED) {
                    AppTrace.nfcAdapterStateChanged()
                    refreshReaderMode()
                }
            }
        }

    private val readerCallback =
        NfcAdapter.ReaderCallback { tag -> onTagDiscovered(tag) }

    fun attach(activity: Activity) {
        checkMainThread()
        attachedActivity = activity
        if (adapter == null) {
            AppTrace.nfcAdapterMissing()
            publish(NfcReaderSnapshot(status = NfcReaderStatus.NOT_AVAILABLE))
            return
        }
        applicationContext.registerReceiver(
            adapterStateReceiver,
            IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED),
            Context.RECEIVER_EXPORTED,
        )
        refreshReaderMode()
    }

    // The session outlives the activity: the privileged provider serves
    // a foreground browser while this app is stopped, so only adapter
    // loss, card loss, replacement, or process stop closes it.
    fun detach(activity: Activity) {
        checkMainThread()
        if (attachedActivity !== activity) {
            return
        }
        attachedActivity = null
        if (adapter != null) {
            applicationContext.unregisterReceiver(adapterStateReceiver)
            adapter.disableReaderMode(activity)
            AppTrace.nfcReaderModeChanged(isEnabled = false)
        }
    }

    fun stop() {
        probeGeneration += 1
        latestIsoDep = null
        tapToSign.cancel()
        probeExecutor.execute(::closeActiveSession)
        probeExecutor.shutdown()
    }

    fun addStateListener(listener: (NfcReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners += listener
        listener(latestSnapshot)
    }

    fun removeStateListener(listener: (NfcReaderSnapshot) -> Unit) {
        checkMainThread()
        stateListeners -= listener
    }

    val snapshot: NfcReaderSnapshot
        get() = latestSnapshot

    val isCardReady: Boolean
        get() = latestSnapshot.status == NfcReaderStatus.CARD_READY

    suspend fun awaitCardReady(timeoutMs: Long = 30_000L): Boolean {
        if (isCardReady) {
            return true
        }
        val resting = latestIsoDep
        AppTrace.nfcAwaitCardReady(
            isCardReady = false,
            status = latestSnapshot.status.name,
            hasResting = resting != null,
        )
        if (!isOpeningSession && resting != null) {
            val inMemoryCan = CanSessionStore.canBytes()
            val generation = probeGeneration
            isOpeningSession = true
            try {
                probeExecutor.execute {
                    val storedCan = inMemoryCan ?: primedCanStore.read()
                    if (storedCan == null) {
                        isOpeningSession = false
                        return@execute
                    }
                    openSessionBytes(
                        canBytes = storedCan,
                        generation = generation,
                        mintOnSuccess = false,
                        pin1 = null,
                        isoDepTarget = resting,
                    )
                }
            } catch (_: RejectedExecutionException) {
                isOpeningSession = false
            }
        }
        return withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine { continuation ->
                lateinit var listener: (NfcReaderSnapshot) -> Unit
                listener = { snapshot ->
                    if (snapshot.status == NfcReaderStatus.CARD_READY && continuation.isActive) {
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

    /**
     * Open a contactless session and hold PIN1 for the session. A
     * supplied access number is minted for tap-to-open; a null one
     * reuses the minted access number for a PIN-only unlock.
     */
    fun connect(
        can: CanSubmission?,
        pin1: Pin1Submission? = null,
    ) {
        checkMainThread()
        can?.let { CanSessionStore.remember(it) }
        val generation = probeGeneration
        val inMemoryCanBytes = can?.transfer() ?: CanSessionStore.canBytes()
        if (isCardReady && activeSession != null) {
            val candidateCan = can?.peekDigits()
            val currentCan = CanSessionStore.currentCan
            if (candidateCan == null || candidateCan == currentCan) {
                pin1?.copyBytes()?.let(pinCache::recordVerified)
                if (primedCardStored) {
                    pin1?.copyBytes()?.let(primedCanStore::writePin1)
                }
                pin1?.close()
                can?.close()
                inMemoryCanBytes?.fill(0)
                return
            }
        }
        // Guard against the no-card case to give immediate UI feedback, but do
        // not capture the handle: a reader-mode re-poll on the NFC callback
        // thread can replace latestIsoDep before the executor runs, so let
        // openSessionBytes read it at execution time instead.
        if (latestIsoDep == null) {
            inMemoryCanBytes?.fill(0)
            pin1?.copyBytes()?.let(pinCache::recordVerified)
            pin1?.close()
            refreshReaderMode()
            // The holder asked to connect with no tag in the field:
            // prompt for the card instead of waiting silently.
            publish(
                NfcReaderSnapshot(
                    status = NfcReaderStatus.WAITING_FOR_CARD,
                    awaitingCard = true,
                ),
            )
            return
        }
        publish(NfcReaderSnapshot(status = NfcReaderStatus.CONNECTING))
        AppTrace.nfcConnectStarted()
        isOpeningSession = true
        try {
            probeExecutor.execute {
                // primedCanStore.read() decrypts Android Keystore ciphertext;
                // it must run off the main thread — resolved here on the executor.
                val canBytes = inMemoryCanBytes ?: primedCanStore.read()
                if (canBytes == null) {
                    isOpeningSession = false
                    pin1?.close()
                    publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true)
                    return@execute
                }
                val mint = can != null || CanSessionStore.hasCan
                openSessionBytes(canBytes, generation, mintOnSuccess = mint, pin1 = pin1)
            }
        } catch (_: RejectedExecutionException) {
            isOpeningSession = false
            inMemoryCanBytes?.fill(0)
            pin1?.close()
        }
    }

    private fun refreshReaderMode() {
        checkMainThread()
        val activity = attachedActivity ?: return
        val nfcAdapter = adapter ?: return
        if (nfcAdapter.isEnabled) {
            nfcAdapter.enableReaderMode(
                activity,
                readerCallback,
                READER_MODE_FLAGS,
                null,
            )
            AppTrace.nfcReaderModeChanged(isEnabled = true)
            if (latestSnapshot.status != NfcReaderStatus.CARD_READY &&
                latestSnapshot.status != NfcReaderStatus.ACTIVATION_REQUIRED
            ) {
                probeGeneration += 1
                publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD))
            }
        } else {
            nfcAdapter.disableReaderMode(activity)
            AppTrace.nfcReaderModeChanged(isEnabled = false)
            probeGeneration += 1
            try {
                probeExecutor.execute(::closeActiveSession)
            } catch (_: RejectedExecutionException) {
                // The executor only stops when the process is terminating.
            }
            publish(NfcReaderSnapshot(status = NfcReaderStatus.TURNED_OFF))
        }
    }

    /** Reader-mode callback; arrives on an NFC system thread. */
    private fun onTagDiscovered(tag: Tag) {
        val generation = probeGeneration
        val isoDep = IsoDep.get(tag)
        AppTrace.nfcTagDiscovered(isIsoDep = isoDep != null)
        // The stack re-polls a resting card after each closed connection;
        // an open session survives that by adopting the fresh handle.
        // Card substitution is safe here: every operation starts with
        // PACE against the session CAN, so a different card fails the
        // handshake before any credential could reach it.
        val isSessionActive =
            latestSnapshot.status == NfcReaderStatus.CARD_READY ||
                latestSnapshot.status == NfcReaderStatus.ACTIVATION_REQUIRED
        if (isoDep == null) {
            if (!isSessionActive) {
                publishAsync(generation, NfcReaderStatus.CARD_NOT_SUPPORTED)
            }
            return
        }
        latestIsoDep = isoDep
        // A tap-to-sign in progress claims the tag before recognition, so
        // signing never depends on a card already resting in the field.
        if (tapToSign.inProgress) {
            feedback.onCardDiscovered()
            try {
                probeExecutor.execute {
                    tapToSign.onTag(isoDep)
                }
            } catch (_: RejectedExecutionException) {
                AppTrace.nfcProbeResultDiscarded()
            }
            return
        }
        if (isSessionActive) {
            try {
                probeExecutor.execute {
                    adoptRestingTag(isoDep, generation)
                }
            } catch (_: RejectedExecutionException) {
                AppTrace.nfcProbeResultDiscarded()
            }
            return
        }
        val storedCan = CanSessionStore.canBytes() ?: primedCanStore.read()
        if (storedCan != null) {
            feedback.onCardDiscovered()
            isOpeningSession = true
            try {
                probeExecutor.execute {
                    openSessionBytes(
                        canBytes = storedCan,
                        generation = generation,
                        mintOnSuccess = true,
                        pin1 = pinCache.take(),
                        isoDepTarget = isoDep,
                    )
                }
            } catch (_: RejectedExecutionException) {
                isOpeningSession = false
                AppTrace.nfcProbeResultDiscarded()
            }
            return
        }
        if (reprobeThrottle.shouldSkip(latestSnapshot.status)) {
            // The resting card is already recognized; the stack re-polls it
            // after every closed connection, so re-probing on each poll only
            // re-runs the public read to the same result. latestIsoDep above
            // stays fresh so a pending unlock uses the newest handle.
            return
        }
        feedback.onCardDiscovered()
        publishAsync(generation, NfcReaderStatus.CHECKING)
        try {
            probeExecutor.execute {
                probe(isoDep, generation)
            }
        } catch (_: RejectedExecutionException) {
            AppTrace.nfcProbeResultDiscarded()
        }
    }

    /** Worker-thread confined; the resting card was re-polled by the stack. */
    private fun adoptRestingTag(
        isoDep: IsoDep,
        generation: Int,
    ) {
        val session = activeSession
        if (session == null || generation != probeGeneration) {
            AppTrace.nfcProbeResultDiscarded()
            return
        }
        AppTrace.nfcTagAdopted()
        session.adopt(isoDep)
    }

    /**
     * Whether any holder intent is waiting on the card: a remembered
     * access number or a primed card means presenting the tag advances
     * a real operation, so losing it deserves a prompt. Pure idle
     * listening has neither and stays silent.
     */
    private fun wantsCard(): Boolean = CanSessionStore.hasCan || primedCardStored

    /** Worker-thread confined; owns the ISO-DEP connection. */
    private fun probe(
        isoDep: IsoDep,
        generation: Int,
    ) {
        reprobeThrottle.onProbe()
        closeActiveSession()
        if (generation != probeGeneration) {
            AppTrace.nfcProbeResultDiscarded()
            return
        }
        try {
            isoDep.connect()
            isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
        } catch (_: IOException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        } catch (_: SecurityException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        } catch (_: IllegalStateException) {
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        }
        val result =
            NativeContactlessCore.probeCardAccess(
                exchangeLevel = NativeCardExchangeLevel.APDU,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        if (result !is NativeCardAccessResult.Success) {
            try {
                isoDep.close()
            } catch (_: IOException) {
                // The tag may already be gone; the probe result stands.
            } catch (_: SecurityException) {
                // The tag handle is out of date.
            } catch (_: IllegalStateException) {
                // Tag service unavailable.
            }
            AppTrace.nfcSessionClosed()
        }
        // A primed card still needs PIN1 to unlock; the UI shows a
        // PIN-only prompt on this recognized state.
        publishAsync(generation, result.toReaderStatus())
    }

    private fun ensureIsoDepConnected(isoDep: IsoDep): Boolean =
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            }
            true
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: IllegalStateException) {
            false
        }

    private fun handleOpenSuccess(
        generation: Int,
        opened: NativeContactlessOpenResult.Success,
        canBytes: ByteArray,
        pin1: Pin1Submission?,
        mintOnSuccess: Boolean,
        isoDep: IsoDep,
        material: NativeCardSessionMaterial,
    ) {
        CanSessionStore.remember(String(canBytes, Charsets.US_ASCII))
        val (cardDetails, holderName) = extractCardDetails(opened)
        if (holderName != null) {
            rememberedHolderName = holderName
            rememberedDetails = cardDetails
        }
        val certDer = opened.certificate.copyDer()
        currentAuthCertDer = certDer.copyOf()
        val app = applicationContext as? RefineIdApplication
        val rootCa = NativeCardCa.readRootCaCertificate()
        if (rootCa != null) {
            app?.caCertificateStore?.saveCertificate(rootCa)
        }
        val intermediateCa = NativeCardCa.readIntermediateCaCertificate()
        if (intermediateCa != null) {
            app?.caCertificateStore?.saveCertificate(intermediateCa)
        }
        if (mintOnSuccess) {
            primedCanStore.write(canBytes.copyOf())
            primedCanStore.writeHolderName(holderName)
            primedCanStore.writeAuthCertificateDer(certDer)
            primedCardStored = true
            AppTrace.nfcPrimedMinted()
        } else if (primedCardStored) {
            if (holderName != null && primedCanStore.readHolderName() == null) {
                primedCanStore.writeHolderName(holderName)
            }
            primedCanStore.writeAuthCertificateDer(certDer)
        }
        pin1?.copyBytes()?.let(pinCache::recordVerified)
        if (mintOnSuccess || primedCardStored) {
            pin1?.copyBytes()?.let(primedCanStore::writePin1)
        }
        pin1?.close()
        activeSession =
            ContactlessSession(
                isoDep = isoDep,
                can = canBytes,
                material = material,
                heldSession = true,
            )
        activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
        feedback.onCardSuccess()
        publishAsync(generation, NfcReaderStatus.CARD_READY, holderName = holderName, cardDetails = cardDetails)
    }

    private fun handleOpenActivationRequired(
        generation: Int,
        opened: NativeContactlessOpenResult.ActivationRequired,
        canBytes: ByteArray,
        pin1: Pin1Submission?,
        isoDep: IsoDep,
        material: NativeCardSessionMaterial,
    ) {
        CanSessionStore.remember(String(canBytes, Charsets.US_ASCII))
        val (cardDetails, holderName) = extractCardDetails(opened)
        currentAuthCertDer = opened.certificate.copyDer()
        pin1?.close()
        primedCanStore.clear()
        primedCardStored = false
        activeSession =
            ContactlessSession(
                isoDep = isoDep,
                can = canBytes,
                material = material,
                heldSession = true,
            )
        activeProviderGeneration = providerGenerationRandom.nextProviderGeneration()
        feedback.onCardSuccess()
        publishAsync(
            generation,
            NfcReaderStatus.ACTIVATION_REQUIRED,
            holderName = holderName,
            cardDetails = cardDetails,
        )
    }

    private fun handleOpenFailure(
        generation: Int,
        status: NfcReaderStatus,
        canBytes: ByteArray,
        pin1: Pin1Submission?,
        material: NativeCardSessionMaterial,
        isoDep: IsoDep,
    ) {
        currentAuthCertDer = null
        pin1?.close()
        if (status == NfcReaderStatus.WRONG_CAN) {
            val rejected = String(canBytes, Charsets.US_ASCII)
            CanSessionStore.recordRejected(rejected)
            primedCanStore.clear()
            primedCardStored = false
            rememberedHolderName = null
            rememberedDetails = null
            feedback.onCardError()
        }
        canBytes.fill(0)
        material.close()
        NativeContactlessSession.close()
        try {
            isoDep.close()
        } catch (_: IOException) {
        } catch (_: SecurityException) {
        } catch (_: IllegalStateException) {
        }
        AppTrace.nfcSessionClosed()
        publishAsync(generation, status, awaitingCard = status == NfcReaderStatus.WAITING_FOR_CARD)
    }

    /**
     * Worker-thread confined; runs PACE, certificate read, and
     * preflight, owning and zeroizing the transferred digits.
     */
    private fun openSessionBytes(
        canBytes: ByteArray,
        generation: Int,
        mintOnSuccess: Boolean,
        pin1: Pin1Submission?,
        isoDepTarget: IsoDep? = latestIsoDep,
    ) {
        try {
            AppTrace.nfcOpenSessionStarted(
                hasTarget = isoDepTarget != null,
                generation = generation,
                mintOnSuccess = mintOnSuccess,
            )
            closeActiveSession()
            val isoDep = isoDepTarget ?: latestIsoDep
            if (isoDep == null || generation != probeGeneration) {
                canBytes.fill(0)
                pin1?.close()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true)
                return
            }
            if (!ensureIsoDepConnected(isoDep)) {
                canBytes.fill(0)
                pin1?.close()
                AppTrace.nfcSessionOpenFailed()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD)
                return
            }
            val exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep))
            val material = NativeCardSessionMaterial()
            val opened = NativeContactlessSession.connect(canBytes.copyOf(), exchange)
            when (opened) {
                is NativeContactlessOpenResult.Success -> {
                    material.cacheAuthenticationCertificate(opened.certificate)
                    material.cachePin1Preflight(opened.preflight)
                    if (generation == probeGeneration) {
                        handleOpenSuccess(generation, opened, canBytes, pin1, mintOnSuccess, isoDep, material)
                    } else {
                        canBytes.fill(0)
                        pin1?.close()
                        material.close()
                    }
                }

                is NativeContactlessOpenResult.ActivationRequired -> {
                    material.cacheAuthenticationCertificate(opened.certificate)
                    if (generation == probeGeneration) {
                        handleOpenActivationRequired(generation, opened, canBytes, pin1, isoDep, material)
                    } else {
                        canBytes.fill(0)
                        pin1?.close()
                        material.close()
                    }
                }

                is NativeContactlessOpenResult.Failure -> {
                    handleOpenFailure(generation, opened.kind.toConnectStatus(), canBytes, pin1, material, isoDep)
                }
            }
        } finally {
            isOpeningSession = false
        }
    }

    private fun extractCardDetails(opened: NativeContactlessOpenResult): Pair<PersonCardDetails?, String?> {
        val certificate =
            when (opened) {
                is NativeContactlessOpenResult.Success -> opened.certificate
                is NativeContactlessOpenResult.ActivationRequired -> opened.certificate
                is NativeContactlessOpenResult.Failure -> null
            }
        val holderNameFromCert = certificate?.let(CertificateHolderName::fromCertificate)
        val photoBytes = CardPhotoStore.getPhoto(holderNameFromCert) ?: NativeCore.readCardFacePhoto()
        val documentNumber = NativeCore.readCardDocumentNumber()
        val tamperProofVerified = NativeVerification.readCardVerificationPassed()
        val cardDetails: PersonCardDetails? =
            certificate?.let { cert ->
                try {
                    PersonCardDetails.fromDer(
                        cert.copyDer(),
                        photoBytes = photoBytes,
                        documentNumber = documentNumber,
                        tamperProofVerified = tamperProofVerified,
                    )
                } catch (_: Exception) {
                    null
                }
            }
        val holderName = cardDetails?.holderName ?: holderNameFromCert
        if (photoBytes != null && photoBytes.isNotEmpty() && holderName != null) {
            CardPhotoStore.savePhoto(photoBytes, holderName, documentNumber)
        }
        return Pair(cardDetails, holderName)
    }

    /**
     * Read the face photo from the card on demand.
     * Uses the active held session if present, or connects with primed CAN if a tag is resting.
     */
    fun readPhoto(onResult: (ByteArray?) -> Unit) {
        val session = activeSession
        if (session != null) {
            probeExecutor.execute {
                val photo =
                    try {
                        session.readFacePhoto()
                    } catch (_: Exception) {
                        null
                    }
                val holderName = latestSnapshot.holderName
                val docNum = NativeCore.readCardDocumentNumber()
                if (photo != null && holderName != null) {
                    CardPhotoStore.savePhoto(photo, holderName, docNum)
                }
                val tamperProofVerified = NativeVerification.readCardVerificationPassed()
                val updatedDetails =
                    latestSnapshot.cardDetails?.copy(
                        photoBytes = photo,
                        isTamperProofVerified = tamperProofVerified,
                    )
                mainHandler.post {
                    if (updatedDetails != null) {
                        publish(latestSnapshot.copy(cardDetails = updatedDetails))
                    }
                    onResult(photo)
                }
            }
            return
        }
        val resting = latestIsoDep
        val canBytes = CanSessionStore.canBytes() ?: primedCanStore.read()
        if (resting != null && canBytes != null) {
            probeExecutor.execute {
                val photo =
                    try {
                        if (!resting.isConnected) {
                            resting.connect()
                            resting.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
                        }
                        val exchange = NfcNativeBlockExchange(IsoDepCardChannel(resting))
                        NativeContactlessSession.readFacePhotoWithCan(canBytes, exchange)
                    } catch (_: Exception) {
                        null
                    }
                val holderName = latestSnapshot.holderName
                val docNum = NativeCore.readCardDocumentNumber()
                if (photo != null && holderName != null) {
                    CardPhotoStore.savePhoto(photo, holderName, docNum)
                }
                val tamperProofVerified = NativeVerification.readCardVerificationPassed()
                val updatedDetails =
                    latestSnapshot.cardDetails?.copy(
                        photoBytes = photo,
                        isTamperProofVerified = tamperProofVerified,
                    )
                mainHandler.post {
                    if (updatedDetails != null) {
                        publish(latestSnapshot.copy(cardDetails = updatedDetails))
                    }
                    onResult(photo)
                }
            }
            return
        }
        mainHandler.post {
            onResult(null)
        }
    }

    private fun closeActiveSession() {
        activeProviderGeneration = null
        currentAuthCertDer = null
        activeSession?.close()
        activeSession = null
    }

    /** Forget the primed card so the next tap requires the access number again. */
    fun forgetPrimedCard() {
        checkMainThread()
        AppTrace.nfcPrimedForgotten()
        CanSessionStore.drop()
        rememberedHolderName = null
        rememberedDetails = null
        try {
            probeExecutor.execute {
                CanSessionStore.drop()
                primedCanStore.clear()
                primedCardStored = false
                pinCache.clear()
                closeActiveSession()
                probeGeneration += 1
                mainHandler.post { publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD)) }
            }
        } catch (_: RejectedExecutionException) {
            // The executor only stops when the process is terminating.
        }
    }

    /** Forget the cached PIN 1 so subsequent operations require PIN entry again. */
    fun forgetPin1() {
        checkMainThread()
        pinCache.clear()
        try {
            probeExecutor.execute {
                primedCanStore.forgetPin1()
                pinCache.clear()
            }
        } catch (_: RejectedExecutionException) {
            // The executor only stops when the process is terminating.
        }
    }

    /**
     * Dismiss the present-card prompt without forgetting anything: the
     * reader keeps listening and the stored access number stays.
     */
    fun cancelAwaitingCard() {
        checkMainThread()
        if (latestSnapshot.awaitingCard) {
            publish(latestSnapshot.copy(awaitingCard = false))
        }
    }

    private fun publishAsync(
        generation: Int,
        status: NfcReaderStatus,
        isPrimedOpening: Boolean = false,
        holderName: String? = null,
        cardDetails: PersonCardDetails? = null,
        awaitingCard: Boolean = false,
    ) {
        mainHandler.post {
            if (generation == probeGeneration) {
                publish(
                    NfcReaderSnapshot(
                        status = status,
                        isPrimed = primedCardStored,
                        isPrimedOpening = isPrimedOpening,
                        holderName = holderName ?: rememberedHolderName,
                        cardDetails = cardDetails ?: rememberedDetails,
                        awaitingCard = awaitingCard,
                    ),
                )
            } else {
                AppTrace.nfcProbeResultDiscarded()
            }
        }
    }

    private fun publish(snapshot: NfcReaderSnapshot) {
        val holder =
            (if (primedCardStored) primedCanStore.readHolderName() else null)
                ?: snapshot.holderName
                ?: rememberedHolderName
        val details =
            snapshot.cardDetails
                ?: (if (holder != null && holder == rememberedHolderName) rememberedDetails else null)
                ?: holder?.let { PersonCardDetails.fromHolderName(it) }
        latestSnapshot = snapshot.copy(isPrimed = primedCardStored, holderName = holder, cardDetails = details)
        AppTrace.nfcSnapshotPublished(latestSnapshot.status)
        if (latestSnapshot.awaitingCard) {
            AppTrace.nfcAwaitingCard()
        }
        stateListeners.toList().forEach { listener -> listener(latestSnapshot) }
    }

    private fun checkMainThread() {
        check(Looper.myLooper() == Looper.getMainLooper()) {
            "NFC reader state must be changed on the main thread"
        }
    }

    private companion object {
        /** ISO-DEP over NFC-A or NFC-B; the card carries no NDEF. */
        const val READER_MODE_FLAGS =
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 15_000

        const val PRESENCE_CHECK_DELAY_MILLISECONDS = 250
    }
}
