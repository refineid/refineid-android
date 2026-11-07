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
import android.os.SystemClock
import fi.refineid.android.RefineIdApplication
import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardCa
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.core.NativeContactlessOpenResult
import fi.refineid.android.core.NativeContactlessSession
import fi.refineid.android.core.NativeOrganizationCard
import fi.refineid.android.core.NativeOrganizationOpenResult
import fi.refineid.android.core.NativePin1PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NfcCardKind
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Retention
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.core.attemptsLeft
import fi.refineid.android.core.organizationPin1Refused
import fi.refineid.android.core.primedAuthenticationCertificate
import fi.refineid.android.core.primedQualifiedCertificate
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.prime.PrimedCanStore
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume

/**
 * Contactless discovery and card sessions bound to one foreground
 * activity. Reader mode delivers each discovered tag once; recognition
 * runs a credential-free EF.CardAccess probe that names the card's kind. A
 * holder-entered CAN opens a citizen card's session, and PIN 1 an organization
 * card's; every operation re-runs PACE inside one bounded ISO-DEP connection on
 * a dedicated worker thread.
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

    @Volatile
    private var isForgetting = false

    /** Last ISO-DEP tag left resting in the field; worker-thread I/O only. */
    @Volatile
    private var latestIsoDep: IsoDep? = null

    /** Suppresses redundant recognition re-probes of a resting card. */
    private val reprobeThrottle = NfcReprobeThrottle()

    // Worker-thread confined. Main-thread state never owns a session.
    private var activeSession: ContactlessCardSession? = null

    /** What opens the card last read in the field; null before one has answered. */
    @Volatile
    private var recognizedKind: NfcCardKind? = null

    /** An organization card's PIN 1 tries, read before any entry. */
    @Volatile
    private var organizationPin1Attempts: Int? = null

    /** The organization card's answer to the PIN 1 last offered to open it. */
    @Volatile
    private var organizationPin1Answer: Pin1Verification? = null

    private val isOpeningSession = AtomicBoolean(false)

    /** Remote or local operations currently waiting on the card. */
    private val activeWaits = AtomicInteger(0)

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
            organizationSession = ::organizationSessionFromStore,
        )

    internal val authenticationCardService =
        NfcAuthenticationCardService(
            probeExecutor = probeExecutor,
            mainHandler = mainHandler,
            isReady = { latestSnapshot.status == NfcReaderStatus.CARD_READY },
            currentGeneration = { probeGeneration },
            activeSession = { activeSession },
            cachedCertificate = {
                val der = currentAuthenticationCertificateDer ?: primedCanStore.readAuthCertificateDer()
                der?.let {
                    fi.refineid.android.core
                        .primedAuthenticationCertificate(it)
                }
            },
            awaitReady = {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                    if (!isCardReady) connect(null, null)
                    awaitCardReady()
                }
            },
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

    internal val authenticationSessionGeneration: Int get() = probeGeneration

    val snapshot: NfcReaderSnapshot
        get() = latestSnapshot

    val isCardReady: Boolean
        get() = latestSnapshot.status == NfcReaderStatus.CARD_READY

    /**
     * Waits for an open session, opening one on any recognized card whose
     * access number is known, for as long as [NfcCardWait] allows.
     */
    suspend fun awaitCardReady(): Boolean {
        if (isCardReady) {
            return true
        }
        AppTrace.nfcAwaitCardReady(
            isCardReady = false,
            status = latestSnapshot.status.name,
            hasResting = latestIsoDep != null,
        )
        val snapshots = Channel<NfcReaderSnapshot>(Channel.CONFLATED)
        val listener: (NfcReaderSnapshot) -> Unit = { snapshots.trySend(it) }
        activeWaits.incrementAndGet()
        try {
            var current =
                suspendCancellableCoroutine { continuation ->
                    mainHandler.post {
                        addStateListener(listener)
                        continuation.resume(latestSnapshot)
                    }
                }
            val startedAt = SystemClock.elapsedRealtime()
            var lastChangeAt = startedAt
            var wasWaitingOnHolder = false
            while (true) {
                if (current.status == NfcReaderStatus.CARD_READY) {
                    return true
                }
                openRestingCard(current.status)
                val waitingOnHolder =
                    NfcCardWait.waitsOnHolder(
                        status = current.status,
                        accessNumberKnown = accessNumberKnown(),
                        readerInFront = attachedActivity != null,
                    )
                if (wasWaitingOnHolder && !waitingOnHolder) {
                    lastChangeAt = SystemClock.elapsedRealtime()
                }
                wasWaitingOnHolder = waitingOnHolder
                val deadline =
                    NfcCardWait.deadline(
                        startedAt = startedAt,
                        lastChangeAt = lastChangeAt,
                        waitingOnHolder = waitingOnHolder,
                    )
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) {
                    return false
                }
                val next = withTimeoutOrNull(remaining) { snapshots.receive() } ?: return false
                if (next.status != current.status) {
                    lastChangeAt = SystemClock.elapsedRealtime()
                }
                current = next
            }
        } finally {
            activeWaits.decrementAndGet()
            mainHandler.post { removeStateListener(listener) }
            snapshots.close()
        }
    }

    private fun accessNumberKnown(): Boolean = CanSessionStore.hasCan || primedCanStore.hasAccessNumber()

    /** The holder's PIN 1 for an organization card the phone has not read yet. */
    private fun connectOrganization(pin1: Pin1Submission) {
        val resting = latestIsoDep
        if (resting == null || pinCache.isRejected(pin1)) {
            val rejected = resting != null
            pin1.close()
            if (rejected) {
                organizationPin1Answer = Pin1Verification(Pin1VerificationResult.WRONG_PIN)
                publish(latestSnapshot)
            } else {
                refreshReaderMode(forceCycle = true, publishWaiting = false)
                publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true))
            }
            return
        }
        if (!isOpeningSession.compareAndSet(false, true)) {
            pin1.close()
            return
        }
        val generation = probeGeneration
        publish(NfcReaderSnapshot(status = NfcReaderStatus.CONNECTING))
        try {
            probeExecutor.execute { openOrganization(pin1, generation, resting) }
        } catch (_: RejectedExecutionException) {
            isOpeningSession.set(false)
            pin1.close()
        }
    }

    /** Worker-thread confined; PACE with PIN 1 and the reads through the channel. */
    private fun openOrganization(
        pin1: Pin1Submission,
        generation: Int,
        isoDep: IsoDep,
    ) {
        try {
            closeActiveSession()
            if (generation != probeGeneration || !ensureIsoDepConnected(isoDep)) {
                pin1.close()
                AppTrace.nfcSessionOpenFailed()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true)
                return
            }
            val candidate = pin1.copyBytes()
            try {
                val exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep))
                when (val opened = NativeOrganizationCard.open(pin1, exchange)) {
                    is NativeOrganizationOpenResult.Opened -> {
                        handleOrganizationOpened(generation, opened, candidate, isoDep)
                    }

                    is NativeOrganizationOpenResult.Refused -> {
                        handleOrganizationRefused(generation, opened.answer, candidate, isoDep)
                    }

                    is NativeOrganizationOpenResult.Unreadable -> {
                        closeResting(isoDep)
                        publishAsync(generation, opened.kind.toConnectStatus())
                    }
                }
            } finally {
                candidate.fill(0)
            }
        } finally {
            isOpeningSession.set(false)
        }
    }

    private fun handleOrganizationOpened(
        generation: Int,
        opened: NativeOrganizationOpenResult.Opened,
        candidate: ByteArray,
        isoDep: IsoDep,
    ) {
        val identity = opened.identity
        if (generation != probeGeneration) {
            identity.certificate.close()
            opened.qualifiedCertificate?.close()
            return
        }
        val (cardDetails, holderName) = extractCardDetails(identity)
        val certDer = identity.certificate.copyDer()
        val previous = currentAuthCertDer ?: primedCanStore.readAuthCertificateDer()
        if (previous != null && !previous.contentEquals(certDer)) {
            pinCache.clear()
        }
        // The handshake proved the digits, and MSE:Set AT's answer before it is
        // the counter custody decides on: held only at the full allowance.
        val retention =
            Pin1Retention.of(
                AuthenticationCardIdentity.of(certDer),
                identity.preflight.state.attemptsLeft(),
            )
        if (retention != null) pinCache.recordVerified(candidate.copyOf(), retention)
        CanSessionStore.drop()
        primedCanStore.writeOrganization(certDer, opened.qualifiedCertificate?.copyDer(), holderName)
        primedCardStored = true
        rememberedHolderName = holderName
        rememberedDetails = cardDetails
        currentAuthCertDer = certDer
        recognizedKind = NfcCardKind.ORGANIZATION
        organizationPin1Attempts = identity.preflight.state.attemptsLeft()
        organizationPin1Answer = null
        saveCardCaCertificates()
        activeSession =
            OrganizationContactlessSession(
                isoDep = isoDep,
                authenticationCertificate = identity.certificate,
                qualifiedCertificate = opened.qualifiedCertificate,
            )
        feedback.onCardSuccess()
        publishAsync(generation, NfcReaderStatus.CARD_READY, holderName = holderName, cardDetails = cardDetails)
    }

    /**
     * The card's answer reaches the holder with its count. Digits it refused
     * are remembered and never sent again; a card that is not an organization
     * card is read anew and named no PIN.
     */
    private fun handleOrganizationRefused(
        generation: Int,
        answer: Pin1Verification,
        candidate: ByteArray,
        isoDep: IsoDep,
    ) {
        when (answer.result) {
            Pin1VerificationResult.CARD_UNAVAILABLE -> {
                closeResting(isoDep)
                signalLostCard()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true)
            }

            Pin1VerificationResult.PACE_REJECTED -> {
                probe(isoDep, generation)
            }

            Pin1VerificationResult.TRANSPORT_ERROR, Pin1VerificationResult.BRIDGE_ERROR -> {
                closeResting(isoDep)
                publishAsync(generation, NfcReaderStatus.TRANSPORT_ERROR)
            }

            else -> {
                if (answer.result == Pin1VerificationResult.WRONG_PIN) {
                    pinCache.recordRejected(candidate.copyOf())
                    organizationPin1Attempts = answer.remainingRetries
                }
                organizationPin1Answer = answer
                feedback.onCardError()
                val pukNext =
                    answer.result == Pin1VerificationResult.PIN_LOCKED ||
                        answer.result == Pin1VerificationResult.SAFETY_REFUSED ||
                        organizationPin1Refused(organizationPin1Attempts)
                if (pukNext) {
                    organizationRecognized(isoDep, generation)
                } else {
                    publishAsync(generation, NfcReaderStatus.CARD_RECOGNIZED)
                }
            }
        }
    }

    /**
     * Worker-thread confined; an organization card answered in the field. A
     * kept card's session comes from its stored certificates, and each
     * operation opens its own channel. An unknown card's PIN 1 counter is read
     * with no secret: a PIN the floor would refuse goes to the PUK's form,
     * otherwise the holder is asked for PIN 1.
     */
    private fun organizationRecognized(
        isoDep: IsoDep,
        generation: Int,
    ) {
        if (generation != probeGeneration) return
        recognizedKind = NfcCardKind.ORGANIZATION
        val stored = organizationSessionFromStore(isoDep)
        if (stored != null) {
            activeSession?.close()
            activeSession = stored
            currentAuthCertDer = primedCanStore.readAuthCertificateDer()
            organizationPin1Answer = null
            publishAsync(generation, NfcReaderStatus.CARD_READY)
            return
        }
        val counter = NativeOrganizationCard.probePin1(NfcNativeBlockExchange(IsoDepCardChannel(isoDep)))
        val state = (counter as? NativePin1PreflightResult.Success)?.preflight?.state
        organizationPin1Attempts = state?.attemptsLeft()
        if (organizationPin1Refused(organizationPin1Attempts)) {
            activeSession?.close()
            activeSession =
                OrganizationContactlessSession(
                    isoDep = isoDep,
                    authenticationCertificate = null,
                    qualifiedCertificate = null,
                    onUnlocked = { reprobeOrganization(isoDep, generation) },
                )
            publishAsync(generation, NfcReaderStatus.ACTIVATION_REQUIRED)
        } else {
            publishAsync(generation, NfcReaderStatus.CARD_RECOGNIZED)
        }
    }

    /** Worker-thread confined; the session for the organization card this phone keeps, or null. */
    private fun organizationSessionFromStore(isoDep: IsoDep): ContactlessCardSession? {
        if (!primedCanStore.isOrganizationPrimed()) return null
        val certificate =
            primedCanStore.readAuthCertificateDer()?.let(::primedAuthenticationCertificate) ?: return null
        val qualified: NativeQualifiedCertificate? =
            primedCanStore.readQualifiedCertificateDer()?.let(::primedQualifiedCertificate)
        return OrganizationContactlessSession(
            isoDep = isoDep,
            authenticationCertificate = certificate,
            qualifiedCertificate = qualified,
        )
    }

    /** A card with no PIN blocked any more opens with PIN 1; it is read anew. */
    private fun reprobeOrganization(
        isoDep: IsoDep,
        generation: Int,
    ) {
        if (generation != probeGeneration) return
        try {
            probeExecutor.execute { probe(isoDep, generation) }
        } catch (_: RejectedExecutionException) {
            AppTrace.nfcProbeResultDiscarded()
        }
    }

    private fun closeResting(isoDep: IsoDep) {
        try {
            isoDep.close()
        } catch (_: IOException) {
            // The tag may already be gone; the result stands.
        } catch (_: SecurityException) {
            // The tag handle is out of date.
        } catch (_: IllegalStateException) {
            // Tag service unavailable.
        }
        if (latestIsoDep == isoDep) latestIsoDep = null
        AppTrace.nfcSessionClosed()
    }

    private fun saveCardCaCertificates() {
        val app = applicationContext as? RefineIdApplication
        NativeCardCa.readRootCaCertificate()?.let { app?.caCertificateStore?.saveCertificate(it) }
        NativeCardCa.readIntermediateCaCertificate()?.let { app?.caCertificateStore?.saveCertificate(it) }
    }

    /** Opens a session on the recognized card resting in the field, when it can. */
    private fun openRestingCard(status: NfcReaderStatus) {
        val resting = latestIsoDep
        val canOpen =
            NfcCardWait.shouldOpenSession(
                status = status,
                cardInField = resting != null,
                accessNumberKnown = accessNumberKnown(),
                opening = isOpeningSession.get(),
            )
        if (resting == null || !canOpen || !isOpeningSession.compareAndSet(false, true)) {
            return
        }
        val inMemoryCan = CanSessionStore.canBytes()
        val generation = probeGeneration
        try {
            probeExecutor.execute {
                val storedCan = inMemoryCan ?: primedCanStore.read()
                if (storedCan == null) {
                    isOpeningSession.set(false)
                    AppTrace.nfcAccessNumberMissing()
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
            inMemoryCan?.fill(0)
            isOpeningSession.set(false)
        }
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
        if (can == null && pin1 != null && recognizedKind == NfcCardKind.ORGANIZATION && !isCardReady) {
            connectOrganization(pin1)
            return
        }
        val currentCan = CanSessionStore.currentCan
        can?.let { CanSessionStore.remember(it) }
        val generation = probeGeneration
        val candidateCan = can?.peekDigits()
        val inMemoryCanBytes = can?.transfer() ?: CanSessionStore.canBytes()
        if (isCardReady && activeSession != null) {
            if (candidateCan == null || candidateCan == currentCan) {
                pin1?.close()
                can?.close()
                inMemoryCanBytes?.fill(0)
                return
            }
        }
        val resting = latestIsoDep
        if (resting == null || !resting.isConnected) {
            latestIsoDep = null
            inMemoryCanBytes?.fill(0)
            pin1?.close()
            probeGeneration += 1
            refreshReaderMode(forceCycle = true, publishWaiting = false)
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
        if (!isOpeningSession.compareAndSet(false, true)) {
            inMemoryCanBytes?.fill(0)
            pin1?.close()
            return
        }
        publish(NfcReaderSnapshot(status = NfcReaderStatus.CONNECTING))
        AppTrace.nfcConnectStarted()
        try {
            probeExecutor.execute {
                // primedCanStore.read() decrypts Android Keystore ciphertext;
                // it must run off the main thread — resolved here on the executor.
                val canBytes = inMemoryCanBytes ?: CanSessionStore.canBytes() ?: primedCanStore.read()
                if (canBytes == null) {
                    isOpeningSession.set(false)
                    pin1?.close()
                    // A card with no access number, or one not read yet, says
                    // what it needs when it answers.
                    if (ensureIsoDepConnected(resting)) {
                        probe(resting, generation)
                    } else {
                        publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = true)
                    }
                    return@execute
                }
                val mint = can != null || CanSessionStore.hasCan
                openSessionBytes(
                    canBytes = canBytes,
                    generation = generation,
                    mintOnSuccess = mint,
                    pin1 = pin1,
                    isoDepTarget = resting,
                )
            }
        } catch (_: RejectedExecutionException) {
            isOpeningSession.set(false)
            inMemoryCanBytes?.fill(0)
            pin1?.close()
        }
    }

    private fun refreshReaderMode(
        forceCycle: Boolean = false,
        publishWaiting: Boolean = true,
    ) {
        checkMainThread()
        val activity = attachedActivity ?: return
        val nfcAdapter = adapter ?: return
        if (nfcAdapter.isEnabled) {
            if (forceCycle) {
                try {
                    nfcAdapter.disableReaderMode(activity)
                } catch (_: IllegalStateException) {
                } catch (_: SecurityException) {
                }
            }
            val extras =
                Bundle().apply {
                    putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MILLISECONDS)
                }
            nfcAdapter.enableReaderMode(
                activity,
                readerCallback,
                READER_MODE_FLAGS,
                extras,
            )
            AppTrace.nfcReaderModeChanged(isEnabled = true)
            if (publishWaiting &&
                latestSnapshot.status != NfcReaderStatus.CARD_READY &&
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
        if (isForgetting) return
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
            // The field cycled, so the card left and is back in place.
            feedback.onCardDiscovered()
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
            if (!isOpeningSession.compareAndSet(false, true)) {
                storedCan.fill(0)
                return
            }
            try {
                probeExecutor.execute {
                    openSessionBytes(
                        canBytes = storedCan,
                        generation = generation,
                        mintOnSuccess = true,
                        pin1 = null,
                        isoDepTarget = isoDep,
                    )
                }
            } catch (_: RejectedExecutionException) {
                isOpeningSession.set(false)
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
            if (latestIsoDep == isoDep) {
                latestIsoDep = null
            }
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        } catch (_: SecurityException) {
            if (latestIsoDep == isoDep) {
                latestIsoDep = null
            }
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        } catch (_: IllegalStateException) {
            if (latestIsoDep == isoDep) {
                latestIsoDep = null
            }
            AppTrace.nfcSessionOpenFailed()
            publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
            return
        }
        val result =
            NativeContactlessCore.probeCardAccess(
                exchangeLevel = NativeCardExchangeLevel.APDU,
                exchange = NfcNativeBlockExchange(IsoDepCardChannel(isoDep)),
            )
        if (result is NativeCardAccessResult.Success) {
            recognizedKind = result.summary.cardKind
            if (result.summary.cardKind == NfcCardKind.ORGANIZATION) {
                organizationRecognized(isoDep, generation)
                return
            }
        } else {
            try {
                isoDep.close()
            } catch (_: IOException) {
                // The tag may already be gone; the probe result stands.
            } catch (_: SecurityException) {
                // The tag handle is out of date.
            } catch (_: IllegalStateException) {
                // Tag service unavailable.
            }
            if (latestIsoDep == isoDep) {
                latestIsoDep = null
            }
            AppTrace.nfcSessionClosed()
            if (result.toReaderStatus() == NfcReaderStatus.WAITING_FOR_CARD) {
                signalLostCard()
            }
        }
        // A primed card still needs PIN1 to unlock; the UI shows a
        // PIN-only prompt on this recognized state.
        publishAsync(generation, result.toReaderStatus())
    }

    private fun ensureIsoDepConnected(isoDep: IsoDep): Boolean =
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
            }
            isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
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
        recognizedKind = NfcCardKind.PERSONAL
        val (cardDetails, holderName) = extractCardDetails(opened)
        if (holderName != null) {
            rememberedHolderName = holderName
            rememberedDetails = cardDetails
        }
        val certDer = opened.certificate.copyDer()
        val previous = currentAuthCertDer ?: primedCanStore.readAuthCertificateDer()
        if (previous != null && !previous.contentEquals(certDer)) {
            // Another card replaced the one a held PIN 1 belongs to (RAPP
            // v26.11.2 section 11 item 2).
            pinCache.clear()
        }
        currentAuthCertDer = certDer.copyOf()
        saveCardCaCertificates()
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
        pin1?.close()
        activeSession =
            ContactlessSession(
                isoDep = isoDep,
                can = canBytes,
                material = material,
                heldSession = true,
            )
        feedback.onCardSuccess()
        publishAsync(generation, NfcReaderStatus.CARD_READY, holderName = holderName, cardDetails = cardDetails)
    }

    private fun handleOpenActivationRequired(
        generation: Int,
        canBytes: ByteArray,
        pin1: Pin1Submission?,
        isoDep: IsoDep,
        material: NativeCardSessionMaterial,
    ) {
        CanSessionStore.remember(String(canBytes, Charsets.US_ASCII))
        pin1?.close()
        // PACE proved the access number against this card, so it is kept
        // from here on, activated or not: the holder is not asked for it
        // again at the activation tap, and a mismatch on a later tap
        // forgets it as for any card. A card awaiting activation has no
        // identity: nothing of it is kept, and whatever an earlier card
        // left in memory or in the store goes, so no name is shown and no
        // identity is offered to a paired computer until an activated open
        // reads the certificate.
        currentAuthCertDer = null
        rememberedHolderName = null
        rememberedDetails = null
        primedCanStore.write(canBytes.copyOf())
        primedCanStore.writeHolderName(null)
        primedCanStore.writeAuthCertificateDer(null)
        primedCardStored = true
        activeSession =
            ContactlessSession(
                isoDep = isoDep,
                can = canBytes,
                material = material,
                heldSession = true,
            )
        feedback.onCardSuccess()
        publishAsync(generation, NfcReaderStatus.ACTIVATION_REQUIRED, holderName = null, cardDetails = null)
    }

    private fun handleOpenFailure(
        generation: Int,
        status: NfcReaderStatus,
        canBytes: ByteArray,
        pin1: Pin1Submission?,
        material: NativeCardSessionMaterial,
        isoDep: IsoDep,
        organizationCard: Boolean,
    ) {
        currentAuthCertDer = null
        pin1?.close()
        if (status == NfcReaderStatus.WRONG_CAN) {
            recognizedKind = NfcCardKind.PERSONAL
            CanSessionStore.drop()
            primedCanStore.clear()
            primedCardStored = false
            rememberedHolderName = null
            rememberedDetails = null
            feedback.onCardError()
        }
        canBytes.fill(0)
        material.close()
        NativeContactlessSession.close()
        // The card has no access number and the one offered was not named to
        // it; what the holder kept stays, and the card says what it needs.
        if (organizationCard) {
            organizationRecognized(isoDep, generation)
            return
        }
        val keepAlive = status == NfcReaderStatus.WRONG_CAN && isoDep.isConnected
        if (!keepAlive) {
            try {
                isoDep.close()
            } catch (_: IOException) {
            } catch (_: SecurityException) {
            } catch (_: IllegalStateException) {
            }
            if (latestIsoDep == isoDep) {
                latestIsoDep = null
            }
            AppTrace.nfcSessionClosed()
        }
        if (status == NfcReaderStatus.WAITING_FOR_CARD) {
            signalLostCard()
        }
        publishAsync(generation, status, awaitingCard = status == NfcReaderStatus.WAITING_FOR_CARD)
    }

    /** The error tone for a card that slipped away while something waited on it. */
    private fun signalLostCard() {
        if (activeWaits.get() > 0 || wantsCard()) {
            feedback.onCardError()
        }
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
                if (latestIsoDep == isoDep) {
                    latestIsoDep = null
                }
                canBytes.fill(0)
                pin1?.close()
                AppTrace.nfcSessionOpenFailed()
                signalLostCard()
                publishAsync(generation, NfcReaderStatus.WAITING_FOR_CARD, awaitingCard = wantsCard())
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
                    if (generation == probeGeneration) {
                        handleOpenActivationRequired(generation, canBytes, pin1, isoDep, material)
                    } else {
                        canBytes.fill(0)
                        pin1?.close()
                        material.close()
                    }
                }

                is NativeContactlessOpenResult.Failure -> {
                    handleOpenFailure(
                        generation = generation,
                        status = opened.kind.toConnectStatus(),
                        canBytes = canBytes,
                        pin1 = pin1,
                        material = material,
                        isoDep = isoDep,
                        organizationCard = opened.kind == NativeCertificateReadFailure.ORGANIZATION_CARD,
                    )
                }
            }
        } finally {
            isOpeningSession.set(false)
        }
    }

    private fun extractCardDetails(opened: NativeContactlessOpenResult): Pair<PersonCardDetails?, String?> {
        val certificate =
            when (opened) {
                is NativeContactlessOpenResult.Success -> opened.certificate
                is NativeContactlessOpenResult.ActivationRequired -> null
                is NativeContactlessOpenResult.Failure -> null
            }
        val holderNameFromCert = certificate?.let(CertificateHolderName::lineFromCertificate)
        val cardDetails: PersonCardDetails? =
            certificate?.let { cert ->
                try {
                    PersonCardDetails.fromDer(cert.copyDer())
                } catch (_: Exception) {
                    null
                }
            }
        val holderName = cardDetails?.holderName ?: holderNameFromCert
        return Pair(cardDetails, holderName)
    }

    private fun closeActiveSession() {
        currentAuthCertDer = null
        activeSession?.close()
        activeSession = null
    }

    /** Forget the primed card so the next tap requires the access number again. */
    fun forgetPrimedCard(onCleared: () -> Unit = {}) {
        checkMainThread()
        AppTrace.nfcPrimedForgotten()
        CanSessionStore.drop()
        rememberedHolderName = null
        rememberedDetails = null
        primedCardStored = false
        recognizedKind = null
        organizationPin1Attempts = null
        organizationPin1Answer = null
        isForgetting = true
        probeGeneration += 1
        try {
            probeExecutor.execute {
                CanSessionStore.drop()
                primedCanStore.clear()
                pinCache.clear()
                primedCardStored = false
                rememberedHolderName = null
                rememberedDetails = null
                closeActiveSession()
                mainHandler.post {
                    isForgetting = false
                    publish(NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD))
                }
                onCleared()
            }
        } catch (_: RejectedExecutionException) {
            isForgetting = false
            onCleared()
        }
    }

    /** Forget the held PIN 1 so subsequent operations require PIN entry again. */
    fun forgetPin1() {
        checkMainThread()
        pinCache.clear()
    }

    /**
     * Dismiss the present-card prompt without forgetting anything: the
     * reader keeps listening and the stored access number stays.
     */
    fun cancelAuthenticationPreparation() {
        checkMainThread()
        probeGeneration += 1
        cancelAwaitingCard()
        probeExecutor.execute(::closeActiveSession)
        publish(
            NfcReaderSnapshot(
                status = NfcReaderStatus.WAITING_FOR_CARD,
                isPrimed = latestSnapshot.isPrimed,
            ),
        )
    }

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
        val kind = recognizedKind
        latestSnapshot =
            snapshot.copy(
                // A kept organization card opens a citizen card with nothing.
                isPrimed = primedCardStored && (kind != NfcCardKind.PERSONAL || !primedOrganizationOnly()),
                holderName = holder,
                cardDetails = details,
                cardKind = kind,
                pin1AttemptsLeft = organizationPin1Attempts,
                pin1Answer = organizationPin1Answer,
            )
        AppTrace.nfcSnapshotPublished(latestSnapshot.status)
        if (latestSnapshot.awaitingCard) {
            AppTrace.nfcAwaitingCard()
        }
        stateListeners.toList().forEach { listener -> listener(latestSnapshot) }
    }

    private fun primedOrganizationOnly(): Boolean = !primedCanStore.hasAccessNumber() && !CanSessionStore.hasCan

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
