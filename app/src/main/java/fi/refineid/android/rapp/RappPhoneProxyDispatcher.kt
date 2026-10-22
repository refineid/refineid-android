@file:Suppress("TooGenericExceptionCaught", "TooManyFunctions", "LargeClass")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.R
import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationCardReads
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.CertificateIdentity
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin1Retention
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.authenticationFailure
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.prime.PrimedCanStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappAnnouncementCandidate
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.RappProgressEvent
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappSessionRecord
import uniffi.refineid_rapp.rappStreamProfileName
import uniffi.refineid_rapp.rappWithdrawnRecord
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The custodian side of RAPP v26.10.22: serves the paired computers' sessions
 * over the stream transport, asks the holder for PINs on this phone, and
 * runs the card commands through the card services.
 *
 * The listener holds one session at a time. Operations take the card one at a
 * time, in the order they arrived, across that session and any earlier one
 * whose card command is still finishing (section 8.2 item 2).
 */
internal class RappPhoneProxyDispatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val inbox: RappAuthorizationInbox,
    private val pinCache: AuthenticationPinCache? = null,
    private val primedCanStore: PrimedCanStore? = null,
    private val authCardService: () -> AuthenticationCardService?,
    private val qualifiedCardService: () -> QualifiedCardService?,
    private val isCardReady: () -> Boolean = { false },
    private val awaitCardReady: suspend () -> Boolean = { false },
    private val offeredCard: suspend () -> RappOfferedCard = { RappOfferedCard.Absent },
    private val onAuthenticationVerified: ((ByteArray, Pin1Retention, Long) -> Boolean)? = null,
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var sessionRouting: RappSessionRouting? = null
    private var withdrawalJob: Job? = null
    private var hintRefreshJob: Job? = null
    private var vault: AndroidRappVault? = null
    private val catalog = RappPairCatalog(context)
    private val preAuthenticationLimiter = RappPreAuthenticationLimiter()

    @Volatile
    private var isClosed = false

    /** The instance name the session record is published under, as the responder last confirmed it. */
    @Volatile
    private var announcedInstance: String? = null

    /** The routed pairing of the session being served. */
    @Volatile
    private var routed: RappStoredPair? = null

    @Volatile
    private var sessionBridge: RappSessionBridge? = null

    /** The established session; null while none is. */
    @Volatile
    private var operationBridge: RappOperationBridge? = null

    /** Completes once the established session carried its first `card.status` (section 8.4 item 1). */
    @Volatile
    private var cardReported: CompletableDeferred<Unit>? = null

    private var livenessJob: Job? = null
    private var operationJob: Job? = null

    /** Frames leave in the order their bridge sealed them. */
    private val sendLock = Any()

    /** The card serves one operation at a time (section 8.2 item 2). */
    private val card = Mutex()

    /** The session whose operation holds [card]; null while the card is free. */
    @Volatile
    private var cardHolder: RappOperationBridge? = null

    /** One lane for card reports: the two readers' listeners call in on their own threads. */
    private val cardStatusLane = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    /** The card last reported on the open session; null before the first report. */
    @Volatile
    private var reportedCard: RappOfferedCard? = null

    @Volatile
    private var lastReadAuthCertDer: ByteArray? = null

    private val _connectedPeer = MutableStateFlow<PairedPeer?>(null)
    val connectedPeer: StateFlow<PairedPeer?> = _connectedPeer.asStateFlow()

    val isListening: Boolean
        get() = activeListener != null

    val listeningPort: Int?
        get() = activeListener?.port

    val cachedAuthCertDer: ByteArray?
        get() = lastReadAuthCertDer?.copyOf()

    /** A card command's result, or why the command never answered. */
    private sealed interface CardRun<out T> {
        class Answered<T>(
            val result: T,
        ) : CardRun<T>

        class Missing(
            val failure: RappCardFailure,
        ) : CardRun<Nothing>
    }

    /** The PIN the holder entered last for one operation; replaced, and the old one closed, after a wrong PIN. */
    private class HeldPin<P : AutoCloseable>(
        submission: P,
    ) : AutoCloseable {
        var submission: P = submission
            private set

        fun replace(next: P) {
            submission.close()
            submission = next
        }

        override fun close() = submission.close()
    }

    companion object {
        private const val DEFAULT_REQUESTER_DISPLAY_NAME = "Computer"

        private const val NANOS_PER_MICROSECOND = 1_000L

        /** How often liveness and operation deadlines are checked (section 8.3). */
        private const val LIVENESS_POLL_INTERVAL_MS = 1_000L
        private const val SHA256_DIGEST_LENGTH = 32
        private const val SHA384_DIGEST_LENGTH = 48

        /** The longest deadline a requester may set, its default when it sets none (section 8.1 item 2). */
        private const val MAXIMUM_OPERATION_LIFETIME_MS = 300_000UL

        /** How long the withdrawn record stays advertised (RAPP section 4.5: 2 to 10 seconds). */
        private const val WITHDRAWN_ANNOUNCEMENT_MS = 3_000L

        private val RANDOM_BYTE_COUNTS = rappRandomByteCounts()

        /** The value random material is overwritten with once used. */
        private const val ERASED: Byte = 0

        private fun elapsedMicros(startedNs: Long): Long = (System.nanoTime() - startedNs) / NANOS_PER_MICROSECOND
    }

    private fun dismissInbox() {
        scope.launch(Dispatchers.Main) { inbox.dismissAll() }
    }

    /**
     * Starts the one session listener for every stored pairing (RAPP
     * discovery hierarchy section 4.2-4.3).
     *
     * It is published under a fresh random instance name with TXT `v=1`,
     * `mode=session` and the rotating hints of the most recently used
     * pairings. Each connection names its pairing only through the routing
     * tag in its preamble.
     */
    fun startListening(vault: AndroidRappVault) {
        if (isClosed) return
        withdrawalJob?.cancel()
        withdrawalJob = null
        this.vault = vault
        endSession()
        activeListener?.close()
        sessionRouting?.close()
        sessionRouting = RappSessionRouting()
        val listener =
            StreamRelayListener(context, scope) { event ->
                handleRelayEvent(event)
            }
        activeListener = listener
        val instance = StreamRendezvousName.ephemeralName()
        announcedInstance = instance
        listener.onRegistered = { registered ->
            // Hints are bound to the instance name; a name the responder
            // changed to resolve a conflict gets its own record.
            if (activeListener === listener && registered != announcedInstance) {
                announcedInstance = registered
                listener.updateAttributes(sessionAttributes(vault))
            }
        }
        listener.start(instance, sessionAttributes(vault))
        RappCustodianService.ensureRunning(context)
        hintRefreshJob?.cancel()
        // Each hint window rebuilds the served set, which also destroys a
        // forgotten record past its notice window (RAPP v26.10.22 section 4.6
        // item 3); the listener stops once nothing is left to serve.
        hintRefreshJob =
            scope.launch {
                while (isActive && activeListener === listener) {
                    delay(StreamRendezvousName.millisUntilNextWindow(System.currentTimeMillis()))
                    if (activeListener === listener) {
                        pairingsChanged()
                    }
                }
            }
    }

    /** Republishes the session record after the set of served pairings changed. */
    fun refreshAnnouncement() {
        val listener = activeListener ?: return
        val vlt = vault ?: return
        listener.updateAttributes(sessionAttributes(vlt))
    }

    /**
     * The pairings changed: the session record is republished, or the
     * listener stops once no custodian pairing is left to serve, forgotten
     * ones that still owe their `pairing_revoked` close included.
     */
    fun pairingsChanged() {
        val vlt = vault ?: return
        val served = RappStoredPairs.served(catalog, vlt)
        val serves = served.any { it.pairing.role == RappEndpointRole.PROXY }
        served.forEach { it.record.close() }
        if (serves) refreshAnnouncement() else stopListening()
    }

    /**
     * Session-mode TXT attributes carrying the current rotating discovery
     * hints of the most recently used custodian pairings (discovery
     * hierarchy section 4.3), forgotten ones included: their peers keep
     * dialing until the close reaches them (RAPP v26.10.22 section 4.6 item
     * 2).
     */
    private fun sessionAttributes(vault: AndroidRappVault): Map<String, String> {
        val now = StreamRendezvousName.nowUnixSeconds().toULong()
        return try {
            StreamRendezvousName.attributes(rappSessionRecord(announcementCandidates(vault) { it.discoveryHint(now) }))
        } catch (_: Exception) {
            StreamRendezvousName.attributes(StreamRendezvousName.MODE_SESSION)
        }
    }

    /** One announcement candidate per served custodian pairing, with its last use. */
    private fun announcementCandidates(
        vault: AndroidRappVault,
        hint: (RappPairRecord) -> ByteArray,
    ): List<RappAnnouncementCandidate> =
        RappStoredPairs.served(catalog, vault).mapNotNull { stored ->
            try {
                if (stored.pairing.role != RappEndpointRole.PROXY) {
                    null
                } else {
                    RappAnnouncementCandidate(hint(stored.record), stored.peer.lastUsedMs.toULong())
                }
            } catch (_: Exception) {
                null
            } finally {
                stored.record.close()
            }
        }

    /**
     * Ends the session to [pairId] because the local user forgot the pairing
     * (RAPP v26.10.22 section 4.6 item 1). Returns true when the session was
     * established and carried the `pairing_revoked` close, so the caller
     * destroys the record at once; false when no session to the pairing was
     * open. A session still in its handshake is dropped, and the next one
     * delivers the close.
     */
    fun closePairingRevoked(pairId: RappPairId): Boolean {
        if (routed?.pairing?.id != pairId) return false
        val bridge = operationBridge
        if (bridge == null) {
            dropConnection()
            return false
        }
        val closed = act(bridge) { it.closeWithReason(RappCloseReason.PAIRING_REVOKED) } != null
        dropConnection()
        return closed
    }

    /**
     * The card this phone holds may have changed: reports it on the open
     * session (RAPP v26.10.22 section 8.4 item 1). Present is a card in the
     * reader, from insertion until removal, or an NFC card the holder added
     * to the phone, until the holder removes it; a card busy with an
     * operation, or one that did not answer an operation, stays present.
     */
    fun cardChanged() {
        if (isClosed) return
        scope.launch(cardStatusLane) { reportCard() }
    }

    /** Runs on [cardStatusLane], so reports leave in the order the card changed. */
    private suspend fun reportCard() {
        val bridge = operationBridge ?: return
        val reported = cardReported
        try {
            val card = currentCard()
            if (card == reportedCard) return
            val certificate = (card as? RappOfferedCard.Present)?.certificate?.toWire()
            if (act(bridge) { it.reportCardStatus(certificate) } != null) {
                reportedCard = card
            }
        } finally {
            reported?.complete(Unit)
        }
    }

    /** The card this phone holds now. */
    private suspend fun currentCard(): RappOfferedCard =
        try {
            offeredCard()
        } catch (_: Exception) {
            RappOfferedCard.Absent
        }

    /**
     * Withdraws the service the user switched off (RAPP v26.10.22 section
     * 4.5): the open session is closed as withdrawn, the listener stops
     * accepting, the instance is advertised as withdrawn for a few seconds,
     * and then everything stops.
     */
    fun withdraw() {
        val listener = activeListener
        val vlt = vault
        val instance = listener?.registeredName
        if (listener == null || vlt == null || instance == null) {
            stopListening()
            return
        }
        hintRefreshJob?.cancel()
        hintRefreshJob = null
        operationBridge?.let { bridge -> act(bridge) { it.closeWithReason(RappCloseReason.SERVICE_WITHDRAWN) } }
        val now = StreamRendezvousName.nowUnixSeconds().toULong()
        val withdrawn =
            try {
                StreamRendezvousName.attributes(
                    rappWithdrawnRecord(announcementCandidates(vlt) { it.withdrawalHint(instance, now) }),
                )
            } catch (_: Exception) {
                null
            }
        dropConnection()
        if (withdrawn == null) {
            stopListening()
            return
        }
        listener.withdraw(withdrawn)
        withdrawalJob?.cancel()
        withdrawalJob =
            scope.launch {
                delay(WITHDRAWN_ANNOUNCEMENT_MS)
                if (activeListener === listener) stopListening()
            }
    }

    fun stopListening() {
        RappCustodianService.stop(context)
        sessionRouting?.close()
        sessionRouting = null
        hintRefreshJob?.cancel()
        hintRefreshJob = null
        endSession()
        activeListener?.close()
        activeListener = null
        announcedInstance = null
        vault = null
    }

    /** Drops the connected computer and publishes the listener afresh. */
    fun disconnectClient() {
        endSession()
        activeListener?.close()
        val vlt = vault
        if (vlt != null && !isClosed) {
            startListening(vlt)
        }
    }

    private fun handleRelayEvent(event: StreamRelayEvent) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                endSession()
                if (!preAuthenticationLimiter.admit(RappClock.monotonicMs())) {
                    activeListener?.disconnectClient()
                }
            }

            is StreamRelayEvent.Frame -> {
                handleRelayFrame(event.data)
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                AppTrace.rappConnectionDropped(
                    if (event is StreamRelayEvent.Error) {
                        event.cause.javaClass.simpleName
                    } else {
                        "stream disconnected"
                    },
                )
                endSession()
            }
        }
    }

    private fun handleRelayFrame(data: ByteArray) {
        val vlt = vault ?: return
        val bridge = operationBridge
        if (bridge != null) {
            receive(bridge, data)
            return
        }
        val session = sessionBridge
        val pair = routed
        if (session == null || pair == null) {
            route(vlt, data)
        } else {
            handshake(vlt, session, pair, data)
        }
    }

    /**
     * The first frame must be the session preamble of a served pairing;
     * anything else closes the connection and changes no stored state
     * (RAPP v26.10.22 section 2.2.1).
     */
    private fun route(
        vault: AndroidRappVault,
        preamble: ByteArray,
    ) {
        val served = RappStoredPairs.served(catalog, vault)
        val record =
            try {
                sessionRouting?.route(preamble, served.map { it.record })
            } catch (_: Exception) {
                null
            }
        val pair = served.firstOrNull { it.record === record }
        served.filter { it !== pair }.forEach { it.record.close() }
        if (pair == null) {
            activeListener?.disconnectClient()
            return
        }
        routed = pair
        try {
            sessionBridge = RappSessionBridge.beginProxy(pair.record, vault, rappStreamProfileName())
        } catch (_: Exception) {
            dropConnection()
        }
    }

    /**
     * Answers the requester's `Noise_KK` message and opens the session with
     * `session.ready` (section 6.3, section 7.1 item 5); a forgotten pairing
     * gets its `pairing_revoked` close instead. Any failure before
     * authentication closes the connection and changes nothing stored.
     */
    private fun handshake(
        vault: AndroidRappVault,
        session: RappSessionBridge,
        pair: RappStoredPair,
        data: ByteArray,
    ) {
        try {
            session.readHandshakeFrame(data)
            send(session.writeHandshakeFrame())
            if (!session.handshakeComplete()) return
            session.enterAuthentication()
            if (pair.pairing.state is RappPairState.Forgotten) {
                deliverRevocationNotice(vault, session, pair)
                return
            }
            val nonce = ByteArray(RANDOM_BYTE_COUNTS.sessionReadyNonce.toInt()).also(SecureRandom()::nextBytes)
            try {
                send(session.sendReady(nonce))
            } finally {
                nonce.fill(ERASED)
            }
            session.enterEstablished()
            establish(session, pair)
        } catch (_: Exception) {
            dropConnection()
        }
    }

    /**
     * The first and only message of a session to a forgotten pairing: the
     * `pairing_revoked` close, after which the record's key is destroyed
     * (RAPP v26.10.22 section 4.6 items 2 and 3).
     */
    private fun deliverRevocationNotice(
        vault: AndroidRappVault,
        session: RappSessionBridge,
        pair: RappStoredPair,
    ) {
        send(session.deliverRevocationNotice())
        routed = null
        RappPairRevocation.revoke(pair.pairing.id, pair.record, vault)
        catalog.removePair(pair.peer.pairIdHex)
        dropConnection()
        pairingsChanged()
    }

    private fun establish(
        session: RappSessionBridge,
        pair: RappStoredPair,
    ) {
        activeListener?.clearSocketTimeout()
        val bridge = RappOperationBridge.beginProxy(session, MAXIMUM_OPERATION_LIFETIME_MS, RappClock.monotonicMs())
        cardReported = CompletableDeferred()
        reportedCard = null
        operationBridge = bridge
        startLivenessLoop(bridge)
        cardChanged()
        catalog.markUsed(pair.peer.pairIdHex, System.currentTimeMillis())
        _connectedPeer.value = pair.peer
        AppTrace.rappPairingCompleted(pair.peer.displayName)
    }

    /** Sends one frame on the connection, before the session's bridge exists. */
    private fun send(frame: ByteArray) {
        synchronized(sendLock) {
            (activeListener ?: throw IOException("listener closed")).send(frame)
        }
    }

    /**
     * Runs one call on the session's bridge, types its action at the binding
     * border, and sends the frame it sealed, so frames leave in the order the
     * bridge sealed them; a closing session ends here. Null when [bridge] no
     * longer serves the session or the call failed.
     */
    private fun act(
        bridge: RappOperationBridge,
        call: (RappOperationBridge) -> RappBridgeAction,
    ): RappBridgeOutcome? {
        val outcome =
            synchronized(sendLock) {
                if (bridge !== operationBridge) return null
                val outcome =
                    try {
                        RappBridgeOutcome.from(call(bridge))
                    } catch (_: Exception) {
                        return null
                    }
                if (outcome is RappBridgeOutcome.Send) {
                    try {
                        activeListener?.send(outcome.frame)
                    } catch (_: IOException) {
                    }
                }
                outcome
            }
        when {
            outcome is RappBridgeOutcome.Closed -> sessionClosed(outcome.reason)
            outcome is RappBridgeOutcome.Send && outcome.closesWith != null -> dropConnection()
        }
        return outcome
    }

    /**
     * The session closed. A requester that forgot this phone closes it with
     * `pairing_revoked`, and the pairing is revoked here at once (RAPP
     * v26.10.22 section 4.6 item 4).
     */
    private fun sessionClosed(reason: RappCloseReason?) {
        val pair = routed.takeIf { reason == RappCloseReason.PAIRING_REVOKED }
        if (pair != null) routed = null
        dropConnection()
        val vlt = vault ?: return
        if (pair != null) {
            catalog.removePair(pair.peer.pairIdHex)
            RappPairRevocation.revoke(pair.pairing.id, pair.record, vlt)
            pairingsChanged()
        }
    }

    /**
     * Decrypts one frame of the established session. A frame that does not
     * authenticate closes the session; the pairing stays (section 10.1 item
     * 2).
     */
    private fun receive(
        bridge: RappOperationBridge,
        data: ByteArray,
    ) {
        when (val outcome = act(bridge) { it.receiveFrame(data, RappClock.monotonicMs()) }) {
            null -> {
                if (bridge === operationBridge) dropConnection()
            }

            is RappBridgeOutcome.Admitted -> {
                startOperation(bridge, outcome.operationId)
            }

            else -> {}
        }
    }

    /** Pings after 5 seconds of silence, ends the session after 30, and cancels operations past their deadline. */
    private fun startLivenessLoop(bridge: RappOperationBridge) {
        livenessJob?.cancel()
        livenessJob =
            scope.launch(Dispatchers.IO) {
                val random = SecureRandom()
                while (isActive && bridge === operationBridge) {
                    delay(LIVENESS_POLL_INTERVAL_MS)
                    val challenge = ByteArray(RANDOM_BYTE_COUNTS.livenessChallenge.toInt()).also(random::nextBytes)
                    val polled =
                        try {
                            act(bridge) { it.pollLiveness(RappClock.monotonicMs(), challenge) }
                        } finally {
                            challenge.fill(ERASED)
                        }
                    if (polled == null) {
                        if (bridge === operationBridge) dropConnection()
                        break
                    }
                    if (act(bridge) { it.expireDue(RappClock.monotonicMs()) } is RappBridgeOutcome.Send) {
                        operationExpired()
                    }
                }
            }
    }

    /** The live operation passed its deadline before the card was commanded; its result already went out. */
    private fun operationExpired() {
        operationJob?.cancel()
        operationJob = null
        dismissInbox()
    }

    /**
     * Forgets the session: every operation of it is over (section 8.1 item
     * 3). A card command in flight is never interrupted; it runs to the
     * card's answer, which nothing delivers.
     */
    private fun endSession() {
        livenessJob?.cancel()
        livenessJob = null
        operationJob?.cancel()
        operationJob = null
        val bridge = operationBridge
        operationBridge = null
        bridge?.close()
        sessionBridge?.close()
        sessionBridge = null
        routed?.record?.close()
        routed = null
        cardReported = null
        reportedCard = null
        lastReadAuthCertDer = null
        _connectedPeer.value = null
        dismissInbox()
    }

    /** Closes the link and ends the session; the pairing stays. */
    private fun dropConnection() {
        AppTrace.rappConnectionDropped("proxy dispatcher dropConnection")
        endSession()
        activeListener?.disconnectClient()
    }

    private fun requesterName(): String =
        _connectedPeer.value
            ?.displayName
            ?.takeIf { it.isNotBlank() }
            ?: DEFAULT_REQUESTER_DISPLAY_NAME

    // --- Operations ---------------------------------------------------------

    /**
     * Runs one operation once the session carried its first `card.status`:
     * it takes the card in its turn, then asks for the PIN it needs or, for a
     * read, goes straight to the card (section 8.2).
     */
    private fun startOperation(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ) {
        val reported = cardReported
        operationJob =
            scope.launch(Dispatchers.IO) {
                try {
                    reported?.await()
                    holdCard(bridge, operationId) {
                        when (
                            val next =
                                act(bridge) { it.prerequisitesComplete(operationId.toWire(), RappClock.monotonicMs()) }
                        ) {
                            is RappBridgeOutcome.AwaitApproval -> {
                                authorize(bridge, operationId, next.request)
                            }

                            is RappBridgeOutcome.ExecuteRead -> {
                                read(bridge, operationId, next.request)
                            }

                            else -> {}
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    act(bridge) { it.operationFailed(operationId.toWire()) }
                }
            }
    }

    /**
     * Runs [block] while the operation holds the card. An operation that
     * finds the card held by another session's operation is told it is
     * queued, once, and waits its turn (section 8.2 item 2); one that waits
     * only for its own session's previous operation to finish is not.
     */
    private suspend fun holdCard(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        block: suspend () -> Unit,
    ) {
        if (!card.tryLock()) {
            if (cardHolder !== bridge) {
                act(bridge) { it.reportProgress(operationId.toWire(), RappProgressEvent.QUEUED) }
            }
            card.lock()
        }
        cardHolder = bridge
        try {
            block()
        } finally {
            cardHolder = null
            card.unlock()
        }
    }

    private suspend fun authorize(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        request: RappRequest,
    ) {
        AppTrace.rappOperationReceived(request.javaClass.simpleName, operationId.key)
        when (request) {
            is RappRequest.BrowserAuthenticate -> {
                authenticate(bridge, operationId, request)
            }

            is RappRequest.SignDocument -> {
                signDocuments(bridge, operationId, request.keyProfile, request.algorithm, listOf(request.document)) {
                    it.completeSignature(operationId.toWire(), single())
                }
            }

            is RappRequest.BatchSignDocuments -> {
                signDocuments(bridge, operationId, request.keyProfile, request.algorithm, request.documents) {
                    it.completeBatch(operationId.toWire())
                }
            }

            RappRequest.InspectCard,
            RappRequest.ReadIdentity,
            RappRequest.ReadAuthenticationCertificate,
            RappRequest.ReadSignatureCertificate,
            -> {
                fail(bridge, operationId, RappCardFailure.OPERATION_FAILED)
            }
        }
    }

    /** Ends the operation with [failure], telling the holder when the retry floor refused (section 10.2). */
    private fun fail(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        failure: RappCardFailure,
    ) {
        AppTrace.rappOperationFailed("remote_operation", operationId.key, failure.name)
        when (failure) {
            RappCardFailure.RETRY_FLOOR -> {
                scope.launch(Dispatchers.Main) { inbox.tell(R.string.rapp_retry_floor) }
            }

            RappCardFailure.USER_CANCELLED,
            RappCardFailure.CARD_ERROR,
            RappCardFailure.UNSUPPORTED,
            RappCardFailure.OPERATION_FAILED,
            -> {}
        }
        val wire = operationId.toWire()
        act(bridge) {
            when (failure) {
                RappCardFailure.USER_CANCELLED -> it.deny(wire)
                RappCardFailure.RETRY_FLOOR -> it.retryFloor(wire)
                RappCardFailure.CARD_ERROR -> it.cardError(wire)
                RappCardFailure.UNSUPPORTED -> it.requestInvalidOrUnsupported(wire)
                RappCardFailure.OPERATION_FAILED -> it.operationFailed(wire)
            }
        }
    }

    /**
     * Applies the holder's approval and returns the one card command it
     * releases; null when the operation expired and its result already went
     * out.
     */
    private fun approve(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ): RappRequest? {
        AppTrace.rappOperationApproved(operationId.key)
        val command = act(bridge) { it.approve(operationId.toWire(), RappClock.monotonicMs()) }
        return (command as? RappBridgeOutcome.ExecuteCommand)?.request
    }

    private fun reportConsentShown(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ) {
        scope.launch(Dispatchers.IO) {
            act(bridge) { it.reportProgress(operationId.toWire(), RappProgressEvent.CONSENT_SHOWN) }
        }
    }

    /**
     * Asks the holder for PIN 1 on this phone; null when the holder declines.
     * Entering the PIN is the holder's consent, reported once the prompt is
     * on screen (section 8.2 item 3); a prompt after a wrong PIN says so.
     */
    private suspend fun askPin1(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        wrongPin: RappCardAnswer.WrongPin?,
    ): Pin1Submission? {
        val answer = CompletableDeferred<Pin1Submission?>()
        withContext(Dispatchers.Main) {
            inbox.askBrowserAuth(
                requestId = operationId.key,
                requester = requesterName(),
                onApproved = { pin -> if (!answer.complete(pin)) pin.close() },
                onDenied = { answer.complete(null) },
                onShown = { reportConsentShown(bridge, operationId) },
                wrongPin = wrongPin,
            )
        }
        return awaitHolder(answer, operationId)
    }

    /** Asks the holder for PIN 2 over the documents [names] on this phone; see [askPin1]. */
    private suspend fun askPin2(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        names: List<String>,
        wrongPin: RappCardAnswer.WrongPin?,
    ): Pin2Submission? {
        val answer = CompletableDeferred<Pin2Submission?>()
        withContext(Dispatchers.Main) {
            inbox.askDocumentSign(
                requestId = operationId.key,
                requester = requesterName(),
                documentNames = names,
                onApproved = { pin -> if (!answer.complete(pin)) pin.close() },
                onDenied = { answer.complete(null) },
                onShown = { reportConsentShown(bridge, operationId) },
                wrongPin = wrongPin,
            )
        }
        return awaitHolder(answer, operationId)
    }

    private suspend fun <T> awaitHolder(
        answer: CompletableDeferred<T?>,
        operationId: RappOperationId,
    ): T? =
        try {
            answer.await()
        } finally {
            answer.cancel()
            withContext(NonCancellable + Dispatchers.Main) { inbox.dismiss(operationId.key) }
        }

    /**
     * Waits for the holder to present the card when none is ready, telling the
     * requester while it waits (section 8.2 item 4). Null when the card is
     * ready; otherwise why the wait ended without one.
     */
    private suspend fun awaitCard(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        action: RappAuthAction,
        forcePrompt: Boolean = false,
    ): RappCardFailure? {
        if (!forcePrompt && isCardReady()) return null
        val cancelled = AtomicBoolean(false)
        AppTrace.rappCardPromptShown(operationId.key, action.name)
        act(bridge) { it.reportProgress(operationId.toWire(), RappProgressEvent.WAITING_FOR_CARD) }
        withContext(Dispatchers.Main) {
            inbox.showTapPrompt(
                requestId = operationId.key,
                requester = requesterName(),
                action = action,
                onCancel = { cancelled.set(true) },
            )
        }
        val ready =
            try {
                awaitCardReady()
            } finally {
                AppTrace.rappCardPromptDismissed(operationId.key)
                withContext(NonCancellable + Dispatchers.Main) { inbox.dismissTapPrompt(operationId.key) }
                act(bridge) { it.reportProgress(operationId.toWire(), RappProgressEvent.CARD_WAIT_ENDED) }
            }
        return when {
            cancelled.get() -> RappCardFailure.USER_CANCELLED
            ready && bridge === operationBridge -> null
            else -> RappCardFailure.CARD_ERROR
        }
    }

    /**
     * Runs one card [command] that presents a PIN; when [cardLeft] says the
     * card did not answer, waits for the card and runs it again only when
     * [attemptsLeft] reads [before] again, showing the card did not count the
     * PIN (section 10.2). [waitFailure] receives why a wait ended without a
     * card.
     */
    private suspend fun <T> withPin(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        action: RappAuthAction,
        before: Int?,
        attemptsLeft: suspend () -> Int?,
        command: suspend () -> T,
        cardLeft: (T) -> Boolean,
        waitFailure: (RappCardFailure) -> Unit,
    ): RappCardRetry.Run<T> =
        RappCardRetry.run(before, attemptsLeft, command, cardLeft) {
            val failure = awaitCard(bridge, operationId, action, forcePrompt = true)
            if (failure != null) waitFailure(failure)
            failure == null
        }

    // --- Reads (section 8.2 item 6) -------------------------------------------

    private suspend fun read(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        request: RappRequest,
    ) {
        val startedNs = System.nanoTime()
        val name = request.javaClass.simpleName
        AppTrace.rappOperationReceived(name, operationId.key)
        val completed =
            when (request) {
                // The card services expose neither the answer to reset nor its
                // historical bytes, so the inspection carries none (section 9.1).
                RappRequest.InspectCard -> {
                    act(bridge) { it.completeInspection(operationId.toWire(), byteArrayOf()) }
                }

                RappRequest.ReadIdentity -> {
                    val certificate = authenticationCertificate(bridge, operationId) ?: return
                    val identity = CertificateIdentity.fromDer(certificate.toWire())
                    if (identity == null) {
                        fail(bridge, operationId, RappCardFailure.OPERATION_FAILED)
                        return
                    }
                    act(bridge) {
                        it.completeIdentity(
                            operationId.toWire(),
                            identity.holderName,
                            identity.cardId,
                            identity.issuanceDate,
                            identity.expirationDate,
                            listOf(certificate.toWire()),
                        )
                    }
                }

                RappRequest.ReadAuthenticationCertificate -> {
                    val certificate = authenticationCertificate(bridge, operationId) ?: return
                    act(bridge) { it.completeCertificate(operationId.toWire(), certificate.toWire()) }
                }

                RappRequest.ReadSignatureCertificate -> {
                    val certificate =
                        when (val read = signatureCertificate(bridge, operationId)) {
                            is CardRun.Answered -> read.result
                            is CardRun.Missing -> return fail(bridge, operationId, read.failure)
                        }
                    act(bridge) { it.completeCertificate(operationId.toWire(), certificate.toWire()) }
                }

                is RappRequest.BrowserAuthenticate, is RappRequest.SignDocument, is RappRequest.BatchSignDocuments -> {
                    fail(bridge, operationId, RappCardFailure.OPERATION_FAILED)
                    return
                }
            }
        if (completed != null) AppTrace.rappOperationCompleted(name, operationId.key, elapsedMicros(startedNs))
    }

    /**
     * The authentication certificate of the card this phone offers, the one
     * `card.status` names; read from the card when only the card can tell.
     * Null when the operation already ended.
     */
    private suspend fun authenticationCertificate(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ): RappCertificate? {
        val certificate =
            (currentCard() as? RappOfferedCard.Present)?.certificate
                ?: run {
                    awaitCard(bridge, operationId, RappAuthAction.BROWSER_AUTH)?.let {
                        fail(bridge, operationId, it)
                        return null
                    }
                    readAuthCertWithTimeout()
                }
        if (certificate == null) {
            fail(bridge, operationId, RappCardFailure.CARD_ERROR)
            return null
        }
        storeReadAuthCertificate(certificate.toWire())
        return certificate
    }

    /** The signature certificate, read from the card, which a read of it needs present. */
    private suspend fun signatureCertificate(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ): CardRun<RappCertificate> {
        val read =
            when (val certificate = signingCertificate(bridge, operationId)) {
                is CardRun.Answered -> certificate.result
                is CardRun.Missing -> return certificate
            }
        val der =
            try {
                read.copyDer()
            } finally {
                read.close()
            }
        return RappCertificate.fromDer(der)?.let { CardRun.Answered(it) }
            ?: CardRun.Missing(RappCardFailure.OPERATION_FAILED)
    }

    internal fun storeReadAuthCertificate(certDer: ByteArray) {
        lastReadAuthCertDer = certDer.copyOf()
        primedCanStore?.writeAuthCertificateDer(certDer)
        val pairId = catalog.listPairs().firstOrNull()?.pairIdHex ?: return
        catalog.updateCertificateDer(pairId, certDer)
    }

    private suspend fun readAuthCertWithTimeout(): RappCertificate? =
        authCardService()?.let { service -> RappCardRead.authenticationCertificate(service) }

    private suspend fun readSignatureCertificateWithTimeout(): NativeQualifiedCertificate? {
        val deferred = CompletableDeferred<NativeQualifiedCertificate?>()
        qualifiedCardService()?.requestQualifiedCertificate { certResult ->
            when (certResult) {
                is NativeCertificateReadResult.Success -> {
                    if (!deferred.complete(certResult.certificate)) certResult.certificate.close()
                }

                else -> {
                    deferred.complete(null)
                }
            }
        } ?: deferred.complete(null)
        return withTimeoutOrNull(RappCardRead.TIMEOUT_MS) { deferred.await() }
    }

    // --- Browser authentication (section 9.2) --------------------------------

    /**
     * The PIN 1 this phone holds in memory for [card] (section 11 item 2):
     * asked once, kept until the card leaves, the card rejects it, the holder
     * clears it or the process ends. A PIN held for another card, or one the
     * card already rejected, is not offered.
     */
    private fun heldPin1(card: AuthenticationCardIdentity): Pin1Submission? {
        val cache = pinCache ?: return null
        val held = cache.take(card) ?: return null
        if (cache.isRejected(held)) {
            held.close()
            return null
        }
        return held
    }

    /** The card this phone holds now, named by its authentication certificate. */
    private suspend fun heldCard(): AuthenticationCardIdentity? =
        (currentCard() as? RappOfferedCard.Present)?.certificate?.toWire()?.let(AuthenticationCardIdentity::of)

    private suspend fun authenticate(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        request: RappRequest.BrowserAuthenticate,
    ) {
        val algorithm = resolveSignAlgorithm(request.algorithm, request.digest)
        if (algorithm == null) {
            fail(bridge, operationId, RappCardFailure.UNSUPPORTED)
            return
        }
        val card = heldCard()
        val held = card?.let(::heldPin1)
        var heldFor = card.takeIf { held != null }
        val first = held ?: askPin1(bridge, operationId, wrongPin = null)
        if (first == null) {
            fail(bridge, operationId, RappCardFailure.USER_CANCELLED)
            return
        }
        HeldPin(first).use { pin ->
            val command = approve(bridge, operationId) as? RappRequest.BrowserAuthenticate ?: return
            while (true) {
                val answer = signAuthentication(bridge, operationId, algorithm, command.digest, pin.submission, heldFor)
                when (answer) {
                    RappCardAnswer.Done -> {
                        return
                    }

                    is RappCardAnswer.Ends -> {
                        fail(bridge, operationId, answer.failure)
                        return
                    }

                    is RappCardAnswer.WrongPin, RappCardAnswer.NotHeld -> {
                        val next = askPin1(bridge, operationId, answer as? RappCardAnswer.WrongPin)
                        if (next == null) {
                            fail(bridge, operationId, RappCardFailure.USER_CANCELLED)
                            return
                        }
                        pin.replace(next)
                        heldFor = null
                    }
                }
            }
        }
    }

    /**
     * Verifies [pin] on the card unless this phone already holds it as the
     * card's verified PIN, then signs [digest] and completes the operation.
     * [pin] goes only to the card it was asked for: a PIN held for [heldFor]
     * is not sent to another card, nor once that card's PIN 1 counter reads
     * below pristine, and every resend reads the counter from the same card
     * (credential custody).
     */
    private suspend fun signAuthentication(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        algorithm: AuthenticationSigningAlgorithm,
        digest: ByteArray,
        pin: Pin1Submission,
        heldFor: AuthenticationCardIdentity?,
    ): RappCardAnswer {
        if (pinCache?.isRejected(pin) == true) return RappCardAnswer.WrongPin.ALREADY_REJECTED
        awaitCard(bridge, operationId, RappAuthAction.BROWSER_AUTH)?.let { return RappCardAnswer.Ends(it) }
        val startedNs = System.nanoTime()
        var service =
            authCardService()
                ?: awaitCard(bridge, operationId, RappAuthAction.BROWSER_AUTH, forcePrompt = true)?.let {
                    return RappCardAnswer.Ends(it)
                } ?: authCardService()
                ?: return RappCardAnswer.Ends(RappCardFailure.CARD_ERROR)
        val card =
            AuthenticationCardReads.identity(service) ?: return RappCardAnswer.Ends(RappCardFailure.CARD_ERROR)
        val attemptsLeft: suspend () -> Int? = { pin1AttemptsLeft(card) }
        val before = attemptsLeft()
        val retention = Pin1Retention.of(card, before)
        if (!custodyContinues(card, heldFor, retention)) return RappCardAnswer.NotHeld
        val cacheGeneration = pinCache?.generation
        var waitFailure = RappCardFailure.CARD_ERROR
        var signBefore = before
        if (pinCache?.isVerified(pin, card) != true) {
            val verifying = service
            val verification =
                when (
                    val run =
                        withPin(
                            bridge,
                            operationId,
                            RappAuthAction.BROWSER_AUTH,
                            before,
                            attemptsLeft,
                            command = {
                                (authCardService() ?: verifying).verifyAuthenticationPin(
                                    Pin1Submission.fromOwnedBytes(pin.copyBytes()),
                                )
                            },
                            cardLeft = { it.result.authenticationFailure()?.meansCardLeft() == true },
                            waitFailure = { waitFailure = it },
                        )
                ) {
                    is RappCardRetry.Run.Answered -> run.result
                    else -> return unanswered(run, waitFailure, pin)
                }
            verification.result.authenticationFailure()?.let { failure ->
                return authenticationAnswer(failure, verification.remainingRetries, pin)
            }
            service = authCardService() ?: service
            signBefore = attemptsLeft()
        }
        var signing = service
        val result =
            when (
                val run =
                    withPin(
                        bridge,
                        operationId,
                        RappAuthAction.BROWSER_AUTH,
                        signBefore,
                        attemptsLeft,
                        command = {
                            signing = authCardService() ?: signing
                            signing.signAuthenticationDigest(
                                algorithm = algorithm,
                                pin1 = Pin1Submission.fromOwnedBytes(pin.copyBytes()),
                                digest = digest,
                            )
                        },
                        cardLeft = { it is AuthenticationSignResult.Failure && it.kind.meansCardLeft() },
                        waitFailure = { waitFailure = it },
                    )
            ) {
                is RappCardRetry.Run.Answered -> run.result
                else -> return unanswered(run, waitFailure, pin)
            }
        return when (result) {
            is AuthenticationSignResult.Success -> {
                authenticated(bridge, operationId, startedNs, Custody(retention, cacheGeneration), pin, signing, result)
            }

            is AuthenticationSignResult.Failure -> {
                authenticationAnswer(result.kind, result.remainingRetries, pin)
            }
        }
    }

    /** The PIN 1 attempts [card] allows when it is the card served now; null otherwise. */
    private suspend fun pin1AttemptsLeft(card: AuthenticationCardIdentity): Int? =
        authCardService()?.let { service -> AuthenticationCardReads.pin1AttemptsLeft(service, card) }

    /**
     * Ends what custody may not keep on [card]: without [retention], its
     * counter read below pristine or not at all, and a PIN held for another
     * card, leave nothing held. True when the PIN in hand, held for
     * [heldFor] or entered when that is null, may go to [card].
     */
    private fun custodyContinues(
        card: AuthenticationCardIdentity,
        heldFor: AuthenticationCardIdentity?,
        retention: Pin1Retention?,
    ): Boolean {
        val heldElsewhere = heldFor != null && heldFor != card
        if (retention == null || heldElsewhere) pinCache?.clear()
        return heldFor == null || (!heldElsewhere && retention != null)
    }

    /** What a refused authentication command means; a wrong PIN is remembered so it is never sent again. */
    private fun authenticationAnswer(
        failure: AuthenticationSignFailure,
        remainingRetries: Int?,
        pin: Pin1Submission,
    ): RappCardAnswer {
        if (failure == AuthenticationSignFailure.WRONG_PIN) {
            pinCache?.recordRejected(pin.copyBytes())
        }
        return RappCardAnswer.of(failure, remainingRetries)
    }

    /**
     * A PIN 1 command the card did not answer. When the attempts fell, the
     * card counted the PIN wrong: it is forgotten and the holder asked again,
     * subject to the floor. Without a count that shows otherwise it is not
     * sent again; a held PIN outlives the failure (credential custody).
     */
    private fun unanswered(
        run: RappCardRetry.Run<*>,
        waitFailure: RappCardFailure,
        pin: Pin1Submission,
    ): RappCardAnswer =
        when (run) {
            is RappCardRetry.Run.Counted -> {
                authenticationAnswer(
                    AuthenticationSignFailure.WRONG_PIN,
                    run.attemptsLeft,
                    pin,
                )
            }

            RappCardRetry.Run.CardMissing -> {
                RappCardAnswer.Ends(waitFailure)
            }

            RappCardRetry.Run.Unproven, is RappCardRetry.Run.Answered -> {
                RappCardAnswer.Ends(RappCardFailure.CARD_ERROR)
            }
        }

    /** The leave to hold an accepted PIN 1, if any, and the custody generation it was read under. */
    private class Custody(
        val retention: Pin1Retention?,
        val generation: Long?,
    )

    /**
     * Holds the accepted PIN 1 in memory when [custody] gives leave, and
     * completes the operation with the signature; without leave the PIN
     * served this operation only.
     */
    private fun authenticated(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        startedNs: Long,
        custody: Custody,
        pin: Pin1Submission,
        service: AuthenticationCardService,
        result: AuthenticationSignResult.Success,
    ): RappCardAnswer {
        try {
            val retention = custody.retention
            val generation = custody.generation
            if (retention != null && onAuthenticationVerified != null && generation != null) {
                if (!onAuthenticationVerified.invoke(pin.copyBytes(), retention, generation)) {
                    return RappCardAnswer.Ends(RappCardFailure.CARD_ERROR)
                }
            } else if (retention != null) {
                pinCache?.recordVerified(pin.copyBytes(), retention, generation)
            }
            ensureAuthCertCached(service)
            val rawSignature = result.signature.copyBytes()
            val coordinateBytes = RappEcdsaWireSignature.coordinateBytes(result.signature.algorithm.keyProfile)
            val wireSignature =
                if (coordinateBytes != null) {
                    RappEcdsaWireSignature.toRaw(rawSignature, coordinateBytes)
                } else {
                    rawSignature
                }
            act(bridge) { it.completeSignature(operationId.toWire(), wireSignature) }
            AppTrace.rappOperationCompleted("browser_auth", operationId.key, elapsedMicros(startedNs))
            return RappCardAnswer.Done
        } finally {
            result.signature.close()
        }
    }

    private fun ensureAuthCertCached(service: AuthenticationCardService) {
        if (lastReadAuthCertDer != null) return
        service.requestAuthenticationCertificate { cert ->
            try {
                cert?.copyDer()?.let { der ->
                    storeReadAuthCertificate(der)
                }
            } catch (_: Exception) {
            } finally {
                cert?.close()
            }
        }
    }

    private fun resolveSignAlgorithm(
        algorithm: RappSignatureAlgorithm,
        digest: ByteArray,
    ): AuthenticationSigningAlgorithm? =
        when (algorithm) {
            RappSignatureAlgorithm.ECDSA_SHA256 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            RappSignatureAlgorithm.ECDSA_SHA384 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA256 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256
            RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA512 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512
            RappSignatureAlgorithm.RSA_PSS_SHA256 -> AuthenticationSigningAlgorithm.RSA_PSS_SHA256
            else -> fallbackSignAlgorithm(digest.size)
        }

    private fun fallbackSignAlgorithm(digestSize: Int): AuthenticationSigningAlgorithm? =
        when (digestSize) {
            SHA256_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            SHA384_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            else -> null
        }

    // --- Document signing (section 9.3) --------------------------------------

    /**
     * Signs [documents] in order with the one PIN 2 entry the holder
     * approved, then answers with [complete] over the signatures. A wrong PIN
     * asks the holder again; signing that stops delivers no signature.
     */
    private suspend fun signDocuments(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        keyProfile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        documents: List<RappDocument>,
        complete: List<ByteArray>.(RappOperationBridge) -> RappBridgeAction,
    ) {
        val names = documents.map { it.name }
        val qualified = resolveQualifiedAlgorithm(keyProfile, algorithm)
        if (qualified == null) {
            fail(bridge, operationId, RappCardFailure.UNSUPPORTED)
            return
        }
        val first = askPin2(bridge, operationId, names, wrongPin = null)
        if (first == null) {
            fail(bridge, operationId, RappCardFailure.USER_CANCELLED)
            return
        }
        HeldPin(first).use { pin ->
            val command = approve(bridge, operationId) ?: return
            val digests =
                when (command) {
                    is RappRequest.SignDocument -> listOf(command.document.digest)
                    is RappRequest.BatchSignDocuments -> command.documents.map { it.digest }
                    else -> return fail(bridge, operationId, RappCardFailure.OPERATION_FAILED)
                }
            val startedNs = System.nanoTime()
            val certificate =
                when (val read = signingCertificate(bridge, operationId)) {
                    is CardRun.Answered -> read.result
                    is CardRun.Missing -> return fail(bridge, operationId, read.failure)
                }
            val signatures = mutableListOf<ByteArray>()
            val outcome =
                try {
                    RappBatchSignatureRun(
                        digests = digests,
                        sign = { digest ->
                            signDocument(bridge, operationId, names, qualified, certificate, digest, pin)
                        },
                        record = { signature ->
                            if (command is RappRequest.BatchSignDocuments) {
                                bridge.recordBatchSignature(operationId.toWire(), signature)
                            }
                            signatures += signature
                        },
                    ).run()
                } finally {
                    certificate.close()
                }
            when (outcome) {
                RappBatchSignatureRun.Outcome.Completed -> {
                    act(bridge) { signatures.complete(it) }
                    AppTrace.rappOperationCompleted("document_sign", operationId.key, elapsedMicros(startedNs))
                }

                is RappBatchSignatureRun.Outcome.Stopped -> {
                    fail(bridge, operationId, outcome.failure)
                }
            }
        }
    }

    /** Brings the card and reads the signature certificate the card must sign with. */
    private suspend fun signingCertificate(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
    ): CardRun<NativeQualifiedCertificate> {
        awaitCard(bridge, operationId, RappAuthAction.DOCUMENT_SIGN)?.let { return CardRun.Missing(it) }
        if (qualifiedCardService() == null) {
            awaitCard(bridge, operationId, RappAuthAction.DOCUMENT_SIGN, forcePrompt = true)?.let {
                return CardRun.Missing(it)
            }
        }
        val certificate =
            readSignatureCertificateWithTimeout()
                ?: awaitCard(bridge, operationId, RappAuthAction.DOCUMENT_SIGN, forcePrompt = true)?.let {
                    return CardRun.Missing(it)
                } ?: readSignatureCertificateWithTimeout()
        return if (certificate != null) CardRun.Answered(certificate) else CardRun.Missing(RappCardFailure.CARD_ERROR)
    }

    private suspend fun signDocument(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        names: List<String>,
        algorithm: QualifiedSigningAlgorithm,
        certificate: NativeQualifiedCertificate,
        digest: ByteArray,
        pin: HeldPin<Pin2Submission>,
    ): RappBatchSignatureRun.Step {
        while (true) {
            var waitFailure = RappCardFailure.CARD_ERROR
            val result =
                when (
                    val run =
                        qualifiedSignature(bridge, operationId, algorithm, certificate, digest, pin.submission) {
                            waitFailure = it
                        }
                ) {
                    is RappCardRetry.Run.Answered -> {
                        run.result
                    }

                    is RappCardRetry.Run.Counted -> {
                        QualifiedSignResult.Failure(QualifiedSignFailure.WRONG_PIN, run.attemptsLeft)
                    }

                    RappCardRetry.Run.CardMissing -> {
                        return RappBatchSignatureRun.Step.Failed(waitFailure)
                    }

                    RappCardRetry.Run.Unproven -> {
                        return RappBatchSignatureRun.Step.Failed(RappCardFailure.CARD_ERROR)
                    }
                }
            val failure =
                when (result) {
                    is QualifiedSignResult.Success -> {
                        return try {
                            RappBatchSignatureRun.Step.Signed(wireSignature(result))
                        } finally {
                            result.signature.close()
                        }
                    }

                    is QualifiedSignResult.Failure -> {
                        result
                    }
                }
            when (val answer = RappCardAnswer.of(failure.kind, failure.remainingRetries)) {
                is RappCardAnswer.WrongPin -> {
                    val next =
                        askPin2(bridge, operationId, names, answer)
                            ?: return RappBatchSignatureRun.Step.Failed(RappCardFailure.USER_CANCELLED)
                    pin.replace(next)
                }

                is RappCardAnswer.Ends -> {
                    return RappBatchSignatureRun.Step.Failed(answer.failure)
                }

                RappCardAnswer.Done, RappCardAnswer.NotHeld -> {
                    return RappBatchSignatureRun.Step.Failed(RappCardFailure.OPERATION_FAILED)
                }
            }
        }
    }

    /**
     * One qualified signature over [digest]. A card that left the field
     * before answering is waited for, and the command repeated with the
     * certificate read afresh from it only when the PIN 2 attempts show the
     * card did not count the PIN (section 10.2); [waitFailure] receives why a
     * wait ended without a card.
     */
    private suspend fun qualifiedSignature(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        algorithm: QualifiedSigningAlgorithm,
        certificate: NativeQualifiedCertificate,
        digest: ByteArray,
        pin: Pin2Submission,
        waitFailure: (RappCardFailure) -> Unit,
    ): RappCardRetry.Run<QualifiedSignResult> {
        var fresh: NativeQualifiedCertificate? = null
        val attemptsLeft: suspend () -> Int? = {
            qualifiedCardService()?.let { service -> RappCardRead.pin2AttemptsLeft(service) }
        }
        return try {
            RappCardRetry.run(
                before = attemptsLeft(),
                attemptsLeft = attemptsLeft,
                command = {
                    requestQualifiedSignature(algorithm, fresh ?: certificate, digest, pin)
                        ?: QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)
                },
                cardLeft = { it is QualifiedSignResult.Failure && it.kind == QualifiedSignFailure.CARD_UNAVAILABLE },
            ) {
                val failure = awaitCard(bridge, operationId, RappAuthAction.DOCUMENT_SIGN, forcePrompt = true)
                if (failure != null) waitFailure(failure)
                fresh = if (failure == null) readSignatureCertificateWithTimeout() else null
                fresh != null
            }
        } finally {
            fresh?.close()
        }
    }

    private suspend fun requestQualifiedSignature(
        algorithm: QualifiedSigningAlgorithm,
        certificate: NativeQualifiedCertificate,
        digest: ByteArray,
        pin: Pin2Submission,
    ): QualifiedSignResult? {
        val service = qualifiedCardService() ?: return null
        val deferred = CompletableDeferred<QualifiedSignResult>()
        service.requestQualifiedDigestSignature(
            algorithm = algorithm,
            pin2 = Pin2Submission.fromOwnedBytes(pin.copyBytes()),
            digest = digest,
            expectedCertificate = certificate,
        ) { result -> deferred.complete(result) }
        return deferred.await()
    }

    /** The section 9.2 wire form of a qualified signature: raw `r || s` for ECDSA. */
    private fun wireSignature(result: QualifiedSignResult.Success): ByteArray {
        val rawSig = result.signature.copyBytes()
        val coordinateBytes = RappEcdsaWireSignature.coordinateBytes(result.signature.algorithm.keyProfile)
        return if (coordinateBytes != null) {
            RappEcdsaWireSignature.toRaw(rawSig, coordinateBytes)
        } else {
            rawSig
        }
    }

    private fun resolveQualifiedAlgorithm(
        keyProfile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
    ): QualifiedSigningAlgorithm? =
        when (algorithm) {
            RappSignatureAlgorithm.ECDSA_SHA384 -> {
                QualifiedSigningAlgorithm.ECDSA_P384_SHA384
            }

            RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> {
                QualifiedSigningAlgorithm.RSA_PKCS1_SHA384
            }

            else -> {
                when (keyProfile) {
                    RappCardKeyProfile.ECDSA_P384 -> QualifiedSigningAlgorithm.ECDSA_P384_SHA384
                    RappCardKeyProfile.RSA3072 -> QualifiedSigningAlgorithm.RSA_PKCS1_SHA384
                    else -> null
                }
            }
        }

    override fun close() {
        isClosed = true
        RappCustodianService.stop(context)
        withdrawalJob?.cancel()
        withdrawalJob = null
        hintRefreshJob?.cancel()
        hintRefreshJob = null
        endSession()
        activeListener?.close()
        activeListener = null
        sessionRouting?.close()
        sessionRouting = null
        cardStatusLane.close()
    }
}

/**
 * Whether a failure means the card was not in the field for the command, so
 * the request waits for the card and tries once more instead of failing.
 */
private fun AuthenticationSignFailure.meansCardLeft(): Boolean =
    this == AuthenticationSignFailure.CARD_UNAVAILABLE ||
        this == AuthenticationSignFailure.TRANSPORT_ERROR ||
        this == AuthenticationSignFailure.BRIDGE_ERROR
