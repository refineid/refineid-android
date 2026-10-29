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
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappAnnouncementCandidate
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCardReader
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.RappProgressEvent
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappSessionRecord
import uniffi.refineid_rapp.rappWithdrawnRecord
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The custodian side of RAPP v26.10.29: serves the paired computers' sessions
 * over the stream transport and over Bluetooth (`fi.refineid.rapp.ble`,
 * section 5), asks the holder for PINs on this phone, and runs the card
 * commands through the card services.
 *
 * The phone serves one session at a time whichever transport carries it
 * (STPA CC-67): a dial on either transport opens a session only as
 * [RappSessionAdmission] allows, and a busy session is never displaced.
 * Operations take the card one at a time, in the order they arrived, across
 * that session and any earlier one whose card command is still finishing
 * (section 8.2 item 2).
 *
 * Session state changes, and every frame is queued on its transport, under
 * one lock. Each transport writes its frames off the calling thread, in the
 * order they were queued, and closes a connection only after the frames
 * queued before; so frames leave in the order their bridge sealed them, a
 * frame of one session never goes out on another's transport, and every
 * public call returns without waiting on the network.
 */
internal class RappPhoneProxyDispatcher(
    private val context: Context,
    private val scope: CoroutineScope,
    private val inbox: RappAuthorizationInbox,
    pinCache: AuthenticationPinCache? = null,
    private val primedCanStore: PrimedCanStore? = null,
    private val authCardService: () -> AuthenticationCardService?,
    private val qualifiedCardService: () -> QualifiedCardService?,
    private val isCardReady: () -> Boolean = { false },
    private val awaitCardReady: suspend () -> Boolean = { false },
    private val offeredCard: suspend () -> RappOfferedCard = { RappOfferedCard.Absent },
    private val cardReader: () -> RappCardReader = { RappCardReader.ABSENT },
    private val onAuthenticationVerified: ((ByteArray, Pin1Retention, Long) -> Boolean)? = null,
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var bleServer: RappBleGattServer? = null
    private var sessionRouting: RappSessionRouting? = null
    private var withdrawalJob: Job? = null
    private var hintRefreshJob: Job? = null
    private var idleExpiryJob: Job? = null
    private var vault: AndroidRappVault? = null
    private val catalog = RappPairCatalog(context)
    private val dialGate = RappSessionDialGate(RappPreAuthenticationLimiter())
    private val pin1Custody = RappPin1Custody(pinCache)

    @Volatile
    private var isClosed = false

    /** Whether the holder switched Remote Access off and the withdrawal is under way (section 4.5). */
    private var withdrawing = false

    /** The connection that carries the session; null while none is routed. */
    @Volatile
    private var served: RappServedTransport? = null

    /** Ends a Bluetooth session whose handshake has not completed in time. */
    private var handshakeDeadlineJob: Job? = null

    /** Monotonic milliseconds when the session was established. */
    private var establishedAtMs = 0L

    /** Monotonic milliseconds when the session's last operation ended. */
    @Volatile
    private var lastOperationEndedMs = 0L

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

    /** Guards the session's state and its transport; frames are queued in the order their bridge sealed them. */
    private val sessionLock = Any()

    /** The card serves one operation at a time (section 8.2 item 2). */
    private val card = Mutex()

    /** The session whose operation holds [card]; null while the card is free. */
    @Volatile
    private var cardHolder: RappOperationBridge? = null

    /** One lane for card reports: the two readers' listeners call in on their own threads. */
    private val cardStatusLane = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    /** The card and reader last reported on the open session; null before the first report. */
    @Volatile
    private var reportedCard: RappCardReport? = null

    @Volatile
    private var lastReadAuthCertDer: ByteArray? = null

    private val _connectedPeer = MutableStateFlow<PairedPeer?>(null)
    val connectedPeer: StateFlow<PairedPeer?> = _connectedPeer.asStateFlow()

    private val _pairingsExpired = MutableStateFlow(0)

    /** How many pairings idle expiry forgot while this process ran; the list of paired computers follows it. */
    val pairingsExpired: StateFlow<Int> = _pairingsExpired.asStateFlow()

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

        /** How long a routed Bluetooth link has to complete `Noise_KK`, the stream listener's bound. */
        private const val BLUETOOTH_HANDSHAKE_DEADLINE_MS = StreamRelayListener.DEFAULT_HANDSHAKE_TIMEOUT_MS

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
     * discovery hierarchy section 4.2-4.3), and the Bluetooth server beside
     * it when the holder allows it.
     *
     * It is published under a fresh random instance name with TXT `v=1`,
     * `mode=session` and the rotating hints of the most recently used
     * pairings. Each connection names its pairing only through the routing
     * tag in its preamble.
     */
    fun startListening(vault: AndroidRappVault) {
        synchronized(sessionLock) {
            if (isClosed) return
            withdrawalJob?.cancel()
            withdrawalJob = null
            // A withdrawal stopped the advertisement for good; serving again starts a fresh server.
            if (withdrawing) stopBluetooth()
            withdrawing = false
            this.vault = vault
            // The new listener ends the stream's connection; a Bluetooth session keeps its link.
            if (served == RappServedTransport.Stream) dropConnection()
            activeListener?.close()
            sessionRouting?.close()
            sessionRouting = RappSessionRouting()
            listen(vault)
            serveBluetooth()
        }
    }

    private fun listen(vault: AndroidRappVault) {
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
        // forgotten record past its notice window (RAPP v26.10.29 section 4.6
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
        val pairs = RappStoredPairs.served(catalog, vlt)
        val serves = pairs.any { it.pairing.role == RappEndpointRole.PROXY }
        pairs.forEach { it.record.close() }
        if (serves) refreshAnnouncement() else stopListening()
    }

    /**
     * Session-mode TXT attributes carrying the current rotating discovery
     * hints of the most recently used custodian pairings (discovery
     * hierarchy section 4.3), forgotten ones included: their peers keep
     * dialing until the close reaches them (RAPP v26.10.29 section 4.6 item
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
     * (RAPP v26.10.29 section 4.6 item 1). Returns true when the session was
     * established and carried the `pairing_revoked` close, so the caller
     * destroys the record at once; false when no session to the pairing was
     * open. A session still in its handshake is dropped, and the next one
     * delivers the close.
     */
    fun closePairingRevoked(pairId: RappPairId): Boolean {
        synchronized(sessionLock) {
            val pair = routed
            if (pair?.pairing?.id != pairId) return false
            val bridge = operationBridge
            if (bridge == null) {
                dropConnection()
                return false
            }
            // The caller revokes the pairing next, so the session's end records no time for it.
            routed = null
            val closed = act(bridge) { it.closeWithReason(RappCloseReason.PAIRING_REVOKED) } != null
            dropConnection()
            pair.record.close()
            return closed
        }
    }

    /**
     * Sweeps the pairings for idle expiry every
     * [RappIdleExpiry.SWEEP_INTERVAL_MS] until this dispatcher closes,
     * whether or not the phone serves (RAPP v26.10.29 section 4.6 item 5);
     * the start's sweep is [RappStoredPairs.cleanAtStartup]'s.
     */
    fun startIdleExpiry(vault: RappPairVault) {
        synchronized(sessionLock) {
            if (isClosed || idleExpiryJob != null) return
            idleExpiryJob =
                scope.launch {
                    while (isActive) {
                        delay(RappIdleExpiry.SWEEP_INTERVAL_MS)
                        sweepIdlePairings(vault)
                    }
                }
        }
    }

    /**
     * Sweeps every pairing for idle expiry under the session lock, so the
     * session cannot come up or end meanwhile: the pairing of an established
     * session is recorded, never expired, and one whose session is coming
     * up is left for the next sweep. A pairing that expired leaves the list
     * of paired computers and nothing else shows it.
     */
    private fun sweepIdlePairings(vault: RappPairVault) {
        synchronized(sessionLock) {
            if (isClosed) return
            val session = routed?.let { RappServedSession(it.pairing.id, established = operationBridge != null) }
            val expired = RappIdleExpiry.sweep(catalog, vault, RappClock.wallMs(), session)
            if (expired.isNotEmpty()) _pairingsExpired.update { it + expired.size }
        }
    }

    /**
     * The card this phone holds, or its card reader, may have changed:
     * reports both on the open session (RAPP v26.10.29 section 8.4 item 1).
     * Present is a card in the reader, from insertion until removal or the
     * reader's detachment, or an NFC card the holder added to the phone,
     * until the holder removes it; a card busy with an operation, or one
     * that did not answer an operation, stays present.
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
            val report = RappCardReport(currentCard(), cardReader())
            if (report == reportedCard) return
            if (act(bridge) { it.reportCardStatus(report.certificateWire(), report.reader) } != null) {
                reportedCard = report
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
     * Withdraws the service the user switched off (RAPP v26.10.29 section
     * 4.5): the open session, on either transport, is closed as withdrawn;
     * the listener and the Bluetooth server stop accepting and the
     * advertisement stops; the instance is advertised as withdrawn for a few
     * seconds, and then everything stops. The Bluetooth advertisement carries
     * no withdrawal (section 4.5 item 5). It returns at once: the close is
     * queued on the session's transport, which writes it before it closes.
     */
    fun withdraw() {
        synchronized(sessionLock) {
            hintRefreshJob?.cancel()
            hintRefreshJob = null
            operationBridge?.let { bridge -> act(bridge) { it.closeWithReason(RappCloseReason.SERVICE_WITHDRAWN) } }
            dropConnection()
            withdrawing = true
            bleServer?.stopAdvertising()
            val listener = activeListener
            val vlt = vault
            val instance = listener?.registeredName
            if (listener == null || vlt == null || instance == null) {
                stopListening()
                return
            }
            val now = StreamRendezvousName.nowUnixSeconds().toULong()
            val withdrawn =
                try {
                    StreamRendezvousName.attributes(
                        rappWithdrawnRecord(announcementCandidates(vlt) { it.withdrawalHint(instance, now) }),
                    )
                } catch (_: Exception) {
                    null
                }
            if (withdrawn == null) {
                stopListening()
                return
            }
            listener.withdraw(withdrawn)
            withdrawalJob?.cancel()
            withdrawalJob =
                scope.launch {
                    delay(WITHDRAWN_ANNOUNCEMENT_MS)
                    synchronized(sessionLock) { if (activeListener === listener) stopListening() }
                }
        }
    }

    fun stopListening() {
        synchronized(sessionLock) {
            RappCustodianService.stop(context)
            sessionRouting?.close()
            sessionRouting = null
            hintRefreshJob?.cancel()
            hintRefreshJob = null
            dropConnection()
            stopBluetooth()
            activeListener?.close()
            activeListener = null
            announcedInstance = null
            vault = null
            withdrawing = false
        }
    }

    /** Drops the connected computer and publishes the listener afresh. */
    fun disconnectClient() {
        synchronized(sessionLock) {
            dropConnection()
            activeListener?.close()
            val vlt = vault
            if (vlt != null && !isClosed) {
                startListening(vlt)
            }
        }
    }

    /**
     * Serves over Bluetooth beside the listener, once the holder allowed it
     * (`BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`); without the permission
     * the phone serves over the stream alone. The server publishes the RAPP
     * service once and advertises while the phone serves, and follows the
     * Bluetooth radio on and off by itself.
     */
    fun serveBluetooth() {
        synchronized(sessionLock) {
            if (isClosed || withdrawing || activeListener == null || bleServer != null) return
            if (!RappBleGattServer.permitted(context)) {
                AppTrace.rappBleServer(RappBleServerStep.PERMISSION_MISSING)
                return
            }
            lateinit var server: RappBleGattServer
            server =
                RappBleGattServer(
                    context,
                    admits = { preamble, link -> admitBluetooth(server, preamble, link) },
                    onEvent = { event -> bluetoothEvent(server, event) },
                )
            bleServer = server
            server.start()
        }
    }

    /**
     * The holder answered the permissions turning Remote Access on asked for
     * ([answers] maps each asked permission to whether it was granted). With
     * nearby devices granted the phone serves over Bluetooth too; declined, it
     * serves over the stream alone, and the debug trace says so.
     */
    fun bluetoothPermissionsAnswered(answers: Map<String, Boolean>) {
        if (RappBleGattServer.PERMISSIONS.any { answers[it] == false }) {
            AppTrace.rappBleServer(RappBleServerStep.PERMISSION_DENIED)
        }
        serveBluetooth()
    }

    private fun stopBluetooth() {
        bleServer?.cancel()
        bleServer = null
    }

    /**
     * Admits the routing preamble of [link] on [server]'s lane: a session
     * preamble routed to a pairing this phone serves (section 2.2.1), within
     * the pre-authentication bound (section 3.3 item 6) and the one-session
     * rule (CC-67). The session opens here; its handshake must complete
     * within [BLUETOOTH_HANDSHAKE_DEADLINE_MS].
     */
    private fun admitBluetooth(
        server: RappBleGattServer,
        preamble: ByteArray,
        link: RappBleLink,
    ): Boolean {
        synchronized(sessionLock) {
            val vlt = vault
            val transport = RappServedTransport.Bluetooth(link)
            val refusal =
                when {
                    bleServer !== server || vlt == null || withdrawing || isClosed -> RappDialRefusal.NOT_SERVING
                    else -> null
                }
            if (refusal != null || vlt == null) {
                AppTrace.rappDialRefused(transport.profile, refusal ?: RappDialRefusal.NOT_SERVING)
                return false
            }
            val pair = admitRouted(vlt, transport.profile, preamble) ?: return false
            if (!admit(pair, transport)) {
                pair.record.close()
                return false
            }
            if (!open(vlt, pair, transport)) return false
            handshakeDeadlineJob =
                scope.launch {
                    delay(BLUETOOTH_HANDSHAKE_DEADLINE_MS)
                    synchronized(sessionLock) {
                        if (served == transport && operationBridge == null) {
                            AppTrace.rappDialRefused(transport.profile, RappDialRefusal.HANDSHAKE_DEADLINE)
                            dropConnection()
                        }
                    }
                }
            return true
        }
    }

    /** One event of [server]'s links, on its lane. */
    private fun bluetoothEvent(
        server: RappBleGattServer,
        event: RappBleGattEvent,
    ) {
        AppTrace.rappBleLink(event)
        synchronized(sessionLock) {
            if (bleServer !== server) return
            when (event) {
                is RappBleGattEvent.Frame -> {
                    if (served ==
                        RappServedTransport.Bluetooth(event.link)
                    ) {
                        vault?.let { sessionFrame(it, event.frame) }
                    }
                }

                is RappBleGattEvent.Closed -> {
                    if (served == RappServedTransport.Bluetooth(event.link)) endSession()
                }

                is RappBleGattEvent.Subscribed, is RappBleGattEvent.Routed, is RappBleGattEvent.Unsubscribed -> {}
            }
        }
    }

    /**
     * One event of the stream listener, which holds one connection at a
     * time. A connection that comes or goes ends only a session the stream
     * carries; a session on Bluetooth is not the stream's to end.
     */
    private fun handleRelayEvent(event: StreamRelayEvent) {
        synchronized(sessionLock) {
            when (event) {
                is StreamRelayEvent.Connected -> {
                    if (served == RappServedTransport.Stream) endSession()
                }

                is StreamRelayEvent.Frame -> {
                    val vlt = vault ?: return
                    when (served) {
                        RappServedTransport.Stream -> sessionFrame(vlt, event.data)
                        else -> routeStream(vlt, event.data)
                    }
                }

                is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                    AppTrace.rappConnectionDropped(
                        if (event is StreamRelayEvent.Error) {
                            event.cause.javaClass.simpleName
                        } else {
                            "stream disconnected"
                        },
                    )
                    if (served == RappServedTransport.Stream) endSession()
                }
            }
        }
    }

    /** One frame of the session [served] carries: the handshake first, then the established session. */
    private fun sessionFrame(
        vault: AndroidRappVault,
        data: ByteArray,
    ) {
        val bridge = operationBridge
        if (bridge != null) {
            receive(bridge, data)
            return
        }
        val session = sessionBridge
        val pair = routed
        if (session == null || pair == null) {
            dropConnection()
        } else {
            handshake(vault, session, pair, data)
        }
    }

    /**
     * The stream connection's first frame must be the session preamble of a
     * served pairing, which alone counts against the pre-authentication
     * bound (section 3.3 item 6), and the session this phone serves must
     * admit it;
     * anything else closes the connection unanswered and changes no stored
     * state (RAPP v26.10.29 section 2.2.1).
     */
    private fun routeStream(
        vault: AndroidRappVault,
        preamble: ByteArray,
    ) {
        val transport = RappServedTransport.Stream
        val pair = admitRouted(vault, transport.profile, preamble)
        if (pair == null) {
            activeListener?.disconnectClient()
            return
        }
        if (!admit(pair, transport)) {
            pair.record.close()
            activeListener?.disconnectClient()
            return
        }
        open(vault, pair, transport)
    }

    /**
     * The served pairing [preamble] routes to on [profile], admitted under
     * the pre-authentication bound; null when it routes to none or the bound
     * refuses it.
     */
    private fun admitRouted(
        vault: AndroidRappVault,
        profile: RappTransportProfile,
        preamble: ByteArray,
    ): RappStoredPair? =
        dialGate.admit(
            nowMonotonicMs = RappClock.monotonicMs(),
            route = { routeServed(vault, profile, preamble) },
            release = { it.record.close() },
            onRateLimited = { AppTrace.rappDialRefused(profile, RappDialRefusal.RATE_LIMITED) },
        )

    /** The served pairing [preamble] routes to on [profile], or null when it routes to none. */
    private fun routeServed(
        vault: AndroidRappVault,
        profile: RappTransportProfile,
        preamble: ByteArray,
    ): RappStoredPair? {
        val pairs = RappStoredPairs.served(catalog, vault)
        val record =
            try {
                sessionRouting?.route(profile, preamble, pairs.map { it.record })
            } catch (_: Exception) {
                null
            }
        val pair = pairs.firstOrNull { it.record === record }
        pairs.filter { it !== pair }.forEach { it.record.close() }
        if (pair == null) AppTrace.rappDialRefused(profile, RappDialRefusal.NO_PAIRING)
        return pair
    }

    /**
     * Whether a dial routed to [pair] on [transport] gets the session (CC-67).
     * An idle session it may take is ended and its transport closed; a busy
     * one is never displaced (UCA-66).
     */
    private fun admit(
        pair: RappStoredPair,
        transport: RappServedTransport,
    ): Boolean {
        val verdict =
            RappSessionAdmission.decide(
                incoming = pair.pairing.id,
                serving = routed?.pairing?.id,
                idleSinceMs = idleSinceMs(),
                nowMs = RappClock.monotonicMs().toLong(),
            )
        when (verdict) {
            RappSessionAdmission.ADMIT -> {}

            RappSessionAdmission.REFUSE_BUSY -> {
                AppTrace.rappDialRefused(transport.profile, RappDialRefusal.BUSY)
            }

            RappSessionAdmission.REFUSE_HELD -> {
                AppTrace.rappDialRefused(transport.profile, RappDialRefusal.HELD)
            }
        }
        if (!verdict.admits) return false
        if (served != null) dropConnection()
        return true
    }

    /** When the open session went idle; null while none is established or it carries an operation. */
    private fun idleSinceMs(): Long? =
        if (operationBridge == null || operationJob?.isCompleted == false) {
            null
        } else {
            maxOf(establishedAtMs, lastOperationEndedMs)
        }

    /** Opens the session [pair] routed on [transport]; false when the bridge could not begin. */
    private fun open(
        vault: AndroidRappVault,
        pair: RappStoredPair,
        transport: RappServedTransport,
    ): Boolean {
        served = transport
        routed = pair
        return try {
            sessionBridge = RappSessionBridge.beginProxy(pair.record, vault, transport.profile.profileName)
            true
        } catch (_: Exception) {
            dropConnection()
            false
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
            establish(vault, session, pair)
        } catch (_: Exception) {
            dropConnection()
        }
    }

    /**
     * The first and only message of a session to a forgotten pairing: the
     * `pairing_revoked` close, after which the record's key is destroyed
     * (RAPP v26.10.29 section 4.6 items 2 and 3).
     */
    private fun deliverRevocationNotice(
        vault: AndroidRappVault,
        session: RappSessionBridge,
        pair: RappStoredPair,
    ) {
        send(session.deliverRevocationNotice())
        routed = null
        RappPairRevocation.revoke(pair, catalog, vault)
        dropConnection()
        pairingsChanged()
    }

    /** The session is established: its pairing's session time is recorded (section 4.6 item 5). */
    private fun establish(
        vault: RappPairVault,
        session: RappSessionBridge,
        pair: RappStoredPair,
    ) {
        if (served == RappServedTransport.Stream) activeListener?.clearSocketTimeout()
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        establishedAtMs = RappClock.monotonicMs().toLong()
        val bridge = RappOperationBridge.beginProxy(session, MAXIMUM_OPERATION_LIFETIME_MS, RappClock.monotonicMs())
        cardReported = CompletableDeferred()
        reportedCard = null
        operationBridge = bridge
        RappIdleExpiry.recordSession(pair.record, vault, RappClock.wallMs())
        startLivenessLoop(bridge)
        cardChanged()
        catalog.markUsed(pair.peer.pairIdHex, System.currentTimeMillis())
        _connectedPeer.value = pair.peer
        AppTrace.rappPairingCompleted(pair.peer.displayName)
    }

    /** Queues one frame on the connection, before the session's bridge exists. */
    private fun send(frame: ByteArray) {
        synchronized(sessionLock) { transportSend(frame) }
    }

    /** Queues [frame] on the transport that carries the session. */
    private fun transportSend(frame: ByteArray) {
        when (val transport = served) {
            RappServedTransport.Stream -> {
                (activeListener ?: throw IOException("listener closed")).send(frame)
            }

            is RappServedTransport.Bluetooth -> {
                val server = bleServer ?: throw IOException("server closed")
                server.send(transport.link, frame)
            }

            null -> {
                throw IOException("no session")
            }
        }
    }

    /** Closes [transport], the stream connection or the Bluetooth link, once its queued frames are out. */
    private fun closeTransport(transport: RappServedTransport?) {
        when (transport) {
            RappServedTransport.Stream -> {
                activeListener?.disconnectClient()
            }

            is RappServedTransport.Bluetooth -> {
                bleServer?.close(transport.link)
            }

            null -> {}
        }
    }

    /**
     * Runs one call on the session's bridge, types its action at the binding
     * border, and queues the frame it sealed, so frames leave in the order
     * the bridge sealed them; a closing session ends here, its transport
     * closing after the frame. Null when [bridge] no longer serves the
     * session or the call failed.
     */
    private fun act(
        bridge: RappOperationBridge,
        call: (RappOperationBridge) -> RappBridgeAction,
    ): RappBridgeOutcome? {
        synchronized(sessionLock) {
            if (bridge !== operationBridge) return null
            val outcome =
                try {
                    RappBridgeOutcome.from(call(bridge))
                } catch (_: Exception) {
                    return null
                }
            if (outcome is RappBridgeOutcome.Send) {
                try {
                    transportSend(outcome.frame)
                } catch (_: IOException) {
                }
            }
            when {
                outcome is RappBridgeOutcome.Closed -> sessionClosed(outcome.reason)
                outcome is RappBridgeOutcome.Send && outcome.closesWith != null -> dropConnection()
            }
            return outcome
        }
    }

    /**
     * The session closed, and with it its operation and any prompt for it.
     * A requester that forgot this phone closes it with `pairing_revoked`,
     * and the pairing is revoked here at once (RAPP v26.10.29 section 4.6
     * item 4). One that withdrew closes it with `service_withdrawn`: this
     * phone sends no close of its own and keeps the pairing (section 4.5
     * item 9).
     */
    private fun sessionClosed(reason: RappCloseReason?) {
        if (reason == RappCloseReason.SERVICE_WITHDRAWN) AppTrace.rappPeerWithdrew()
        val pair = routed.takeIf { reason == RappCloseReason.PAIRING_REVOKED }
        if (pair != null) routed = null
        dropConnection()
        val vlt = vault ?: return
        if (pair != null) {
            RappPairRevocation.revoke(pair, catalog, vlt)
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
                        synchronized(sessionLock) { if (bridge === operationBridge) dropConnection() }
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
     * card's answer, which nothing delivers. An established session's end is
     * recorded as its pairing's session time (section 4.6 item 5).
     */
    private fun endSession() {
        synchronized(sessionLock) {
            livenessJob?.cancel()
            livenessJob = null
            operationJob?.cancel()
            operationJob = null
            handshakeDeadlineJob?.cancel()
            handshakeDeadlineJob = null
            served = null
            val bridge = operationBridge
            operationBridge = null
            bridge?.close()
            sessionBridge?.close()
            sessionBridge = null
            val pair = routed
            routed = null
            val vlt = vault
            if (bridge != null && pair != null && vlt != null) {
                RappIdleExpiry.recordSession(pair.record, vlt, RappClock.wallMs())
            }
            pair?.record?.close()
            cardReported = null
            reportedCard = null
            lastReadAuthCertDer = null
            _connectedPeer.value = null
            dismissInbox()
        }
    }

    /** Closes the session's transport and ends the session; the pairing stays. */
    private fun dropConnection() {
        synchronized(sessionLock) {
            AppTrace.rappConnectionDropped("proxy dispatcher dropConnection")
            val transport = served
            endSession()
            closeTransport(transport)
        }
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
                } finally {
                    lastOperationEndedMs = RappClock.monotonicMs().toLong()
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
     * The prompt names the computer. Entering the PIN is the holder's consent, reported
     * once the operation's first prompt is on screen when [firstPrompt]
     * (section 8.2 item 3); a prompt after a wrong PIN says so to the holder
     * and reports nothing, so the Requester learns nothing of it (section
     * 10.2).
     */
    private suspend fun askPin1(
        bridge: RappOperationBridge,
        operationId: RappOperationId,
        wrongPin: RappCardAnswer.WrongPin?,
        firstPrompt: Boolean,
    ): Pin1Submission? {
        val answer = CompletableDeferred<Pin1Submission?>()
        withContext(Dispatchers.Main) {
            inbox.askBrowserAuth(
                requestId = operationId.key,
                requester = requesterName(),
                onApproved = { pin -> if (!answer.complete(pin)) pin.close() },
                onDenied = { answer.complete(null) },
                onShown = { if (firstPrompt) reportConsentShown(bridge, operationId) },
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
        firstPrompt: Boolean,
    ): Pin2Submission? {
        val answer = CompletableDeferred<Pin2Submission?>()
        withContext(Dispatchers.Main) {
            inbox.askDocumentSign(
                requestId = operationId.key,
                requester = requesterName(),
                documentNames = names,
                onApproved = { pin -> if (!answer.complete(pin)) pin.close() },
                onDenied = { answer.complete(null) },
                onShown = { if (firstPrompt) reportConsentShown(bridge, operationId) },
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
        val held = card?.let(pin1Custody::held)
        var heldFor = card.takeIf { held != null }
        val first = held ?: askPin1(bridge, operationId, wrongPin = null, firstPrompt = true)
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
                        // Only a held PIN can come before the operation's first prompt.
                        val next =
                            askPin1(
                                bridge,
                                operationId,
                                answer as? RappCardAnswer.WrongPin,
                                firstPrompt = heldFor != null,
                            )
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
        if (pin1Custody.refused(pin)) return RappCardAnswer.WrongPin.ALREADY_REJECTED
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
        if (!pin1Custody.admits(card, heldFor, retention)) return RappCardAnswer.NotHeld
        val cacheGeneration = pin1Custody.generation
        var waitFailure = RappCardFailure.CARD_ERROR
        var signBefore = before
        if (!pin1Custody.holds(pin, card)) {
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

    /** What a refused authentication command means; a wrong PIN is remembered so it is never sent again. */
    private fun authenticationAnswer(
        failure: AuthenticationSignFailure,
        remainingRetries: Int?,
        pin: Pin1Submission,
    ): RappCardAnswer {
        if (failure == AuthenticationSignFailure.WRONG_PIN) {
            pin1Custody.refuse(pin)
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
                pin1Custody.hold(pin, retention, generation)
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
        val first = askPin2(bridge, operationId, names, wrongPin = null, firstPrompt = true)
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
                        askPin2(bridge, operationId, names, answer, firstPrompt = false)
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
     * before answering is waited for, and the command repeated only when the
     * card back holds [certificate], so the PIN 2 typed for it reaches no
     * other card, and the PIN 2 attempts show the card did not count the PIN
     * (section 10.2); [waitFailure] receives why a wait ended without a card.
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
                fresh?.copyDer()?.contentEquals(certificate.copyDer()) == true
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
        synchronized(sessionLock) {
            isClosed = true
            RappCustodianService.stop(context)
            idleExpiryJob?.cancel()
            idleExpiryJob = null
            withdrawalJob?.cancel()
            withdrawalJob = null
            hintRefreshJob?.cancel()
            hintRefreshJob = null
            dropConnection()
            stopBluetooth()
            activeListener?.close()
            activeListener = null
            sessionRouting?.close()
            sessionRouting = null
        }
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
