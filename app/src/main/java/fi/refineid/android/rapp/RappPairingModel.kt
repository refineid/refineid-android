@file:Suppress("TooGenericExceptionCaught", "MagicNumber", "MaxLineLength", "TooManyFunctions")

package fi.refineid.android.rapp

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.RefineIdApplication
import fi.refineid.android.diagnostics.AppTrace
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.rappStreamProfileName

internal sealed interface PairingPhase {
    data object Idle : PairingPhase

    data class Offering(
        val code: String,
        val secondsRemaining: Int,
    ) : PairingPhase

    data class Connecting(
        val message: String,
    ) : PairingPhase

    data class Failed(
        val reason: String,
    ) : PairingPhase
}

private const val LISTENER_CLOSE_DELAY_MS = 2000L
private const val HANDSHAKE_DEADLINE_MS = 10_000L
private const val MILLISECONDS_PER_SECOND = 1_000L
private const val CPACE_RANDOM_BYTES = 64
private const val OFFER_ID_BYTES = 32

/** The countdown of an offer that has no time left, or of no offer. */
private const val NO_SECONDS_REMAINING = 0

/** Why no code shows while Android 17's local network permission is not granted (ADR 0041 section 2.3). */
private const val LOCAL_NETWORK_CLOSED_REASON = "Allow local network access"

/** The offer failure the debug trace names when the local network is closed. */
private const val LOCAL_NETWORK_CLOSED_FAILURE = "local_network_permission_missing"

/** The credential profiles every offer grants (RAPP v26.10.29 section 9). */
private val DEFAULT_PAIRING_PROFILES =
    listOf(
        "fi.refineid.card-status",
        "fi.refineid.authentication",
        "fi.refineid.document-signing",
    )

/**
 * The Remote Access page's pairing side: the offer and its code, the
 * ceremony a computer runs against it, and the paired devices.
 *
 * While Remote Access is on, the page always shows a pairing code, whatever
 * computers are connected: on opening, on turning Remote Access on, when an
 * offer expires, after a pairing completes or fails, and after a pairing is
 * removed. A wrong code, or a connection lost during an attempt, leaves the
 * code on screen (RAPP v26.10.29 section 3.3 item 4). The offer lives only
 * while the page is open: leaving it calls [reset].
 *
 * [mainDispatcher] runs the offer's countdown and deadlines; [pairVault]
 * stands in for the application's vault, [connectedPeers] for the
 * custodian's open session, and [monotonicMs] for the continuous clock; a
 * connection that has not completed its handshake within
 * [handshakeDeadlineMs] of connecting is closed.
 */
internal class RappPairingModel(
    private val context: Context,
    private val scope: CoroutineScope,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val pairVault: RappPairVault? = null,
    connectedPeers: StateFlow<PairedPeer?>? = null,
    private val handshakeDeadlineMs: Long = HANDSHAKE_DEADLINE_MS,
    private val monotonicMs: () -> ULong = RappClock::monotonicMs,
) : AutoCloseable {
    private val catalog = RappPairCatalog(context)

    /** The live offer's listener; a listener it replaced is ignored while it drains. */
    @Volatile
    private var listener: StreamRelayListener? = null
    private var pairingBridge: RappPairingBridge? = null
    private var timerJob: Job? = null
    private var handshakeDeadlineJob: Job? = null
    private var activeOfferingCode: String? = null
    private var offerSeconds = NO_SECONDS_REMAINING
    private var secondsRemaining = NO_SECONDS_REMAINING
    private var ceremony: RappCustodianPairingCeremony? = null
    private var awaitingPreamble = false

    /**
     * The connection the listener's events are of, taken when it connects;
     * null once it ended. The listener delivers every event of a connection
     * before it takes the next.
     */
    private var candidate: StreamRelayConnection? = null

    /** The live offer's answers to pairing connections; null without an offer. */
    @Volatile
    private var pairingBootstrap: RappPairingBootstrap? = null

    /** The connection's CPace start was refused, so its step 1 is answered busy. */
    private var refusingStepOne = false
    private val preAuthenticationLimiter = RappPreAuthenticationLimiter()
    private val app = context.applicationContext as? RefineIdApplication

    var phase by mutableStateOf<PairingPhase>(PairingPhase.Idle)
        private set

    var pairedDevices by mutableStateOf<List<PairedPeer>>(catalog.listPairs())
        private set

    var activeConnectedPeer by mutableStateOf<PairedPeer?>(null)
        private set

    val settings = RappSettings(context)

    private var _isRemoteAccessEnabled by mutableStateOf(settings.isCardRemoteAccessEnabled)
    val isRemoteAccessEnabled: Boolean
        get() = _isRemoteAccessEnabled

    init {
        val peers = connectedPeers ?: app?.rappProxyDispatcher?.connectedPeer
        if (peers != null) {
            scope.launch {
                peers.collect { peer ->
                    activeConnectedPeer = peer
                    // A peer that forgot this phone ends its session and leaves the list.
                    pairedDevices = catalog.listPairs()
                }
            }
        }
        // A pairing that idle expiry forgot leaves the list (RAPP v26.10.29 section 4.6 item 5).
        app?.rappProxyDispatcher?.pairingsExpired?.let { expired ->
            scope.launch { expired.collect { pairedDevices = catalog.listPairs() } }
        }
    }

    fun setRemoteAccessEnabled(enabled: Boolean) {
        settings.isCardRemoteAccessEnabled = enabled
        _isRemoteAccessEnabled = enabled
        if (enabled) {
            val app = context.applicationContext as? RefineIdApplication
            app?.startRappProxyListening()
            offerWhileOn()
        } else {
            reset()
            val app = context.applicationContext as? RefineIdApplication
            app?.rappProxyDispatcher?.withdraw()
        }
    }

    /**
     * Shows a new pairing code when Remote Access is on and none is shown,
     * whether or not a computer is connected or paired; a code that is shown,
     * a ceremony under way, or a failure on screen stays.
     */
    fun offerWhileOn() {
        if (isRemoteAccessEnabled && phase is PairingPhase.Idle) createOffer()
    }

    /** A ceremony ended: while Remote Access is on, the next code follows. */
    private fun nextOffer() {
        if (isRemoteAccessEnabled) createOffer()
    }

    /** The code's port on this phone's stream listener, for a test that pairs over it. */
    @VisibleForTesting
    internal val offerPort: Int?
        get() = listener?.port

    fun createOffer() {
        reset()
        if (!isRemoteAccessEnabled) {
            settings.isCardRemoteAccessEnabled = true
            _isRemoteAccessEnabled = true
        }
        val startedAtMonotonicMs = monotonicMs()
        // Without the local network the stream cannot be found or reached;
        // the page says so where the code would be, and the retry asks again.
        if (!LocalNetworkPermission.isGranted(context)) {
            AppTrace.rappOfferFailed(LOCAL_NETWORK_CLOSED_FAILURE)
            phase = PairingPhase.Failed(LOCAL_NETWORK_CLOSED_REASON)
            return
        }
        val code = RappPairingCode.generate()
        activeOfferingCode = code
        val offerId = ByteArray(OFFER_ID_BYTES).also { java.security.SecureRandom().nextBytes(it) }

        try {
            val proxyBridge =
                RappPairingBridge.createCustodianOffer(
                    offerId = offerId,
                    profiles = DEFAULT_PAIRING_PROFILES,
                    transportProfiles = listOf(rappStreamProfileName()),
                    startedAtMonotonicMs = startedAtMonotonicMs,
                )
            pairingBridge = proxyBridge
            pairingBootstrap = RappPairingBootstrap(proxyBridge, preAuthenticationLimiter, rappStreamProfileName())
            ceremony = null
            offerSeconds = (proxyBridge.offerTtlMs().toLong() / MILLISECONDS_PER_SECOND).toInt()
            secondsRemaining = offerSeconds

            lateinit var relayListener: StreamRelayListener
            relayListener =
                StreamRelayListener(
                    context = context,
                    scope = scope,
                    handshakeTimeoutMs = handshakeDeadlineMs,
                ) { event ->
                    handleProxyListenerEvent(relayListener, event, proxyBridge, code)
                }
            relayListener.answerWhileHeld = { preamble ->
                val answer = pairingBootstrap?.answerWhileHeld(preamble, monotonicMs())
                (answer as? RappPairingBootstrap.Answer.Busy)?.frame
            }
            listener = relayListener
            relayListener.start(
                StreamRendezvousName.ephemeralName(),
                StreamRendezvousName.attributes(StreamRendezvousName.MODE_PAIRING),
            )

            phase = PairingPhase.Offering(code = code, secondsRemaining = offerSeconds)
            startCountdown()
        } catch (e: Throwable) {
            AppTrace.rappOfferFailed(e.javaClass.simpleName)
            phase = PairingPhase.Failed("Failed to initialize remote pairing offer")
        } finally {
            offerId.fill(0)
        }
    }

    /**
     * The holder answered the permissions turning Remote Access on asked
     * for. A local network the holder opened serves the paired computers
     * again and starts the offer that waited for it; any other answer
     * changes nothing here.
     */
    fun permissionsAnswered(answers: Map<String, Boolean>) {
        if (answers[LocalNetworkPermission.NAME] != true) return
        app?.startRappProxyListening()
        if (phase is PairingPhase.Failed) createOffer()
    }

    /**
     * Handles an event of [source], the listener it was installed on; an
     * event of a listener the page no longer offers on is dropped.
     */
    private fun handleProxyListenerEvent(
        source: StreamRelayListener,
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
        code: String,
    ) {
        if (source !== listener) return
        when (event) {
            is StreamRelayEvent.Connected -> {
                handleProxyConnected(source)
            }

            is StreamRelayEvent.Frame -> {
                candidate?.let { handleProxyFrame(source, it, event, bridge, code) }
            }

            is StreamRelayEvent.Disconnected -> {
                handleProxyDisconnected(bridge)
            }

            is StreamRelayEvent.Error -> {
                handshakeDeadlineJob?.cancel()
                handshakeDeadlineJob = null
                AppTrace.rappPairingFailed("connection-error " + event.cause.javaClass.simpleName)
                phase = PairingPhase.Failed("Connection error")
            }
        }
    }

    /**
     * A new connection opens with its routing preamble, which
     * [beginCandidate] answers; its handshake deadline runs from now. A
     * connection that ended before this event is not taken.
     */
    private fun handleProxyConnected(source: StreamRelayListener) {
        ceremony = null
        refusingStepOne = false
        val connection = source.currentConnection
        candidate = connection
        awaitingPreamble = connection != null
        connection?.let(::startHandshakeDeadline)
    }

    /**
     * Answers the connection's routing preamble (RAPP v26.10.29 section
     * 4.2): a pairing preamble the offer can admit gets the offer, and CPace
     * starts; one it cannot admit, through the limiter of section 3.3 item 6
     * or because an attempt holds the offer, gets `pairing-busy` and the
     * connection closes. Any other first frame closes the connection
     * without touching the offer. Only a started attempt changes the screen.
     */
    private fun beginCandidate(
        connection: StreamRelayConnection,
        preamble: ByteArray,
        bridge: RappPairingBridge,
        code: String,
    ) {
        awaitingPreamble = false
        val now = monotonicMs()
        val offer =
            when (val answer = pairingBootstrap?.answer(preamble, now) ?: RappPairingBootstrap.Answer.Close) {
                is RappPairingBootstrap.Answer.Offer -> answer.frame
                else -> return refuse(connection, answer)
            }
        val candidateId = bridge.offerCandidates().first { it.profile == rappStreamProfileName() }.candidateId
        connection.send(offer)
        val random64 = ByteArray(CPACE_RANDOM_BYTES).apply { java.security.SecureRandom().nextBytes(this) }
        try {
            bridge.beginCpace(
                candidateId = candidateId,
                pairingCode = code,
                randomBytes64 = random64,
                nowMonotonicMs = now,
            )
        } catch (_: RappBindingException.RateLimited) {
            refusingStepOne = true
            return
        } catch (_: RappBindingException.WrongPhase) {
            refusingStepOne = true
            return
        } finally {
            random64.fill(0)
        }
        val vault = vault()
        ceremony =
            RappCustodianPairingCeremony(
                bridge = bridge,
                offeredProfiles = DEFAULT_PAIRING_PROFILES,
                displayName = localDeviceDisplayName(),
                platform = "Android",
                monotonicMs = monotonicMs,
                wallMs = RappClock::wallMs,
                persistUnconfirmed = { record -> record.persistDeviceOnly(vault) },
            )
        phase = PairingPhase.Connecting("Connected! Starting security handshake...")
    }

    /**
     * Sends a busy answer and closes the connection, or closes it unanswered
     * (section 4.2, "Busy Refusal"); the offer and the screen stay as they are.
     */
    private fun refuse(
        connection: StreamRelayConnection,
        answer: RappPairingBootstrap.Answer,
    ) {
        if (answer is RappPairingBootstrap.Answer.Busy) connection.send(answer.frame)
        connection.disconnect()
    }

    private fun vault(): RappPairVault = pairVault ?: app?.rappVault ?: AndroidRappVault(context)

    /**
     * Destroys the record a ceremony stored but the requester never
     * confirmed (RAPP v26.10.29 section 4.3 item 4); nobody is told.
     */
    private fun revokeUnconfirmedRecord() {
        val stored = ceremony?.storedRecord ?: return
        RappPairRevocation.revoke(stored.pairing().id, stored, vault())
    }

    private fun handleProxyDisconnected(bridge: RappPairingBridge) {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        candidate = null
        awaitingPreamble = false
        if (phase is PairingPhase.Connecting) {
            candidateEnded(bridge)
        }
    }

    /**
     * Ends the connection's attempt. Before T_A the offer stays as it was
     * for another connection while its lifetime remains (section 3.3 item 4);
     * after T_A the ceremony is over. Either way the next code follows an
     * offer that ended.
     */
    private fun candidateEnded(bridge: RappPairingBridge) {
        val pastOffer = ceremony?.isPastOfferPhase == true
        revokeUnconfirmedRecord()
        ceremony = null
        if (pastOffer) {
            AppTrace.rappPairingFailed("peer-disconnected")
            phase = PairingPhase.Failed("Peer disconnected")
            nextOffer()
            return
        }
        val now = monotonicMs()
        val offerKept =
            try {
                bridge.candidateFailed(now)
            } catch (_: Exception) {
                false
            }
        if (offerKept) {
            restoreOfferingOrWaiting()
        } else {
            nextOffer()
        }
    }

    private fun handleProxyFrame(
        source: StreamRelayListener,
        connection: StreamRelayConnection,
        event: StreamRelayEvent.Frame,
        bridge: RappPairingBridge,
        code: String,
    ) {
        try {
            if (awaitingPreamble) {
                beginCandidate(connection, event.data, bridge, code)
                return
            }
            if (refusingStepOne) {
                refusingStepOne = false
                val answer = pairingBootstrap?.answerInPlaceOfStepTwo(monotonicMs())
                refuse(connection, answer ?: RappPairingBootstrap.Answer.Close)
                return
            }
            val active = ceremony ?: return
            when (val outcome = active.receive(event.data)) {
                is RappCustodianPairingCeremony.Outcome.Send -> {
                    outcome.frames.forEach { frame -> connection.send(frame) }
                    startHandshakeDeadline(connection)
                }

                is RappCustodianPairingCeremony.Outcome.Paired -> {
                    finalizeProxyPairing(source, outcome.record, outcome.peer)
                }
            }
        } catch (e: Throwable) {
            handshakeDeadlineJob?.cancel()
            handshakeDeadlineJob = null
            if (ceremony?.isPastOfferPhase == true) {
                revokeUnconfirmedRecord()
                ceremony = null
                AppTrace.rappPairingFailed("ceremony " + e.javaClass.simpleName)
                phase = PairingPhase.Failed("Pairing error: ${e.javaClass.simpleName}")
                nextOffer()
            } else {
                AppTrace.rappPairingFailed("attempt " + e.javaClass.simpleName)
                connection.disconnect()
            }
        }
    }

    private fun finalizeProxyPairing(
        source: StreamRelayListener,
        record: uniffi.refineid_rapp.RappPairRecord,
        hello: uniffi.refineid_rapp.RappPeerHello,
    ) {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        source.clearSocketTimeout()
        val pairing = record.pairing()
        val peer =
            PairedPeer(
                pairIdHex = pairing.id.key,
                displayName = hello.displayName.takeIf { it.isNotBlank() } ?: "Computer",
                platform = hello.platform.takeIf { it.isNotBlank() } ?: "Unknown",
                createdAtMs = System.currentTimeMillis(),
            )

        val app = context.applicationContext as? RefineIdApplication
        val vault = vault()
        record.replaceDeviceOnly(vault)

        val primedStore = app?.primedCanStore
        val certDer =
            primedStore?.readAuthCertificateDer()
                ?: app?.nfcReaderController?.currentAuthenticationCertificateDer
                ?: app?.rappProxyDispatcher?.cachedAuthCertDer
        if (certDer != null) {
            app?.rappProxyDispatcher?.storeReadAuthCertificate(certDer)
        }

        catalog.savePair(
            pairId = pairing.id.toWire(),
            displayName = peer.displayName,
            platform = peer.platform,
            createdAtMs = peer.createdAtMs,
            holderName = null,
            certificateDerBase64 = null,
        )
        pairedDevices = catalog.listPairs()
        phase = PairingPhase.Idle

        // The paired connection's last frames drain before its listener
        // closes; the listener's later events are dropped.
        listener = null
        scope.launch {
            kotlinx.coroutines.delay(LISTENER_CLOSE_DELAY_MS)
            source.close()
        }

        app?.let { it.rappProxyDispatcher.startListening(it.rappVault) }
        // The next computer pairs with the next code.
        offerWhileOn()
    }

    /**
     * Closes [connection] [handshakeDeadlineMs] from now unless it reached
     * the next step meanwhile: while it owes its preamble, its step 1 after
     * a refused CPace start, or the next frame of its ceremony. The close
     * ends the candidate as a lost connection does, showing nothing new; a
     * connection that followed it is left alone.
     */
    private fun startHandshakeDeadline(connection: StreamRelayConnection) {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob =
            scope.launch(mainDispatcher) {
                delay(handshakeDeadlineMs)
                if (awaitingPreamble || refusingStepOne || phase is PairingPhase.Connecting) {
                    connection.disconnect()
                }
            }
    }

    private fun restoreOfferingOrWaiting() {
        val code = activeOfferingCode
        if (code != null) {
            phase = PairingPhase.Offering(code = code, secondsRemaining = secondsRemaining)
        } else {
            phase = PairingPhase.Connecting("Waiting for peer...")
        }
        ceremony = null
    }

    private fun startCountdown() {
        timerJob?.cancel()
        timerJob =
            scope.launch(mainDispatcher) {
                for (sec in offerSeconds downTo NO_SECONDS_REMAINING) {
                    secondsRemaining = sec
                    val current = phase
                    if (current is PairingPhase.Offering) {
                        phase = current.copy(secondsRemaining = sec)
                    }
                    delay(1000L)
                }
                offerExpired()
            }
    }

    /**
     * The offer's lifetime ran out (RAPP v26.10.29 section 3.3 item 7) and
     * the next code follows: an unused offer and an attempt still in its
     * offer phase end with it. A ceremony past CPace is exempt from the
     * offer's lifetime; it runs to its own deadlines, and the next code
     * follows its end.
     */
    @VisibleForTesting
    internal fun offerExpired() {
        if (ceremony?.isPastOfferPhase == true) return
        if (phase is PairingPhase.Offering || phase is PairingPhase.Connecting) nextOffer()
    }

    /**
     * Forgets one pairing (RAPP v26.10.29 section 4.6), updates what this
     * phone serves, and shows a code while Remote Access stays on, the last
     * pairing's removal included.
     */
    fun removePair(pairIdHex: String) {
        forgetPairing(pairIdHex)
        pairedDevices = catalog.listPairs()
        app?.rappProxyDispatcher?.pairingsChanged()
        offerWhileOn()
    }

    /**
     * Forgets one pairing (section 4.6). An open session to it is closed
     * with `pairing_revoked` and the record destroyed at once; otherwise the
     * record keeps its key only to deliver that close on the next session,
     * and leaves the list of paired devices.
     */
    private fun forgetPairing(pairIdHex: String) {
        val vault = vault()
        if (activeConnectedPeer?.pairIdHex == pairIdHex) {
            activeConnectedPeer = null
        }
        val pairId = RappPairId.fromKey(pairIdHex)
        when {
            pairId == null -> {
                catalog.removePair(pairIdHex)
            }

            app?.rappProxyDispatcher?.closePairingRevoked(pairId) == true -> {
                RappPairRevocation.revoke(pairId, vault)
                catalog.removePair(pairIdHex)
            }

            RappPairRevocation.forget(pairId, vault) -> {
                catalog.markForgotten(pairIdHex, System.currentTimeMillis())
            }

            else -> {
                catalog.removePair(pairIdHex)
            }
        }
    }

    fun reset() {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        timerJob?.cancel()
        timerJob = null
        activeOfferingCode = null
        secondsRemaining = NO_SECONDS_REMAINING
        listener?.close()
        listener = null
        try {
            pairingBridge?.cancelPairing()
        } catch (_: Exception) {
        }
        pairingBridge = null
        pairingBootstrap = null
        revokeUnconfirmedRecord()
        ceremony = null
        candidate = null
        awaitingPreamble = false
        refusingStepOne = false
        phase = PairingPhase.Idle
        pairedDevices = catalog.listPairs()
    }

    /** Forgets every pairing, each as [removePair] does, and turns Remote Access off. */
    fun terminate() {
        reset()
        for (pair in catalog.listPairs()) {
            forgetPairing(pair.pairIdHex)
        }
        pairedDevices = catalog.listPairs()
        activeConnectedPeer = null
        settings.isCardRemoteAccessEnabled = false
        _isRemoteAccessEnabled = false
        app?.rappProxyDispatcher?.pairingsChanged()
    }

    private fun localDeviceDisplayName(): String {
        val deviceName =
            try {
                android.provider.Settings.Global
                    .getString(
                        context.contentResolver,
                        android.provider.Settings.Global.DEVICE_NAME,
                    )?.trim()
            } catch (_: Exception) {
                null
            }
        if (!deviceName.isNullOrBlank()) {
            return deviceName
        }
        val model =
            android.os.Build.MODEL
                ?.trim()
        if (!model.isNullOrBlank()) {
            return model
        }
        return "Android"
    }

    override fun close() {
        reset()
    }
}
