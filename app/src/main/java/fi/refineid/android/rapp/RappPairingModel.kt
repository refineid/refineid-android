@file:Suppress("TooGenericExceptionCaught", "MagicNumber", "MaxLineLength", "TooManyFunctions")

package fi.refineid.android.rapp

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.RefineIdApplication
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.rappPairingPreamble
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
 * stands in for the application's vault and [connectedPeers] for the
 * custodian's open session.
 */
internal class RappPairingModel(
    private val context: Context,
    private val scope: CoroutineScope,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main,
    private val pairVault: RappPairVault? = null,
    connectedPeers: StateFlow<PairedPeer?>? = null,
) : AutoCloseable {
    private val catalog = RappPairCatalog(context)
    private var listener: StreamRelayListener? = null
    private var pairingBridge: RappPairingBridge? = null
    private var timerJob: Job? = null
    private var handshakeDeadlineJob: Job? = null
    private var activeOfferingCode: String? = null
    private var offerSeconds = NO_SECONDS_REMAINING
    private var secondsRemaining = NO_SECONDS_REMAINING
    private var ceremony: RappCustodianPairingCeremony? = null
    private var awaitingPreamble = false
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
        val startedAtMonotonicMs = RappClock.monotonicMs()
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
            ceremony = null
            offerSeconds = (proxyBridge.offerTtlMs().toLong() / MILLISECONDS_PER_SECOND).toInt()
            secondsRemaining = offerSeconds

            val relayListener =
                StreamRelayListener(
                    context = context,
                    scope = scope,
                    handshakeTimeoutMs = HANDSHAKE_DEADLINE_MS,
                ) { event ->
                    handleProxyListenerEvent(event, proxyBridge, code)
                }
            listener = relayListener
            relayListener.start(
                StreamRendezvousName.ephemeralName(),
                StreamRendezvousName.attributes(StreamRendezvousName.MODE_PAIRING),
            )

            phase = PairingPhase.Offering(code = code, secondsRemaining = offerSeconds)
            startCountdown()
        } catch (_: Throwable) {
            phase = PairingPhase.Failed("Failed to initialize remote pairing offer")
        } finally {
            offerId.fill(0)
        }
    }

    private fun handleProxyListenerEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
        code: String,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                handleProxyConnected()
            }

            is StreamRelayEvent.Frame -> {
                handleProxyFrame(event, bridge, code)
            }

            is StreamRelayEvent.Disconnected -> {
                handleProxyDisconnected(bridge)
            }

            is StreamRelayEvent.Error -> {
                handshakeDeadlineJob?.cancel()
                handshakeDeadlineJob = null
                phase = PairingPhase.Failed("Connection error")
            }
        }
    }

    /**
     * A new connection must be admitted by the pre-authentication limiter
     * (RAPP v26.10.29 section 3.3) and then open with the pairing preamble.
     */
    private fun handleProxyConnected() {
        ceremony = null
        if (!preAuthenticationLimiter.admit(RappClock.monotonicMs())) {
            awaitingPreamble = false
            listener?.disconnectClient()
            return
        }
        awaitingPreamble = true
        phase = PairingPhase.Connecting("Connected! Starting security handshake...")
        startHandshakeDeadline()
    }

    /**
     * Serves the offer bootstrap (section 4.2) and starts CPace after the
     * requester's pairing preamble; any other first frame closes the
     * connection without touching the offer.
     */
    private fun beginCandidate(
        preamble: ByteArray,
        bridge: RappPairingBridge,
        code: String,
    ) {
        awaitingPreamble = false
        if (!preamble.contentEquals(rappPairingPreamble(rappStreamProfileName()))) {
            listener?.disconnectClient()
            return
        }
        val now = RappClock.monotonicMs()
        val candidateId = bridge.offerCandidates().first { it.profile == rappStreamProfileName() }.candidateId
        listener?.send(bridge.bootstrapBytes(now))
        val random64 = ByteArray(CPACE_RANDOM_BYTES).apply { java.security.SecureRandom().nextBytes(this) }
        try {
            bridge.beginCpace(
                candidateId = candidateId,
                pairingCode = code,
                randomBytes64 = random64,
                nowMonotonicMs = now,
            )
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
                monotonicMs = RappClock::monotonicMs,
                wallMs = RappClock::wallMs,
                persistUnconfirmed = { record -> record.persistDeviceOnly(vault) },
            )
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
            phase = PairingPhase.Failed("Peer disconnected")
            nextOffer()
            return
        }
        val now = RappClock.monotonicMs()
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
        event: StreamRelayEvent.Frame,
        bridge: RappPairingBridge,
        code: String,
    ) {
        try {
            if (awaitingPreamble) {
                beginCandidate(event.data, bridge, code)
                return
            }
            val active = ceremony ?: return
            when (val outcome = active.receive(event.data)) {
                is RappCustodianPairingCeremony.Outcome.Send -> {
                    outcome.frames.forEach { frame -> listener?.send(frame) }
                    startHandshakeDeadline()
                }

                is RappCustodianPairingCeremony.Outcome.Paired -> {
                    finalizeProxyPairing(outcome.record, outcome.peer)
                }
            }
        } catch (e: Throwable) {
            handshakeDeadlineJob?.cancel()
            handshakeDeadlineJob = null
            if (ceremony?.isPastOfferPhase == true) {
                revokeUnconfirmedRecord()
                ceremony = null
                phase = PairingPhase.Failed("Pairing error: ${e.javaClass.simpleName}")
                nextOffer()
            } else {
                listener?.disconnectClient()
            }
        }
    }

    private fun finalizeProxyPairing(
        record: uniffi.refineid_rapp.RappPairRecord,
        hello: uniffi.refineid_rapp.RappPeerHello,
    ) {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        listener?.clearSocketTimeout()
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

        val oldListener = listener
        listener = null
        scope.launch {
            kotlinx.coroutines.delay(LISTENER_CLOSE_DELAY_MS)
            oldListener?.close()
        }

        app?.let { it.rappProxyDispatcher.startListening(it.rappVault) }
        // The next computer pairs with the next code.
        offerWhileOn()
    }

    private fun startHandshakeDeadline() {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob =
            scope.launch(mainDispatcher) {
                delay(HANDSHAKE_DEADLINE_MS)
                if (phase is PairingPhase.Connecting) {
                    listener?.disconnectClient()
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
        revokeUnconfirmedRecord()
        ceremony = null
        awaitingPreamble = false
        phase = PairingPhase.Idle
        pairedDevices = catalog.listPairs()
    }

    /** Forgets every pairing, each as [removePair] does. */
    fun terminate() {
        reset()
        for (pair in catalog.listPairs()) {
            forgetPairing(pair.pairIdHex)
        }
        pairedDevices = catalog.listPairs()
        activeConnectedPeer = null
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
