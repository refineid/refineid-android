@file:Suppress("TooGenericExceptionCaught", "MagicNumber", "MaxLineLength", "TooManyFunctions")

package fi.refineid.android.rapp

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.RefineIdApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBackoff
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappPreAuthenticationLimiter
import uniffi.refineid_rapp.rappStreamPairingPreamble
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

    data class Paired(
        val peer: PairedPeer,
    ) : PairingPhase

    data class Failed(
        val reason: String,
    ) : PairingPhase
}

private const val LISTENER_CLOSE_DELAY_MS = 2000L
private const val HANDSHAKE_DEADLINE_MS = 10_000L
private const val MILLISECONDS_PER_SECOND = 1_000L
private const val DEFAULT_PAIRING_COUNTDOWN_SECONDS =
    (RappPairingCode.DEFAULT_LIFETIME_MS / MILLISECONDS_PER_SECOND).toInt()
private const val CPACE_RANDOM_BYTES = 64
private const val OFFER_ID_BYTES = 32
private const val STREAM_CANDIDATE_ID = "stream-1"
private val DEFAULT_PAIRING_PROFILES =
    listOf(
        "fi.refineid.card-status.v1",
        "fi.refineid.authentication.v1",
        "fi.refineid.document-signing.v1",
    )

internal class RappPairingModel(
    private val context: Context,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val catalog = RappPairCatalog(context)
    private var listener: StreamRelayListener? = null
    private var pairingBridge: RappPairingBridge? = null
    private var timerJob: Job? = null
    private var handshakeDeadlineJob: Job? = null
    private var activeOfferingCode: String? = null
    private var secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS
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
        val dispatcher = app?.rappProxyDispatcher
        if (dispatcher != null) {
            scope.launch {
                dispatcher.connectedPeer.collect { peer ->
                    activeConnectedPeer = peer
                }
            }
        }
    }

    fun setRemoteAccessEnabled(enabled: Boolean) {
        settings.isCardRemoteAccessEnabled = enabled
        _isRemoteAccessEnabled = enabled
        if (enabled) {
            val app = context.applicationContext as? RefineIdApplication
            if (pairedDevices.isNotEmpty()) {
                app?.startRappProxyListening()
            }
            if (phase is PairingPhase.Idle && activeConnectedPeer == null) {
                createOffer()
            }
        } else {
            reset()
            val app = context.applicationContext as? RefineIdApplication
            app?.rappProxyDispatcher?.disconnectClient()
            app?.rappProxyDispatcher?.stopListening()
        }
    }

    fun disconnectActivePeer() {
        app?.rappProxyDispatcher?.disconnectClient()
    }

    fun createOffer() {
        reset()
        if (!isRemoteAccessEnabled) {
            settings.isCardRemoteAccessEnabled = true
            _isRemoteAccessEnabled = true
        }
        val startedAtMonotonicMs = RappClock.monotonicMs()
        val backoffMs = pairingBackoff.msUntilNextOffer(startedAtMonotonicMs)
        if (backoffMs > 0UL) {
            val seconds = (backoffMs.toLong() + MILLISECONDS_PER_SECOND - 1) / MILLISECONDS_PER_SECOND
            phase = PairingPhase.Failed("Too many attempts. Try again in $seconds s")
            return
        }
        val code = RappPairingCode.generate()
        activeOfferingCode = code
        secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS
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

            phase = PairingPhase.Offering(code = code, secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS)
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
     * (RAPP v26.10.9 section 3.3) and then open with the pairing preamble.
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
        if (!preamble.contentEquals(rappStreamPairingPreamble())) {
            listener?.disconnectClient()
            return
        }
        val now = RappClock.monotonicMs()
        listener?.send(bridge.bootstrapBytes(now))
        val random64 = ByteArray(CPACE_RANDOM_BYTES).apply { java.security.SecureRandom().nextBytes(this) }
        try {
            bridge.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = code,
                randomBytes64 = random64,
                nowMonotonicMs = now,
            )
        } finally {
            random64.fill(0)
        }
        ceremony =
            RappCustodianPairingCeremony(
                bridge = bridge,
                offeredProfiles = DEFAULT_PAIRING_PROFILES,
                displayName = localDeviceDisplayName(),
                platform = "Android",
                monotonicMs = RappClock::monotonicMs,
                wallMs = RappClock::wallMs,
            )
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
     * Spends the connection's attempt. Before T_A the offer stays for another
     * connection while attempts and lifetime remain; after T_A, or once the
     * third attempt failed, the ceremony is over.
     */
    private fun candidateEnded(bridge: RappPairingBridge) {
        val pastOffer = ceremony?.isPastOfferPhase == true
        ceremony = null
        if (pastOffer) {
            phase = PairingPhase.Failed("Peer disconnected")
            return
        }
        val now = RappClock.monotonicMs()
        val offerKept =
            try {
                bridge.candidateFailed(now)
            } catch (_: RappBindingException.AttemptsExhausted) {
                false
            } catch (_: Exception) {
                false
            }
        if (offerKept) {
            restoreOfferingOrWaiting()
        } else {
            pairingBackoff.recordLockout(now)
            phase = PairingPhase.Failed("Too many attempts")
            reset(keepPhase = true)
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
                ceremony = null
                phase = PairingPhase.Failed("Pairing error: ${e.javaClass.simpleName}")
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
        val peer =
            PairedPeer(
                pairIdHex = record.metadata().pairId.joinToString("") { "%02x".format(it) },
                displayName = hello.displayName.takeIf { it.isNotBlank() } ?: "Computer",
                platform = hello.platform.takeIf { it.isNotBlank() } ?: "Unknown",
                createdAtMs = System.currentTimeMillis(),
            )

        val app = context.applicationContext as? RefineIdApplication
        val vault = app?.rappVault ?: AndroidRappVault(context)
        record.persistDeviceOnly(vault)

        val primedStore = app?.primedCanStore
        val certDer =
            primedStore?.readAuthCertificateDer()
                ?: app?.nfcReaderController?.currentAuthenticationCertificateDer
                ?: app?.rappProxyDispatcher?.cachedAuthCertDer
        if (certDer != null) {
            app?.rappProxyDispatcher?.storeReadAuthCertificate(certDer)
        }

        catalog.savePair(
            pairId = record.metadata().pairId,
            displayName = peer.displayName,
            platform = peer.platform,
            createdAtMs = peer.createdAtMs,
            holderName = null,
            certificateDerBase64 = null,
        )
        pairedDevices = catalog.listPairs()
        pairingBackoff.recordSuccess()
        phase = PairingPhase.Paired(peer)

        val oldListener = listener
        listener = null
        scope.launch {
            kotlinx.coroutines.delay(LISTENER_CLOSE_DELAY_MS)
            oldListener?.close()
        }

        app?.rappProxyDispatcher?.startListening(vault)
    }

    private fun startHandshakeDeadline() {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob =
            scope.launch(Dispatchers.Main) {
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
            scope.launch(Dispatchers.Main) {
                for (sec in DEFAULT_PAIRING_COUNTDOWN_SECONDS downTo 0) {
                    secondsRemaining = sec
                    val current = phase
                    if (current is PairingPhase.Offering) {
                        phase = current.copy(secondsRemaining = sec)
                    }
                    delay(1000L)
                }
                if (phase is PairingPhase.Offering || phase is PairingPhase.Connecting) {
                    phase = PairingPhase.Failed("Pairing timed out")
                    reset()
                }
            }
    }

    fun removePair(pairIdHex: String) {
        val app = context.applicationContext as? RefineIdApplication
        val vault = app?.rappVault ?: AndroidRappVault(context)
        val pairIdBytes = decodeHexOrNull(pairIdHex)
        if (pairIdBytes != null) {
            vault.revokeDeviceOnly(pairIdBytes, RappClock.wallMs())
        }
        catalog.removePair(pairIdHex)
        pairedDevices = catalog.listPairs()
        if (activeConnectedPeer?.pairIdHex == pairIdHex) {
            app?.rappProxyDispatcher?.disconnectClient()
            activeConnectedPeer = null
        }
        if (pairedDevices.isEmpty()) {
            app?.rappProxyDispatcher?.stopListening()
        }
    }

    fun reset() {
        reset(keepPhase = false)
    }

    private fun reset(keepPhase: Boolean) {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        timerJob?.cancel()
        timerJob = null
        activeOfferingCode = null
        secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS
        listener?.close()
        listener = null
        try {
            pairingBridge?.cancelPairing()
        } catch (_: Exception) {
        }
        pairingBridge = null
        ceremony = null
        awaitingPreamble = false
        if (!keepPhase) {
            phase = PairingPhase.Idle
        }
        pairedDevices = catalog.listPairs()
    }

    fun terminate() {
        reset()
        val app = context.applicationContext as? RefineIdApplication
        app?.rappProxyDispatcher?.disconnectClient()
        app?.rappProxyDispatcher?.stopListening()
        val vault = app?.rappVault ?: AndroidRappVault(context)
        for (pair in catalog.listPairs()) {
            try {
                val pairIdBytes = decodeHexOrNull(pair.pairIdHex)
                if (pairIdBytes != null) {
                    vault.revokeDeviceOnly(pairIdBytes, RappClock.wallMs())
                }
            } catch (_: Exception) {
            }
        }
        catalog.clearAll()
        pairedDevices = emptyList()
        activeConnectedPeer = null
    }

    companion object {
        /** Post-lockout backoff shared by every offer this process creates. */
        private val pairingBackoff = RappPairingBackoff()

        internal fun decodeHexOrNull(hex: String): ByteArray? {
            if (hex.isEmpty() || hex.length % 2 != 0) return null
            val result = ByteArray(hex.length / 2)
            for (i in result.indices) {
                val byte = hex.substring(i * 2, i * 2 + 2).toIntOrNull(16) ?: return null
                result[i] = byte.toByte()
            }
            return result
        }
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
