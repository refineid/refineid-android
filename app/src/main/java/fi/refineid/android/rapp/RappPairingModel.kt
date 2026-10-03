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
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappTransportCandidate
import uniffi.refineid_rapp.rappStreamPairingPreamble

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
private const val DEFAULT_PAIRING_COUNTDOWN_SECONDS = 180
private const val CPACE_RANDOM_BYTES = 64
private const val STREAM_CANDIDATE_ID = "stream-1"
private const val EMPTY_CBOR_MAP_BYTE = 0xa0.toByte()
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
    private var proxyHandshakeStep = 0
    private var receivedPeerHello: uniffi.refineid_rapp.RappPeerHello? = null
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
            } else if (phase is PairingPhase.Idle && activeConnectedPeer == null) {
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
        val code = RappPairingCode.generate()
        activeOfferingCode = code
        secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS
        val candidates =
            listOf(
                RappTransportCandidate(
                    profile = "fi.refineid.stream.v1",
                    candidateId = STREAM_CANDIDATE_ID,
                    parametersCbor = byteArrayOf(EMPTY_CBOR_MAP_BYTE),
                ),
            )

        try {
            val startedAtMonotonicMs = RappClock.monotonicMs()
            val proxyBridge =
                RappPairingBridge.fromProxyCodeOffer(
                    pairingCode = code,
                    profiles = DEFAULT_PAIRING_PROFILES,
                    transports = candidates,
                    offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                    startedAtMonotonicMs = startedAtMonotonicMs,
                )
            pairingBridge = proxyBridge
            proxyHandshakeStep = 0

            val relayListener =
                StreamRelayListener(
                    context = context,
                    scope = scope,
                    handshakeTimeoutMs = HANDSHAKE_DEADLINE_MS,
                ) { event ->
                    handleProxyListenerEvent(event, proxyBridge, code)
                }
            listener = relayListener
            relayListener.start(StreamRendezvousName.MANUAL_PAIRING_SERVICE_NAME)

            phase = PairingPhase.Offering(code = code, secondsRemaining = DEFAULT_PAIRING_COUNTDOWN_SECONDS)
            startCountdown()
        } catch (_: Throwable) {
            phase = PairingPhase.Failed("Failed to initialize remote pairing offer")
        }
    }

    private fun handleProxyListenerEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
        code: String,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                handleProxyConnected(bridge, code)
            }

            is StreamRelayEvent.Frame -> {
                handleProxyFrame(event, bridge)
            }

            is StreamRelayEvent.Disconnected -> {
                handleProxyDisconnected()
            }

            is StreamRelayEvent.Error -> {
                handshakeDeadlineJob?.cancel()
                handshakeDeadlineJob = null
                phase = PairingPhase.Failed("Connection error")
            }
        }
    }

    private fun handleProxyConnected(
        bridge: RappPairingBridge,
        code: String,
    ) {
        phase = PairingPhase.Connecting("Connected! Starting security handshake...")
        proxyHandshakeStep = 0
        startHandshakeDeadline()
        val random64 = ByteArray(CPACE_RANDOM_BYTES).apply { java.security.SecureRandom().nextBytes(this) }
        try {
            bridge.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = code,
                randomBytes64 = random64,
                nowMonotonicMs = RappClock.monotonicMs(),
            )
        } catch (_: Exception) {
            phase = PairingPhase.Failed("Failed to initialize security handshake")
        } finally {
            random64.fill(0)
        }
    }

    private fun handleProxyDisconnected() {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        if (phase is PairingPhase.Connecting) {
            if (proxyHandshakeStep > 0) {
                phase = PairingPhase.Failed("Peer disconnected")
            } else {
                restoreOfferingOrWaiting()
            }
        }
    }

    private fun handleProxyFrame(
        event: StreamRelayEvent.Frame,
        bridge: RappPairingBridge,
    ) {
        try {
            val preamble = rappStreamPairingPreamble()
            if (event.data.contentEquals(preamble)) {
                return
            }

            val nowMonotonicMs = RappClock.monotonicMs()
            when (proxyHandshakeStep) {
                0 -> {
                    val response = bridge.writeCpaceFrame(nowMonotonicMs)
                    bridge.readCpaceFrame(event.data, nowMonotonicMs)
                    listener?.send(response)
                    proxyHandshakeStep = 1
                    startHandshakeDeadline()
                }

                1 -> {
                    bridge.readHandshakeFrame(event.data, nowMonotonicMs)
                    val response = bridge.writeHandshakeFrame(nowMonotonicMs)
                    listener?.send(response)
                    proxyHandshakeStep = 2
                    startHandshakeDeadline()
                }

                2 -> {
                    bridge.readHandshakeFrame(event.data, nowMonotonicMs)
                    if (bridge.handshakeComplete(nowMonotonicMs)) {
                        bridge.enterConfirmation(nowMonotonicMs)
                        val hello =
                            bridge.sendHello(displayName = localDeviceDisplayName(), platform = "Android")
                        listener?.send(hello)
                        proxyHandshakeStep = 3
                        startHandshakeDeadline()
                    }
                }

                3 -> {
                    receivedPeerHello = bridge.receiveHello(event.data, RappClock.wallMs())
                    val confirmation = bridge.sendConfirmation(DEFAULT_PAIRING_PROFILES)
                    listener?.send(confirmation)
                    proxyHandshakeStep = 4
                    startHandshakeDeadline()
                }

                4 -> {
                    finalizeProxyPairing(event.data, bridge)
                }
            }
        } catch (e: Throwable) {
            handshakeDeadlineJob?.cancel()
            handshakeDeadlineJob = null
            phase = PairingPhase.Failed("Pairing error: ${e.javaClass.simpleName}")
        }
    }

    private fun finalizeProxyPairing(
        confirmationData: ByteArray,
        bridge: RappPairingBridge,
    ) {
        bridge.receiveConfirmation(confirmationData, RappClock.wallMs())
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob = null
        listener?.clearSocketTimeout()
        val nowMs = RappClock.wallMs()
        val record = bridge.finishPairing(nowMs)
        val hello = receivedPeerHello
        val peer =
            PairedPeer(
                pairIdHex = record.metadata().pairId.joinToString("") { "%02x".format(it) },
                displayName = hello?.displayName?.takeIf { it.isNotBlank() } ?: "Computer",
                platform = hello?.platform?.takeIf { it.isNotBlank() } ?: "Unknown",
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
        phase = PairingPhase.Paired(peer)

        val oldListener = listener
        listener = null
        scope.launch {
            kotlinx.coroutines.delay(LISTENER_CLOSE_DELAY_MS)
            oldListener?.close()
        }

        val rendezvousToken = record.metadata().rendezvousToken
        val sessionRendezvousName = StreamRendezvousName.name(sharingValue = rendezvousToken)
        app?.rappProxyDispatcher?.startListening(sessionRendezvousName, record, vault)
    }

    private fun startHandshakeDeadline() {
        handshakeDeadlineJob?.cancel()
        handshakeDeadlineJob =
            scope.launch(Dispatchers.Main) {
                delay(HANDSHAKE_DEADLINE_MS)
                if (phase is PairingPhase.Connecting) {
                    listener?.disconnectClient()
                    restoreOfferingOrWaiting()
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
        proxyHandshakeStep = 0
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
        receivedPeerHello = null
        proxyHandshakeStep = 0
        phase = PairingPhase.Idle
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
