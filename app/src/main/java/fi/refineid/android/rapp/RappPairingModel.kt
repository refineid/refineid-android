@file:Suppress("TooGenericExceptionCaught", "MagicNumber", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.BuildConfig
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

    data object CodeEntry : PairingPhase

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

internal class RappPairingModel(
    private val context: Context,
    private val scope: CoroutineScope,
) : AutoCloseable {
    private val catalog = RappPairCatalog(context)
    private var listener: StreamRelayListener? = null
    private var browser: StreamRelayBrowser? = null
    private var pairingBridge: RappPairingBridge? = null
    private var timerJob: Job? = null
    private var proxyHandshakeStep = 0
    private var requesterHandshakeStep = 0
    private var receivedPeerHello: uniffi.refineid_rapp.RappPeerHello? = null
    private val app = context.applicationContext as? RefineIdApplication

    var phase by mutableStateOf<PairingPhase>(PairingPhase.Idle)
        private set

    var pairedDevices by mutableStateOf<List<PairedPeer>>(catalog.listPairs())
        private set

    var activeConnectedPeer by mutableStateOf<PairedPeer?>(null)
        private set

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

    fun disconnectActivePeer() {
        app?.rappProxyDispatcher?.disconnectClient()
    }

    fun createOffer() {
        reset()
        val code = RappPairingCode.generate()
        val offerId = RappPairingCode.offerIdentifier(code)
        val pairingSecret = RappPairingCode.pairingSecret(code)
        val candidates =
            listOf(
                RappTransportCandidate(
                    profile = "fi.refineid.stream.v1",
                    candidateId = "stream-1",
                    parametersCbor = byteArrayOf(0xa0.toByte()),
                ),
            )
        val profiles =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )

        try {
            val startedAtMonotonicMs = RappClock.monotonicMs()
            val bridge =
                RappPairingBridge.createRequesterOffer(
                    offerId = offerId,
                    pairingSecret = pairingSecret,
                    profiles = profiles,
                    transports = candidates,
                    offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                    startedAtMonotonicMs = startedAtMonotonicMs,
                )
            pairingBridge = bridge
            val offerUri = bridge.offerUri(nowMonotonicMs = startedAtMonotonicMs)
            val rendezvousName = StreamRendezvousName.name(sharingOfferUri = offerUri)

            phase = PairingPhase.Offering(code = code, secondsRemaining = 180)
            startCountdown()

            bridge.begin(candidateId = "stream-1", nowMonotonicMs = startedAtMonotonicMs)
            requesterHandshakeStep = 0

            val relayBrowser =
                StreamRelayBrowser(context, scope, rendezvousName) { event ->
                    handleRequesterBrowserEvent(event, bridge)
                }
            browser = relayBrowser
            relayBrowser.start()
        } catch (e: Exception) {
            phase = PairingPhase.Failed(e.message ?: "Failed to generate pairing offer")
        }
    }

    private fun handleRequesterBrowserEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                phase = PairingPhase.Connecting("Peer connected! Starting security handshake...")
                requesterHandshakeStep = 0
                try {
                    browser?.send(rappStreamPairingPreamble())
                    val frame = bridge.writeHandshakeFrame(RappClock.monotonicMs())
                    browser?.send(frame)
                    requesterHandshakeStep = 1
                } catch (e: Exception) {
                    phase = PairingPhase.Failed("Handshake write error: ${e.message}")
                }
            }

            is StreamRelayEvent.Frame -> {
                try {
                    val nowMonotonicMs = RappClock.monotonicMs()
                    when (requesterHandshakeStep) {
                        1 -> {
                            // Responder sent Message 2
                            bridge.readHandshakeFrame(event.data, nowMonotonicMs)
                            val finalHandshake = bridge.writeHandshakeFrame(nowMonotonicMs)
                            if (bridge.handshakeComplete(nowMonotonicMs)) {
                                bridge.enterConfirmation(nowMonotonicMs)
                                val hello =
                                    bridge.sendHello(
                                        displayName = localDeviceDisplayName(),
                                        platform = "Android",
                                    )
                                browser?.send(finalHandshake)
                                browser?.send(hello)
                                requesterHandshakeStep = 2
                            }
                        }

                        2 -> {
                            // Responder sent Hello
                            receivedPeerHello = bridge.receiveHello(event.data, RappClock.wallMs())
                            val grantedProfiles =
                                listOf(
                                    "fi.refineid.card-status.v1",
                                    "fi.refineid.authentication.v1",
                                    "fi.refineid.document-signing.v1",
                                )
                            val conf = bridge.sendConfirmation(grantedProfiles)
                            browser?.send(conf)
                            requesterHandshakeStep = 3
                        }

                        3 -> {
                            // Responder sent Confirmation
                            bridge.receiveConfirmation(event.data, RappClock.wallMs())
                            val record = bridge.finishPairing(RappClock.wallMs())
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

                            val oldBrowser = browser
                            browser = null
                            scope.launch {
                                kotlinx.coroutines.delay(LISTENER_CLOSE_DELAY_MS)
                                oldBrowser?.close()
                            }

                            if (record.metadata().role == uniffi.refineid_rapp.RappEndpointRole.PROXY) {
                                val rendezvousToken = record.metadata().rendezvousToken
                                val sessionRendezvousName = StreamRendezvousName.name(sharingValue = rendezvousToken)
                                app?.rappProxyDispatcher?.startListening(sessionRendezvousName, record, vault)
                            } else {
                                app?.remoteCardModel?.refresh()
                            }
                        }
                    }
                } catch (e: Exception) {
                    phase = PairingPhase.Failed("Handshake error: ${e.message}")
                }
            }

            is StreamRelayEvent.Disconnected -> {
                if (phase is PairingPhase.Connecting) {
                    phase = PairingPhase.Failed("Peer disconnected")
                }
            }

            is StreamRelayEvent.Error -> {
                phase = PairingPhase.Failed(event.cause.message ?: "Connection error")
            }
        }
    }

    fun startCodeEntry() {
        reset()
        phase = PairingPhase.CodeEntry
    }

    fun connectWithCode(rawCode: String) {
        val code = RappPairingCode.normalize(rawCode)
        if (!RappPairingCode.isValid(code)) return

        listener?.close()
        listener = null
        browser?.close()
        browser = null
        try {
            pairingBridge?.cancelPairing()
        } catch (_: Exception) {
        }
        pairingBridge = null
        receivedPeerHello = null

        phase = PairingPhase.Connecting("Connecting...")
        val offerId = RappPairingCode.offerIdentifier(code)
        val pairingSecret = RappPairingCode.pairingSecret(code)
        val candidates =
            listOf(
                RappTransportCandidate(
                    profile = "fi.refineid.stream.v1",
                    candidateId = "stream-1",
                    parametersCbor = byteArrayOf(0xa0.toByte()),
                ),
            )
        val profiles =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )

        try {
            val startedAtMonotonicMs = RappClock.monotonicMs()
            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 1: createRequesterOffer")
            val tempBridge =
                RappPairingBridge.createRequesterOffer(
                    offerId = offerId,
                    pairingSecret = pairingSecret,
                    profiles = profiles,
                    transports = candidates,
                    offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                    startedAtMonotonicMs = startedAtMonotonicMs,
                )
            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 2: offerUri")
            val offerUri = tempBridge.offerUri(nowMonotonicMs = startedAtMonotonicMs)
            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 3: rendezvousName from $offerUri")
            val rendezvousName = StreamRendezvousName.name(sharingOfferUri = offerUri)

            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 4: fromScannedOffer")
            val proxyBridge =
                RappPairingBridge.fromScannedOffer(
                    uri = offerUri,
                    startedAtMonotonicMs = startedAtMonotonicMs,
                )
            pairingBridge = proxyBridge
            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 5: begin stream-1")
            proxyBridge.begin(candidateId = "stream-1", nowMonotonicMs = startedAtMonotonicMs)
            proxyHandshakeStep = 0

            if (BuildConfig.DEBUG) android.util.Log.i("RAPP_PAIR", "Step 6: StreamRelayListener start $rendezvousName")
            val relayListener =
                StreamRelayListener(context, scope) { event ->
                    handleProxyListenerEvent(event, proxyBridge)
                }
            listener = relayListener
            relayListener.start(rendezvousName)
        } catch (e: Throwable) {
            android.util.Log.e("RAPP_PAIR", "Failed to initiate pairing: ${e.javaClass.name}: ${e.message}", e)
            phase = PairingPhase.Failed("${e.javaClass.simpleName}: ${e.message ?: "unknown"}")
        }
    }

    private fun handleProxyListenerEvent(
        event: StreamRelayEvent,
        bridge: RappPairingBridge,
    ) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                phase = PairingPhase.Connecting("Connected! Starting security handshake...")
                proxyHandshakeStep = 0
            }

            is StreamRelayEvent.Frame -> {
                try {
                    val preamble = rappStreamPairingPreamble()
                    if (event.data.contentEquals(preamble)) {
                        return
                    }

                    val nowMonotonicMs = RappClock.monotonicMs()
                    when (proxyHandshakeStep) {
                        0 -> {
                            // Peer sent Message 1
                            bridge.readHandshakeFrame(event.data, nowMonotonicMs)
                            val response = bridge.writeHandshakeFrame(nowMonotonicMs)
                            listener?.send(response)
                            proxyHandshakeStep = 1
                        }

                        1 -> {
                            // Peer sent Message 3
                            bridge.readHandshakeFrame(event.data, nowMonotonicMs)
                            if (bridge.handshakeComplete(nowMonotonicMs)) {
                                bridge.enterConfirmation(nowMonotonicMs)
                                val hello =
                                    bridge.sendHello(
                                        displayName = localDeviceDisplayName(),
                                        platform = "Android",
                                    )
                                listener?.send(hello)
                                proxyHandshakeStep = 2
                            }
                        }

                        2 -> {
                            // Peer sent Hello
                            receivedPeerHello = bridge.receiveHello(event.data, RappClock.wallMs())
                            val grantedProfiles =
                                listOf(
                                    "fi.refineid.card-status.v1",
                                    "fi.refineid.authentication.v1",
                                    "fi.refineid.document-signing.v1",
                                )
                            val confirmation = bridge.sendConfirmation(grantedProfiles)
                            listener?.send(confirmation)
                            proxyHandshakeStep = 3
                        }

                        3 -> {
                            // Peer sent Confirmation
                            bridge.receiveConfirmation(event.data, RappClock.wallMs())
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
                    }
                } catch (e: Throwable) {
                    android.util.Log.e(
                        "RAPP_PAIR",
                        "handleProxyListenerEvent failed: ${e.javaClass.name}: ${e.message}",
                        e,
                    )
                    phase = PairingPhase.Failed("Pairing error: ${e.javaClass.simpleName}: ${e.message ?: "unknown"}")
                }
            }

            is StreamRelayEvent.Disconnected -> {
                if (phase is PairingPhase.Connecting) {
                    if (proxyHandshakeStep > 0) {
                        phase = PairingPhase.Failed("Peer disconnected")
                    } else {
                        if (BuildConfig.DEBUG) {
                            android.util.Log.w(
                                "RAPP_PAIR",
                                "Connection dropped before handshake; continuing to wait for peer...",
                            )
                        }
                    }
                }
            }

            is StreamRelayEvent.Error -> {
                phase = PairingPhase.Failed(event.cause.message ?: "Connection error")
            }
        }
    }

    private fun startCountdown() {
        timerJob?.cancel()
        timerJob =
            scope.launch(Dispatchers.Main) {
                for (sec in 180 downTo 0) {
                    val current = phase
                    if (current is PairingPhase.Offering) {
                        phase = current.copy(secondsRemaining = sec)
                    }
                    delay(1000L)
                }
                if (phase is PairingPhase.Offering) {
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
        timerJob?.cancel()
        timerJob = null
        listener?.close()
        listener = null
        browser?.close()
        browser = null
        try {
            pairingBridge?.cancelPairing()
        } catch (_: Exception) {
        }
        pairingBridge = null
        receivedPeerHello = null
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

    private fun decodeHexOrNull(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            val byte = hex.substring(i * 2, i * 2 + 2).toIntOrNull(16) ?: return null
            result[i] = byte.toByte()
        }
        return result
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
