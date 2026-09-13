@file:Suppress("UnusedParameter", "TooGenericExceptionCaught", "TooManyFunctions", "LargeClass")

package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import fi.refineid.android.BuildConfig
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.P384EcdsaSignature
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.prime.PrimedCanStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappLivenessConfiguration
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappOperationDescriptor
import uniffi.refineid_rapp.RappOperationKind
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappStreamSessionPreamble
import java.security.SecureRandom

/**
 * Handles incoming RAPP protocol requests from a paired Mac, coordinates user approvals,
 * and executes card signing operations via physical card services.
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
    private val activeAuthCertDer: () -> ByteArray? = { null },
) : AutoCloseable {
    private var activeListener: StreamRelayListener? = null
    private var sessionBridge: RappSessionBridge? = null
    private var sessionHandshakeDone = false
    private var operationBridge: RappOperationBridge? = null
    private var pairRecord: RappPairRecord? = null
    private var vault: AndroidRappVault? = null
    private val catalog = RappPairCatalog(context)
    private var isClosed = false

    @Volatile
    private var lastReadAuthCertDer: ByteArray? = null

    private val _connectedPeer = MutableStateFlow<PairedPeer?>(null)
    val connectedPeer: StateFlow<PairedPeer?> = _connectedPeer.asStateFlow()

    val isListening: Boolean
        get() = activeListener != null

    val listeningPort: Int?
        get() = activeListener?.port

    companion object {
        /** Maximum time to wait for an NFC card certificate read before reporting card-removed. */
        private const val CERT_READ_TIMEOUT_MS = 5_000L
        private const val NANOS_PER_MICROSECOND = 1_000L
        private const val SHA256_DIGEST_LENGTH = 32
        private const val SHA384_DIGEST_LENGTH = 48
    }

    fun startListening(
        rendezvousName: String,
        pairRecord: RappPairRecord,
        vault: AndroidRappVault,
    ) {
        if (isClosed) return
        this.pairRecord = pairRecord
        this.vault = vault
        activeListener?.close()
        val listener =
            StreamRelayListener(context, scope) { event ->
                handleRelayEvent(event)
            }
        activeListener = listener
        listener.start(rendezvousName)
    }

    fun stopListening() {
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        pairRecord = null
        vault = null
        _connectedPeer.value = null
        inbox.dismissAll()
    }

    fun disconnectClient() {
        activeListener?.close()
        sessionBridge?.close()
        sessionBridge = null
        sessionHandshakeDone = false
        operationBridge?.close()
        operationBridge = null
        _connectedPeer.value = null
        inbox.dismissAll()
        val currentPair = pairRecord
        val vlt = vault
        if (currentPair != null && vlt != null && !isClosed) {
            val token = currentPair.metadata().rendezvousToken
            val name = StreamRendezvousName.name(sharingValue = token)
            startListening(name, currentPair, vlt)
        }
    }

    private fun handleRelayEvent(event: StreamRelayEvent) {
        when (event) {
            is StreamRelayEvent.Connected -> {
                sessionBridge?.close()
                sessionBridge = null
                sessionHandshakeDone = false
                operationBridge?.close()
                operationBridge = null
            }

            is StreamRelayEvent.Frame -> {
                val pair = pairRecord ?: return
                val vlt = vault ?: return

                val opBridge = operationBridge
                if (opBridge != null) {
                    try {
                        val action = opBridge.receiveFrame(event.data, RappClock.monotonicMs())
                        handleBridgeAction(action, opBridge)
                    } catch (_: Exception) {
                    }
                    return
                }

                val currentSession = sessionBridge
                if (currentSession == null) {
                    try {
                        val token = pair.metadata().rendezvousToken
                        val preamble = rappStreamSessionPreamble(token)
                        if (event.data.contentEquals(preamble)) {
                            sessionBridge = RappSessionBridge.beginProxy(pair = pair, vault = vlt)
                            return
                        }
                    } catch (_: Exception) {
                    }

                    // Not preamble or preamble was skipped: treat as Noise Message 1
                    try {
                        val sess = RappSessionBridge.beginProxy(pair = pair, vault = vlt)
                        sessionBridge = sess
                        sess.readHandshakeFrame(event.data)
                        val reply = sess.writeHandshakeFrame()
                        activeListener?.send(reply)
                        if (sess.handshakeComplete()) {
                            sessionHandshakeDone = true
                            sess.enterAuthentication()
                            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                            val ready = sess.sendReady(nonce)
                            activeListener?.send(ready)
                        }
                    } catch (_: Exception) {
                    }
                    return
                }

                if (!sessionHandshakeDone) {
                    try {
                        currentSession.readHandshakeFrame(event.data)
                        val reply = currentSession.writeHandshakeFrame()
                        activeListener?.send(reply)
                        if (currentSession.handshakeComplete()) {
                            sessionHandshakeDone = true
                            currentSession.enterAuthentication()
                            val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                            val ready = currentSession.sendReady(nonce)
                            activeListener?.send(ready)
                        }
                    } catch (_: Exception) {
                    }
                    return
                }

                // Bilateral ready confirmation
                try {
                    currentSession.receiveReady(event.data, RappClock.wallMs())
                    currentSession.enterEstablished()

                    val liveness =
                        RappLivenessConfiguration(
                            baseIntervalMs = 5_000UL,
                            responseTimeoutMs = 10_000UL,
                            maximumIntervalMs = 60_000UL,
                            maximumJitterMs = 500UL,
                            maximumMisses = 3.toUByte(),
                        )
                    val newOpBridge =
                        RappOperationBridge.beginProxy(
                            session = currentSession,
                            vault = vlt,
                            maximumLifetimeMs = 120_000UL,
                            liveness = liveness,
                            nowMs = RappClock.wallMs(),
                        )
                    operationBridge = newOpBridge
                    val currentPair = pairRecord
                    if (currentPair != null) {
                        val hex = currentPair.metadata().pairId.joinToString("") { "%02x".format(it) }
                        val peer =
                            catalog.listPairs().firstOrNull { it.pairIdHex == hex }
                                ?: PairedPeer(
                                    pairIdHex = hex,
                                    displayName = "Computer",
                                    platform = "macOS",
                                    createdAtMs = System.currentTimeMillis(),
                                )
                        _connectedPeer.value = peer
                        AppTrace.rappPairingCompleted(peer.displayName)
                    }
                } catch (_: Exception) {
                }
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                AppTrace.rappConnectionDropped(
                    if (event is StreamRelayEvent.Error) {
                        event.cause.message ?: "unknown error"
                    } else {
                        "stream disconnected"
                    },
                )
                activeOperationJob?.cancel()
                activeOperationJob = null
                sessionBridge?.close()
                sessionBridge = null
                sessionHandshakeDone = false
                operationBridge?.close()
                operationBridge = null
                _connectedPeer.value = null
                inbox.dismissAll()
            }
        }
    }

    private val pendingPins = java.util.concurrent.ConcurrentHashMap<String, String>()
    private var activeOperationJob: Job? = null

    private fun handleBridgeAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        bridge: RappOperationBridge,
    ) {
        if (action.kind == RappBridgeActionKind.SEND_FRAME) {
            action.frame?.let { frame ->
                try {
                    activeListener?.send(frame)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "send frame failed", e)
                }
            }
            return
        }

        val opId = action.operationId ?: return
        val opIdHex = opId.joinToString("") { "%02x".format(it) }

        when (action.kind) {
            RappBridgeActionKind.INSPECT_PREREQUISITES -> {
                try {
                    val resp = bridge.prerequisitesComplete(opId)
                    handleBridgeAction(resp, bridge)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "prerequisitesComplete failed", e)
                }
            }

            RappBridgeActionKind.EXECUTE_SAFE_READ -> {
                handleSafeRead(action, opId, bridge)
            }

            RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                val desc = action.operation ?: return
                handleApproval(desc, opId, opIdHex, bridge)
            }

            RappBridgeActionKind.EXECUTE_CARD_COMMAND -> {
                val desc = action.operation ?: return
                handleExecute(desc, opId, opIdHex, bridge)
            }

            RappBridgeActionKind.RESULT_ACKNOWLEDGMENT -> {
                try {
                    bridge.acknowledgmentReleased(opId)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "acknowledgmentReleased failed", e)
                }
            }

            else -> {
            }
        }
    }

    private fun handleApproval(
        desc: uniffi.refineid_rapp.RappOperationDescriptor,
        opId: ByteArray,
        opIdHex: String,
        bridge: RappOperationBridge,
    ) {
        AppTrace.rappOperationReceived(desc.kind.name, opIdHex)
        when (desc.kind) {
            RappOperationKind.BROWSER_AUTHENTICATE -> {
                val cachedPin = pinCache?.take()
                val storedPinBytes = if (cachedPin == null) primedCanStore?.readPin1() else null
                val pinToUse =
                    if (cachedPin != null) {
                        var pinStr = ""
                        cachedPin.consume { pinBytes ->
                            pinStr = String(pinBytes, Charsets.US_ASCII)
                        }
                        pinStr
                    } else if (storedPinBytes != null) {
                        val pinStr = String(storedPinBytes, Charsets.US_ASCII)
                        storedPinBytes.fill(0)
                        pinCache?.recordVerified(pinStr.toByteArray(Charsets.US_ASCII))
                        pinStr
                    } else {
                        null
                    }

                if (pinToUse != null) {
                    pendingPins[opIdHex] = pinToUse
                    approve(opId, bridge)
                } else {
                    val requesterName =
                        catalog
                            .listPairs()
                            .firstOrNull()
                            ?.displayName
                            ?.takeIf { it.isNotBlank() }
                            ?: "Computer"
                    inbox.ask(
                        requestId = opIdHex,
                        requester = requesterName,
                        action = RappAuthAction.BROWSER_AUTH,
                        onApproved = { pin1 ->
                            pinCache?.recordVerified(pin1.toByteArray(Charsets.US_ASCII))
                            if (primedCanStore?.isPrimed() == true) {
                                primedCanStore.writePin1(pin1.toByteArray(Charsets.US_ASCII))
                            }
                            pendingPins[opIdHex] = pin1
                            approve(opId, bridge)
                        },
                        onDenied = { deny(opId, bridge) },
                    )
                }
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                val requesterName =
                    catalog
                        .listPairs()
                        .firstOrNull()
                        ?.displayName
                        ?.takeIf { it.isNotBlank() }
                        ?: "Computer"
                inbox.ask(
                    requestId = opIdHex,
                    requester = requesterName,
                    action = RappAuthAction.DOCUMENT_SIGN,
                    onApproved = { pin2 ->
                        pendingPins[opIdHex] = pin2
                        approve(opId, bridge)
                    },
                    onDenied = { deny(opId, bridge) },
                )
            }

            else -> {
                approve(opId, bridge)
            }
        }
    }

    private fun approve(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        val opIdHex = opId.joinToString("") { "%02x".format(it) }
        AppTrace.rappOperationApproved(opIdHex)
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                try {
                    val resp = bridge.approve(opId, RappClock.monotonicMs())
                    handleBridgeAction(resp, bridge)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "approve failed", e)
                }
            }
    }

    /** Tears down the active stream so Mac must reconnect for the next request. */
    private fun dropConnection() {
        AppTrace.rappConnectionDropped("proxy dispatcher dropConnection")
        activeOperationJob?.cancel()
        activeOperationJob = null
        activeListener?.disconnectClient()
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        sessionHandshakeDone = false
        pendingPins.clear()
        _connectedPeer.value = null
        inbox.dismissAll()
    }

    private fun deny(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        val opIdHex = opId.joinToString("") { "%02x".format(it) }
        AppTrace.rappOperationDenied(opIdHex, "user_denied")
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                try {
                    val resp = bridge.deny(opId)
                    handleBridgeAction(resp, bridge)
                } catch (e: Exception) {
                    android.util.Log.e("PROXY_DISPATCH", "deny failed", e)
                }
                // Drop the client stream so Mac cannot immediately re-request on the same session.
                dropConnection()
            }
    }

    private fun handleExecute(
        desc: uniffi.refineid_rapp.RappOperationDescriptor,
        opId: ByteArray,
        opIdHex: String,
        bridge: RappOperationBridge,
    ) {
        val pin = pendingPins.remove(opIdHex) ?: ""
        when (desc.kind) {
            RappOperationKind.BROWSER_AUTHENTICATE -> {
                executeBrowserAuth(opId, desc, pin, bridge)
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                executeDocumentSign(opId, desc, pin, bridge)
            }

            else -> {
            }
        }
    }

    private enum class CardReadyOutcome {
        READY,
        CANCELLED,
        TIMEOUT,
    }

    private suspend fun ensureCardReady(
        opIdHex: String,
        action: RappAuthAction,
        forcePrompt: Boolean = false,
    ): CardReadyOutcome {
        if (!forcePrompt && isCardReady()) return CardReadyOutcome.READY
        val requesterName =
            catalog
                .listPairs()
                .firstOrNull()
                ?.displayName
                ?.takeIf { it.isNotBlank() }
                ?: "Computer"
        var cancelled = false
        AppTrace.rappCardPromptShown(opIdHex, action.name)
        inbox.showTapPrompt(
            requestId = opIdHex,
            requester = requesterName,
            action = action,
            onCancel = { cancelled = true },
        )
        val ready =
            try {
                awaitCardReady()
            } finally {
                AppTrace.rappCardPromptDismissed(opIdHex)
                inbox.dismissTapPrompt(opIdHex)
            }
        return when {
            cancelled -> CardReadyOutcome.CANCELLED
            ready && scope.isActive && sessionBridge != null -> CardReadyOutcome.READY
            else -> CardReadyOutcome.TIMEOUT
        }
    }

    private suspend fun ensureCardOrAbort(
        opId: ByteArray,
        opIdHex: String,
        action: RappAuthAction,
        bridge: RappOperationBridge,
        forcePrompt: Boolean = false,
    ): Boolean =
        when (ensureCardReady(opIdHex, action, forcePrompt = forcePrompt)) {
            CardReadyOutcome.CANCELLED -> {
                AppTrace.rappOperationDenied(opIdHex, "user_cancelled")
                respondBridgeDeny(opId, bridge)
                dropConnection()
                false
            }

            CardReadyOutcome.TIMEOUT -> {
                val actionTag =
                    when (action) {
                        RappAuthAction.BROWSER_AUTH -> "browser_auth"
                        RappAuthAction.DOCUMENT_SIGN -> "document_sign"
                    }
                AppTrace.rappOperationFailed(actionTag, opIdHex, "card_not_ready_timeout")
                respondCardRemoved(opId, bridge)
                false
            }

            CardReadyOutcome.READY -> {
                true
            }
        }

    val cachedAuthCertDer: ByteArray?
        get() = lastReadAuthCertDer?.copyOf()

    private fun resolveCachedAuthCertificate(): ByteArray? {
        lastReadAuthCertDer?.let { return it.copyOf() }
        activeAuthCertDer()?.let { return it.copyOf() }
        primedCanStore?.readAuthCertificateDer()?.let { return it }
        val encoded = catalog.listPairs().firstOrNull()?.certificateDerBase64 ?: return null
        return try {
            Base64.decode(encoded, Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        }
    }

    internal fun storeReadAuthCertificate(certDer: ByteArray) {
        lastReadAuthCertDer = certDer.copyOf()
        primedCanStore?.writeAuthCertificateDer(certDer)
        val pairId = catalog.listPairs().firstOrNull()?.pairIdHex ?: return
        catalog.updateCertificateDer(pairId, certDer)
    }

    private fun respondCardRemoved(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp = bridge.cardRemovedBeforeTransmit(opId)
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    private fun respondBridgeDeny(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp = bridge.deny(opId)
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    private fun respondBridgeInvalid(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp = bridge.requestInvalidOrUnsupported(opId)
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    private fun respondCredentialRejected(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp = bridge.credentialRejected(opId, RappClock.monotonicMs())
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    private fun respondBridgeCertificate(
        opId: ByteArray,
        certDer: ByteArray,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp = bridge.completeCertificate(opId, certDer)
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    private fun tryCompleteFromCachedAuthCert(
        opId: ByteArray,
        opIdHex: String,
        opKindName: String,
        isAuth: Boolean,
        bridge: RappOperationBridge,
    ): Boolean {
        if (!isAuth) return false
        val cached = resolveCachedAuthCertificate() ?: return false
        storeReadAuthCertificate(cached)
        AppTrace.rappOperationCompleted(opKindName, opIdHex, 0L)
        respondBridgeCertificate(opId, cached, bridge)
        return true
    }

    private fun handleSafeRead(
        action: uniffi.refineid_rapp.RappBridgeAction,
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        val desc = action.operation ?: return
        val opIdHex = opId.joinToString("") { "%02x".format(it) }
        AppTrace.rappOperationReceived(desc.kind.name, opIdHex)
        val isAuth =
            when (desc.kind) {
                RappOperationKind.READ_AUTHENTICATION_CERTIFICATE -> true
                RappOperationKind.READ_SIGNATURE_CERTIFICATE -> false
                else -> return
            }
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                if (sessionBridge == null || activeListener == null) return@launch
                if (tryCompleteFromCachedAuthCert(opId, opIdHex, desc.kind.name, isAuth, bridge)) {
                    return@launch
                }
                val authAction =
                    if (isAuth) RappAuthAction.BROWSER_AUTH else RappAuthAction.DOCUMENT_SIGN
                if (!ensureCardOrAbort(opId, opIdHex, authAction, bridge)) return@launch
                if (tryCompleteFromCachedAuthCert(opId, opIdHex, desc.kind.name, isAuth, bridge)) {
                    return@launch
                }
                var certDer =
                    if (isAuth) {
                        readAuthCertWithTimeout()
                    } else {
                        readSignatureCertWithTimeout()
                    }
                if (certDer == null) {
                    when (ensureCardReady(opIdHex, authAction, forcePrompt = true)) {
                        CardReadyOutcome.CANCELLED, CardReadyOutcome.TIMEOUT -> {}

                        CardReadyOutcome.READY -> {
                            certDer = if (isAuth) readAuthCertWithTimeout() else readSignatureCertWithTimeout()
                        }
                    }
                }
                if (certDer != null) {
                    if (isAuth) {
                        storeReadAuthCertificate(certDer)
                    }
                    AppTrace.rappOperationCompleted(desc.kind.name, opIdHex, 0L)
                    respondBridgeCertificate(opId, certDer, bridge)
                } else {
                    AppTrace.rappOperationFailed(desc.kind.name, opIdHex, "certificate_read_timeout")
                    respondCardRemoved(opId, bridge)
                }
            }
    }

    private suspend fun readAuthCertWithTimeout(): ByteArray? {
        val deferred = CompletableDeferred<ByteArray?>()
        authCardService()?.requestAuthenticationCertificate { cert ->
            try {
                deferred.complete(cert?.copyDer())
            } catch (_: Exception) {
                deferred.complete(null)
            } finally {
                cert?.close()
            }
        } ?: deferred.complete(null)
        return try {
            withTimeoutOrNull(CERT_READ_TIMEOUT_MS) { deferred.await() }
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun readSignatureCertWithTimeout(): ByteArray? {
        val deferred = CompletableDeferred<ByteArray?>()
        qualifiedCardService()?.requestQualifiedCertificate { certResult ->
            when (certResult) {
                is NativeCertificateReadResult.Success -> {
                    val der =
                        try {
                            certResult.certificate.copyDer()
                        } catch (_: Exception) {
                            null
                        }
                    certResult.certificate.close()
                    deferred.complete(der)
                }

                else -> {
                    deferred.complete(null)
                }
            }
        } ?: deferred.complete(null)
        return try {
            withTimeoutOrNull(CERT_READ_TIMEOUT_MS) { deferred.await() }
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun readSignatureCertificateWithTimeout(): NativeQualifiedCertificate? {
        val deferred = CompletableDeferred<NativeQualifiedCertificate?>()
        qualifiedCardService()?.requestQualifiedCertificate { certResult ->
            when (certResult) {
                is NativeCertificateReadResult.Success -> deferred.complete(certResult.certificate)
                else -> deferred.complete(null)
            }
        } ?: deferred.complete(null)
        return try {
            withTimeoutOrNull(CERT_READ_TIMEOUT_MS) { deferred.await() }
        } catch (_: Exception) {
            null
        }
    }

    private fun executeBrowserAuth(
        opId: ByteArray,
        desc: RappOperationDescriptor,
        pin1: String,
        bridge: RappOperationBridge,
    ) {
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                if (sessionBridge == null || activeListener == null) return@launch
                val startedNs = System.nanoTime()
                val opIdHex = opId.joinToString("") { "%02x".format(it) }
                val algorithm = resolveSignAlgorithm(desc)
                if (algorithm == null) {
                    AppTrace.rappOperationFailed("browser_auth", opIdHex, "unsupported_algorithm")
                    respondBridgeInvalid(opId, bridge)
                    return@launch
                }
                if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.BROWSER_AUTH, bridge)) return@launch
                var service = authCardService()
                if (service == null) {
                    if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.BROWSER_AUTH, bridge, forcePrompt = true)) {
                        return@launch
                    }
                    service = authCardService()
                }
                if (service == null) {
                    AppTrace.rappOperationFailed("browser_auth", opIdHex, "service_unavailable")
                    respondCardRemoved(opId, bridge)
                    return@launch
                }
                val resolvedPin = resolvePin1(pin1)
                if (resolvedPin.isEmpty()) {
                    AppTrace.rappOperationDenied(opIdHex, "pin1_missing")
                    respondBridgeDeny(opId, bridge)
                    return@launch
                }
                val authResult =
                    performBrowserAuthWithRetry(
                        opId = opId,
                        opIdHex = opIdHex,
                        algorithm = algorithm,
                        resolvedPin = resolvedPin,
                        digest = desc.digest,
                        initialService = service,
                        bridge = bridge,
                    ) ?: return@launch
                service = authResult.first
                when (val result = authResult.second) {
                    is AuthenticationSignResult.Success -> {
                        handleBrowserAuthSuccess(
                            opId = opId,
                            opIdHex = opIdHex,
                            startedNs = startedNs,
                            resolvedPin = resolvedPin,
                            service = service,
                            result = result,
                            bridge = bridge,
                        )
                    }

                    is AuthenticationSignResult.Failure -> {
                        handleBrowserAuthFailure(
                            opId = opId,
                            opIdHex = opIdHex,
                            resolvedPin = resolvedPin,
                            result = result,
                            bridge = bridge,
                        )
                    }
                }
            }
    }

    private suspend fun performBrowserAuthWithRetry(
        opId: ByteArray,
        opIdHex: String,
        algorithm: AuthenticationSigningAlgorithm,
        resolvedPin: String,
        digest: ByteArray,
        initialService: AuthenticationCardService,
        bridge: RappOperationBridge,
    ): Pair<AuthenticationCardService, AuthenticationSignResult>? {
        var service = initialService
        var result =
            service.signAuthenticationDigest(
                algorithm = algorithm,
                pin1 = Pin1Submission.from(resolvedPin),
                digest = digest,
            )
        if (result is AuthenticationSignResult.Failure &&
            result.kind == AuthenticationSignFailure.CARD_UNAVAILABLE
        ) {
            if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.BROWSER_AUTH, bridge, forcePrompt = true)) {
                return null
            }
            val retryService = authCardService()
            if (retryService != null) {
                service = retryService
                result =
                    retryService.signAuthenticationDigest(
                        algorithm = algorithm,
                        pin1 = Pin1Submission.from(resolvedPin),
                        digest = digest,
                    )
            }
        }
        return Pair(service, result)
    }

    private fun resolvePin1(pin1: String): String {
        if (pin1.isNotEmpty()) return pin1
        var fromCache = ""
        pinCache?.take()?.consume { pinBytes ->
            fromCache = String(pinBytes, Charsets.US_ASCII)
        }
        if (fromCache.isEmpty()) {
            primedCanStore?.readPin1()?.let { storedBytes ->
                fromCache = String(storedBytes, Charsets.US_ASCII)
                storedBytes.fill(0)
                pinCache?.recordVerified(fromCache.toByteArray(Charsets.US_ASCII))
            }
        }
        return fromCache
    }

    private fun handleBrowserAuthSuccess(
        opId: ByteArray,
        opIdHex: String,
        startedNs: Long,
        resolvedPin: String,
        service: AuthenticationCardService,
        result: AuthenticationSignResult.Success,
        bridge: RappOperationBridge,
    ) {
        pinCache?.recordVerified(resolvedPin.toByteArray(Charsets.US_ASCII))
        if (primedCanStore?.isPrimed() == true) {
            primedCanStore.writePin1(resolvedPin.toByteArray(Charsets.US_ASCII))
        }
        ensureAuthCertCached(service)
        try {
            val rawSig = result.signature.copyBytes()
            val wireSig =
                if (result.signature.algorithm.keyProfile == NativeCardKeyProfile.ECDSA_P384) {
                    P384EcdsaSignature.toDer(rawSig)
                } else {
                    rawSig
                }
            val resp = bridge.completeSignature(opId, wireSig)
            AppTrace.rappOperationCompleted(
                "browser_auth",
                opIdHex,
                (System.nanoTime() - startedNs) / NANOS_PER_MICROSECOND,
            )
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
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

    private fun handleBrowserAuthFailure(
        opId: ByteArray,
        opIdHex: String,
        resolvedPin: String,
        result: AuthenticationSignResult.Failure,
        bridge: RappOperationBridge,
    ) {
        AppTrace.rappOperationFailed("browser_auth", opIdHex, result.kind.name)
        if (result.kind == AuthenticationSignFailure.WRONG_PIN) {
            pinCache?.recordRejected(resolvedPin.toByteArray(Charsets.US_ASCII))
            primedCanStore?.forgetPin1()
            respondCredentialRejected(opId, bridge)
        } else {
            respondCardRemoved(opId, bridge)
        }
    }

    private fun resolveSignAlgorithm(desc: RappOperationDescriptor): AuthenticationSigningAlgorithm? =
        when (desc.algorithm) {
            RappSignatureAlgorithm.ECDSA_SHA256 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            RappSignatureAlgorithm.ECDSA_SHA384 -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA256 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256
            RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384
            RappSignatureAlgorithm.RSA_PKCS1_SHA512 -> AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512
            RappSignatureAlgorithm.RSA_PSS_SHA256 -> AuthenticationSigningAlgorithm.RSA_PSS_SHA256
            else -> fallbackSignAlgorithm(desc.digest.size)
        }

    private fun fallbackSignAlgorithm(digestSize: Int): AuthenticationSigningAlgorithm? =
        when (digestSize) {
            SHA256_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA256
            SHA384_DIGEST_LENGTH -> AuthenticationSigningAlgorithm.ECDSA_P384_SHA384
            else -> null
        }

    private fun executeDocumentSign(
        opId: ByteArray,
        desc: RappOperationDescriptor,
        pin2: String,
        bridge: RappOperationBridge,
    ) {
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                if (sessionBridge == null || activeListener == null) return@launch
                val startedNs = System.nanoTime()
                val opIdHex = opId.joinToString("") { "%02x".format(it) }
                val algorithm = resolveQualifiedAlgorithm(desc)
                if (algorithm == null) {
                    AppTrace.rappOperationFailed("document_sign", opIdHex, "unsupported_algorithm")
                    respondBridgeInvalid(opId, bridge)
                    return@launch
                }
                if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.DOCUMENT_SIGN, bridge)) return@launch
                var service = qualifiedCardService()
                if (service == null) {
                    if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.DOCUMENT_SIGN, bridge, forcePrompt = true)) {
                        return@launch
                    }
                    service = qualifiedCardService()
                }
                if (service == null) {
                    AppTrace.rappOperationFailed("document_sign", opIdHex, "service_unavailable")
                    respondCardRemoved(opId, bridge)
                    return@launch
                }
                if (!Pin2Submission.acceptsEntry(pin2) || !Pin2Submission.isComplete(pin2)) {
                    AppTrace.rappOperationDenied(opIdHex, "pin2_incomplete")
                    respondBridgeDeny(opId, bridge)
                    return@launch
                }
                var expectedCert = readSignatureCertificateWithTimeout()
                if (expectedCert == null) {
                    if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.DOCUMENT_SIGN, bridge, forcePrompt = true)) {
                        return@launch
                    }
                    expectedCert = readSignatureCertificateWithTimeout()
                }
                if (expectedCert == null) {
                    AppTrace.rappOperationFailed("document_sign", opIdHex, "certificate_read_timeout")
                    respondCardRemoved(opId, bridge)
                    return@launch
                }
                try {
                    val signResult =
                        performQualifiedSignWithRetry(
                            opId = opId,
                            opIdHex = opIdHex,
                            desc = desc,
                            pin2 = pin2,
                            algorithm = algorithm,
                            expectedCert = expectedCert,
                            bridge = bridge,
                        ) ?: return@launch
                    when (signResult) {
                        is QualifiedSignResult.Success -> {
                            handleDocumentSignSuccess(
                                opId = opId,
                                opIdHex = opIdHex,
                                startedNs = startedNs,
                                result = signResult,
                                bridge = bridge,
                            )
                        }

                        is QualifiedSignResult.Failure -> {
                            handleDocumentSignFailure(
                                opId = opId,
                                opIdHex = opIdHex,
                                result = signResult,
                                bridge = bridge,
                            )
                        }
                    }
                } finally {
                    expectedCert.close()
                }
            }
    }

    private suspend fun performQualifiedSignWithRetry(
        opId: ByteArray,
        opIdHex: String,
        desc: RappOperationDescriptor,
        pin2: String,
        algorithm: QualifiedSigningAlgorithm,
        expectedCert: NativeQualifiedCertificate,
        bridge: RappOperationBridge,
    ): QualifiedSignResult? {
        val service = qualifiedCardService() ?: return null
        val deferred = CompletableDeferred<QualifiedSignResult>()
        service.requestQualifiedDigestSignature(
            algorithm = algorithm,
            pin2 = Pin2Submission.from(pin2),
            digest = desc.digest,
            expectedCertificate = expectedCert,
        ) { signResult ->
            deferred.complete(signResult)
        }
        var signResult = deferred.await()
        if (signResult is QualifiedSignResult.Failure &&
            signResult.kind == QualifiedSignFailure.CARD_UNAVAILABLE
        ) {
            if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.DOCUMENT_SIGN, bridge, forcePrompt = true)) {
                return null
            }
            val retryService = qualifiedCardService()
            if (retryService != null) {
                val retryDeferred = CompletableDeferred<QualifiedSignResult>()
                retryService.requestQualifiedDigestSignature(
                    algorithm = algorithm,
                    pin2 = Pin2Submission.from(pin2),
                    digest = desc.digest,
                    expectedCertificate = expectedCert,
                ) { rResult ->
                    retryDeferred.complete(rResult)
                }
                signResult = retryDeferred.await()
            }
        }
        return signResult
    }

    private fun handleDocumentSignSuccess(
        opId: ByteArray,
        opIdHex: String,
        startedNs: Long,
        result: QualifiedSignResult.Success,
        bridge: RappOperationBridge,
    ) {
        try {
            val rawSig = result.signature.copyBytes()
            val wireSig =
                if (result.signature.algorithm == QualifiedSigningAlgorithm.ECDSA_P384_SHA384) {
                    P384EcdsaSignature.toDer(rawSig)
                } else {
                    rawSig
                }
            val resp = bridge.completeSignature(opId, wireSig)
            AppTrace.rappOperationCompleted(
                "document_sign",
                opIdHex,
                (System.nanoTime() - startedNs) / NANOS_PER_MICROSECOND,
            )
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        } finally {
            result.signature.close()
        }
    }

    private fun handleDocumentSignFailure(
        opId: ByteArray,
        opIdHex: String,
        result: QualifiedSignResult.Failure,
        bridge: RappOperationBridge,
    ) {
        AppTrace.rappOperationFailed("document_sign", opIdHex, result.kind.name)
        if (result.kind == QualifiedSignFailure.WRONG_PIN) {
            respondCredentialRejected(opId, bridge)
        } else {
            respondCardRemoved(opId, bridge)
        }
    }

    private fun resolveQualifiedAlgorithm(desc: RappOperationDescriptor): QualifiedSigningAlgorithm? =
        when (desc.algorithm) {
            RappSignatureAlgorithm.ECDSA_SHA384 -> {
                QualifiedSigningAlgorithm.ECDSA_P384_SHA384
            }

            RappSignatureAlgorithm.RSA_PKCS1_SHA384 -> {
                QualifiedSigningAlgorithm.RSA_PKCS1_SHA384
            }

            else -> {
                when (desc.keyProfile) {
                    uniffi.refineid_rapp.RappCardKeyProfile.ECDSA_P384 -> QualifiedSigningAlgorithm.ECDSA_P384_SHA384
                    uniffi.refineid_rapp.RappCardKeyProfile.RSA3072 -> QualifiedSigningAlgorithm.RSA_PKCS1_SHA384
                    else -> null
                }
            }
        }

    override fun close() {
        isClosed = true
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        inbox.dismissAll()
    }
}
