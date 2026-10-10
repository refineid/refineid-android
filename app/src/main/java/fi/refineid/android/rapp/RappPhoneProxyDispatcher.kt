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
import fi.refineid.android.core.authenticationFailure
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.prime.PrimedCanStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
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
import uniffi.refineid_rapp.rappStreamProfileName
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
    private val onAuthenticationRejected: () -> Unit = {},
    private val onAuthenticationVerified: ((ByteArray, Long) -> Boolean)? = null,
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
        private const val DEFAULT_REQUESTER_DISPLAY_NAME = "Computer"

        /** Maximum time to wait for an NFC card certificate read before reporting card-removed. */
        private const val CERT_READ_TIMEOUT_MS = 5_000L
        private const val NANOS_PER_MICROSECOND = 1_000L
        private const val LIVENESS_POLL_INTERVAL_MS = 1_000L
        private const val LIVENESS_CHALLENGE_BYTES = 32
        private const val LIVENESS_JITTER_MS = 0L
        private const val SESSION_NONCE_BYTES = 32
        private const val SHA256_DIGEST_LENGTH = 32
        private const val SHA384_DIGEST_LENGTH = 48
    }

    private fun dismissInbox(opIdHex: String? = null) {
        scope.launch(Dispatchers.Main) {
            if (opIdHex != null) {
                inbox.dismiss(opIdHex)
            } else {
                inbox.dismissAll()
            }
        }
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
        listener.start(rendezvousName, emptyMap())
    }

    fun stopListening() {
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        livenessJob?.cancel()
        livenessJob = null
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        pairRecord = null
        vault = null
        _connectedPeer.value = null
        lastReadAuthCertDer = null
        clearPendingPins()
        dismissInbox()
    }

    fun disconnectClient() {
        livenessJob?.cancel()
        livenessJob = null
        activeListener?.close()
        sessionBridge?.close()
        sessionBridge = null
        sessionHandshakeDone = false
        operationBridge?.close()
        operationBridge = null
        _connectedPeer.value = null
        lastReadAuthCertDer = null
        clearPendingPins()
        dismissInbox()
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
                handleRelayFrame(event)
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                AppTrace.rappConnectionDropped(
                    if (event is StreamRelayEvent.Error) {
                        event.cause.javaClass.simpleName
                    } else {
                        "stream disconnected"
                    },
                )
                livenessJob?.cancel()
                livenessJob = null
                activeOperationJob?.cancel()
                activeOperationJob = null
                sessionBridge?.close()
                sessionBridge = null
                sessionHandshakeDone = false
                operationBridge?.close()
                operationBridge = null
                _connectedPeer.value = null
                lastReadAuthCertDer = null
                clearPendingPins()
                dismissInbox()
            }
        }
    }

    private fun handleRelayFrame(event: StreamRelayEvent.Frame) {
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
                    sessionBridge =
                        RappSessionBridge.beginProxy(
                            pair = pair,
                            vault = vlt,
                            transportProfile = rappStreamProfileName(),
                        )
                    return
                }
            } catch (_: Exception) {
            }

            // Not preamble or preamble was skipped: treat as Noise Message 1
            try {
                val sess =
                    RappSessionBridge.beginProxy(
                        pair = pair,
                        vault = vlt,
                        transportProfile = rappStreamProfileName(),
                    )
                sessionBridge = sess
                sess.readHandshakeFrame(event.data)
                val reply = sess.writeHandshakeFrame()
                activeListener?.send(reply)
                if (sess.handshakeComplete()) {
                    sessionHandshakeDone = true
                    sess.enterAuthentication()
                    val nonce = ByteArray(SESSION_NONCE_BYTES).also { SecureRandom().nextBytes(it) }
                    try {
                        val ready = sess.sendReady(nonce)
                        activeListener?.send(ready)
                    } finally {
                        nonce.fill(0)
                    }
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
                    val nonce = ByteArray(SESSION_NONCE_BYTES).also { SecureRandom().nextBytes(it) }
                    try {
                        val ready = currentSession.sendReady(nonce)
                        activeListener?.send(ready)
                    } finally {
                        nonce.fill(0)
                    }
                }
            } catch (_: Exception) {
            }
            return
        }

        // Bilateral ready confirmation
        try {
            currentSession.receiveReady(event.data, RappClock.wallMs())
            currentSession.enterEstablished()
            activeListener?.clearSocketTimeout()

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
                    nowMs = RappClock.monotonicMs(),
                )
            operationBridge = newOpBridge
            startLivenessLoop(newOpBridge)
            val currentPair = pairRecord
            if (currentPair != null) {
                val hex = currentPair.metadata().pairId.joinToString("") { "%02x".format(it) }
                val peer =
                    catalog.listPairs().firstOrNull { it.pairIdHex == hex }
                        ?: PairedPeer(
                            pairIdHex = hex,
                            displayName = DEFAULT_REQUESTER_DISPLAY_NAME,
                            platform = "macOS",
                            createdAtMs = System.currentTimeMillis(),
                        )
                _connectedPeer.value = peer
                AppTrace.rappPairingCompleted(peer.displayName)
            }
        } catch (_: Exception) {
        }
    }

    private val pendingPin1 = java.util.concurrent.ConcurrentHashMap<String, Pin1Submission>()
    private val pendingPin2 = java.util.concurrent.ConcurrentHashMap<String, Pin2Submission>()
    private var activeOperationJob: Job? = null
    private var livenessJob: Job? = null

    private fun clearPendingPins() {
        pendingPin1.values.forEach { it.close() }
        pendingPin1.clear()
        pendingPin2.values.forEach { it.close() }
        pendingPin2.clear()
    }

    private fun startLivenessLoop(bridge: RappOperationBridge) {
        livenessJob?.cancel()
        livenessJob =
            scope.launch(Dispatchers.IO) {
                val challenge = ByteArray(LIVENESS_CHALLENGE_BYTES)
                val secureRandom = SecureRandom()
                try {
                    while (isActive) {
                        delay(LIVENESS_POLL_INTERVAL_MS)
                        try {
                            secureRandom.nextBytes(challenge)
                            val challengeCopy = challenge.copyOf()
                            try {
                                val action =
                                    bridge.pollLiveness(
                                        nowMs = RappClock.monotonicMs(),
                                        challenge = challengeCopy,
                                        jitterMs = LIVENESS_JITTER_MS,
                                    )
                                handleBridgeAction(action, bridge)
                            } finally {
                                challengeCopy.fill(0)
                            }
                        } catch (_: Exception) {
                            break
                        }
                    }
                } finally {
                    challenge.fill(0)
                }
            }
    }

    private fun handleBridgeAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        bridge: RappOperationBridge,
    ) {
        // A status report travels with the result it re-delivers, in order.
        for (frame in listOfNotNull(action.frame) + action.additionalFrames) {
            try {
                activeListener?.send(frame)
            } catch (_: Exception) {
            }
        }

        if (action.closeSessionAfterSend) {
            dropConnection()
            return
        }

        if (action.kind == RappBridgeActionKind.SEND_FRAME) {
            return
        }

        val opId = action.operationId
        val opIdHex = opId?.joinToString("") { "%02x".format(it) }

        if (handleLifecycleAction(action, opIdHex)) {
            return
        }

        handleOperationAction(action, opId, opIdHex, bridge)
    }

    private fun handleLifecycleAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        opIdHex: String?,
    ): Boolean {
        when (action.kind) {
            RappBridgeActionKind.SESSION_CLOSED -> {
                dropConnection()
                return true
            }

            RappBridgeActionKind.PAIR_REVOKED -> {
                val currentPair = pairRecord
                if (currentPair != null) {
                    val hex = currentPair.metadata().pairId.joinToString("") { "%02x".format(it) }
                    catalog.removePair(hex)
                }
                dropConnection()
                return true
            }

            RappBridgeActionKind.TERMINAL -> {
                if (opIdHex != null) {
                    dismissInbox(opIdHex)
                    pendingPin1.remove(opIdHex)?.close()
                    pendingPin2.remove(opIdHex)?.close()
                }
                return true
            }

            else -> {
                return false
            }
        }
    }

    private fun handleOperationAction(
        action: uniffi.refineid_rapp.RappBridgeAction,
        opId: ByteArray?,
        opIdHex: String?,
        bridge: RappOperationBridge,
    ) {
        when (action.kind) {
            RappBridgeActionKind.INSPECT_PREREQUISITES -> {
                if (opId == null) return
                try {
                    val resp = bridge.prerequisitesComplete(opId)
                    handleBridgeAction(resp, bridge)
                } catch (_: Exception) {
                }
            }

            RappBridgeActionKind.EXECUTE_SAFE_READ -> {
                if (opId != null) {
                    handleSafeRead(action, opId, bridge)
                }
            }

            RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                if (opId != null && opIdHex != null) {
                    action.operation?.let { desc ->
                        handleApproval(desc, opId, opIdHex, bridge)
                    }
                }
            }

            RappBridgeActionKind.EXECUTE_CARD_COMMAND -> {
                if (opId != null && opIdHex != null) {
                    action.operation?.let { desc ->
                        handleExecute(desc, opId, opIdHex, bridge)
                    }
                }
            }

            RappBridgeActionKind.RESULT_ACKNOWLEDGMENT -> {
                if (opId != null) {
                    try {
                        bridge.acknowledgmentReleased(opId)
                    } catch (_: Exception) {
                    }
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
                val candidatePin: Pin1Submission? =
                    if (cachedPin != null) {
                        val sub =
                            cachedPin.consume { pinBytes ->
                                Pin1Submission.fromOwnedBytes(pinBytes.copyOf())
                            }
                        if (pinCache.isRejected(sub)) {
                            sub.close()
                            null
                        } else {
                            sub
                        }
                    } else {
                        val stored = primedCanStore?.readPin1()
                        if (stored != null) {
                            val sub = Pin1Submission.fromOwnedBytes(stored)
                            if (pinCache?.isRejected(sub) == true) {
                                sub.close()
                                null
                            } else {
                                sub
                            }
                        } else {
                            null
                        }
                    }

                if (candidatePin != null) {
                    pendingPin1.remove(opIdHex)?.close()
                    pendingPin1[opIdHex] = candidatePin
                    approve(opId, bridge)
                } else {
                    val requesterName =
                        catalog
                            .listPairs()
                            .firstOrNull()
                            ?.displayName
                            ?.takeIf { it.isNotBlank() }
                            ?: DEFAULT_REQUESTER_DISPLAY_NAME
                    scope.launch(Dispatchers.Main) {
                        inbox.askBrowserAuth(
                            requestId = opIdHex,
                            requester = requesterName,
                            onApproved = { pin1Submission ->
                                if (pinCache?.isRejected(pin1Submission) == true) {
                                    pin1Submission.close()
                                    respondKnownRejectedPin(opId, bridge)
                                } else {
                                    pendingPin1.remove(opIdHex)?.close()
                                    pendingPin1[opIdHex] = pin1Submission
                                    approve(opId, bridge)
                                }
                            },
                            onDenied = { deny(opId, bridge) },
                        )
                    }
                }
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                val requesterName =
                    catalog
                        .listPairs()
                        .firstOrNull()
                        ?.displayName
                        ?.takeIf { it.isNotBlank() }
                        ?: DEFAULT_REQUESTER_DISPLAY_NAME
                scope.launch(Dispatchers.Main) {
                    inbox.askDocumentSign(
                        requestId = opIdHex,
                        requester = requesterName,
                        onApproved = { pin2Submission ->
                            pendingPin2.remove(opIdHex)?.close()
                            pendingPin2[opIdHex] = pin2Submission
                            approve(opId, bridge)
                        },
                        onDenied = { deny(opId, bridge) },
                    )
                }
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
                } catch (_: Exception) {
                    AppTrace.rappOperationApproveFailed("approve_failed")
                }
            }
    }

    /** Tears down the active stream so Mac must reconnect for the next request. */
    private fun dropConnection() {
        AppTrace.rappConnectionDropped("proxy dispatcher dropConnection")
        livenessJob?.cancel()
        livenessJob = null
        activeOperationJob?.cancel()
        activeOperationJob = null
        lastReadAuthCertDer = null
        activeListener?.disconnectClient()
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        sessionHandshakeDone = false
        clearPendingPins()
        _connectedPeer.value = null
        dismissInbox()
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
                } catch (_: Exception) {
                    AppTrace.rappOperationDenyFailed("deny_failed")
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
        when (desc.kind) {
            RappOperationKind.BROWSER_AUTHENTICATE -> {
                val pin1Submission = pendingPin1.remove(opIdHex)
                if (pin1Submission == null) {
                    AppTrace.rappOperationDenied(opIdHex, "pin1_missing")
                    respondBridgeDeny(opId, bridge)
                    return
                }
                executeBrowserAuth(opId, desc, pin1Submission, bridge)
            }

            RappOperationKind.SIGN_DOCUMENT -> {
                val pin2Submission = pendingPin2.remove(opIdHex)
                if (pin2Submission == null) {
                    AppTrace.rappOperationDenied(opIdHex, "pin2_missing")
                    respondBridgeDeny(opId, bridge)
                    return
                }
                executeDocumentSign(opId, desc, pin2Submission, bridge)
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
        opId: ByteArray,
        opIdHex: String,
        action: RappAuthAction,
        bridge: RappOperationBridge,
        forcePrompt: Boolean = false,
    ): CardReadyOutcome {
        if (!forcePrompt && isCardReady()) return CardReadyOutcome.READY
        val requesterName =
            catalog
                .listPairs()
                .firstOrNull()
                ?.displayName
                ?.takeIf { it.isNotBlank() }
                ?: DEFAULT_REQUESTER_DISPLAY_NAME
        var cancelled = false
        AppTrace.rappCardPromptShown(opIdHex, action.name)
        try {
            val progressAction =
                bridge.reportProgress(opId, uniffi.refineid_rapp.RappProgressEvent.WAITING_FOR_CARD)
            handleBridgeAction(progressAction, bridge)
        } catch (e: Exception) {
            AppTrace.rappProgressReportFailed("waiting_for_card", e.javaClass.simpleName)
        }
        scope.launch(Dispatchers.Main) {
            inbox.showTapPrompt(
                requestId = opIdHex,
                requester = requesterName,
                action = action,
                onCancel = { cancelled = true },
            )
        }
        val ready =
            try {
                awaitCardReady()
            } finally {
                AppTrace.rappCardPromptDismissed(opIdHex)
                scope.launch(Dispatchers.Main) {
                    inbox.dismissTapPrompt(opIdHex)
                }
                try {
                    val progressAction =
                        bridge.reportProgress(opId, uniffi.refineid_rapp.RappProgressEvent.CARD_WAIT_ENDED)
                    handleBridgeAction(progressAction, bridge)
                } catch (e: Exception) {
                    AppTrace.rappProgressReportFailed("card_wait_ended", e.javaClass.simpleName)
                }
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
        when (ensureCardReady(opId, opIdHex, action, bridge, forcePrompt = forcePrompt)) {
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
        if (!isCardReady()) return null
        lastReadAuthCertDer?.let { return it.copyOf() }
        activeAuthCertDer()?.let { return it.copyOf() }
        return null
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
        lastReadAuthCertDer = null
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

    /**
     * Reports a credential the card refused (RAPP v26.10.1 section 10.2). A
     * wrong PIN with attempts left keeps the pairing; a blocked counter, or a
     * refusal whose count is unknown, revokes it.
     */
    private fun respondRejectedCredential(
        opId: ByteArray,
        remainingRetries: Int?,
        bridge: RappOperationBridge,
    ) {
        try {
            val resp =
                when (val action = RappCredentialRejection.of(remainingRetries)) {
                    is RappCredentialRejection.AttemptsRemain -> {
                        bridge.invalidCredential(opId, action.remainingRetries)
                    }

                    RappCredentialRejection.Blocked -> {
                        bridge.credentialRejected(opId, RappClock.monotonicMs())
                    }
                }
            handleBridgeAction(resp, bridge)
        } catch (_: Exception) {
        }
    }

    /**
     * Refuses a PIN this phone already saw the card reject. No card command
     * runs and no attempt is spent, so the session and pairing stay; the
     * requester learns the holder's submission was not usable.
     */
    private fun respondKnownRejectedPin(
        opId: ByteArray,
        bridge: RappOperationBridge,
    ) {
        respondBridgeDeny(opId, bridge)
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
                if (sessionBridge == null || activeListener == null) {
                    respondCardRemoved(opId, bridge)
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
                    when (ensureCardReady(opId, opIdHex, authAction, bridge, forcePrompt = true)) {
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
        pin1Submission: Pin1Submission,
        bridge: RappOperationBridge,
    ) {
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                try {
                    if (sessionBridge == null || activeListener == null) {
                        respondCardRemoved(opId, bridge)
                        return@launch
                    }
                    val cacheGeneration = pinCache?.generation
                    val startedNs = System.nanoTime()
                    val opIdHex = opId.joinToString("") { "%02x".format(it) }
                    val algorithm = resolveSignAlgorithm(desc)
                    if (algorithm == null) {
                        AppTrace.rappOperationFailed("browser_auth", opIdHex, "unsupported_algorithm")
                        respondBridgeInvalid(opId, bridge)
                        return@launch
                    }

                    // Check if candidate PIN was already rejected
                    if (pinCache?.isRejected(pin1Submission) == true) {
                        AppTrace.rappOperationDenied(opIdHex, "known_rejected_pin")
                        respondKnownRejectedPin(opId, bridge)
                        return@launch
                    }

                    if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.BROWSER_AUTH, bridge)) {
                        return@launch
                    }
                    var service = authCardService()
                    if (service == null) {
                        val cardReady =
                            ensureCardOrAbort(
                                opId = opId,
                                opIdHex = opIdHex,
                                action = RappAuthAction.BROWSER_AUTH,
                                bridge = bridge,
                                forcePrompt = true,
                            )
                        if (!cardReady) {
                            return@launch
                        }
                        service = authCardService()
                    }
                    if (service == null) {
                        AppTrace.rappOperationFailed("browser_auth", opIdHex, "service_unavailable")
                        respondCardRemoved(opId, bridge)
                        return@launch
                    }

                    if (pinCache?.isVerified(pin1Submission) != true) {
                        val candidate = Pin1Submission.fromOwnedBytes(pin1Submission.copyBytes())
                        val verification = service.verifyAuthenticationPin(candidate)
                        val failure = verification.result.authenticationFailure()
                        if (failure != null) {
                            handleBrowserAuthFailure(
                                opId,
                                opIdHex,
                                pin1Submission,
                                AuthenticationSignResult.Failure(failure, verification.remainingRetries),
                                bridge,
                            )
                            return@launch
                        }
                    }
                    val authResult =
                        performBrowserAuthWithRetry(
                            opId = opId,
                            opIdHex = opIdHex,
                            algorithm = algorithm,
                            pin1Submission = pin1Submission,
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
                                cacheGeneration = cacheGeneration,
                                pin1Submission = pin1Submission,
                                service = service,
                                result = result,
                                bridge = bridge,
                            )
                        }

                        is AuthenticationSignResult.Failure -> {
                            handleBrowserAuthFailure(
                                opId = opId,
                                opIdHex = opIdHex,
                                pin1Submission = pin1Submission,
                                result = result,
                                bridge = bridge,
                            )
                        }
                    }
                } finally {
                    pin1Submission.close()
                }
            }
    }

    private suspend fun performBrowserAuthWithRetry(
        opId: ByteArray,
        opIdHex: String,
        algorithm: AuthenticationSigningAlgorithm,
        pin1Submission: Pin1Submission,
        digest: ByteArray,
        initialService: AuthenticationCardService,
        bridge: RappOperationBridge,
    ): Pair<AuthenticationCardService, AuthenticationSignResult>? {
        var service = initialService
        val initialBytes =
            try {
                pin1Submission.copyBytes()
            } catch (_: IllegalStateException) {
                return null
            }
        var result =
            service.signAuthenticationDigest(
                algorithm = algorithm,
                pin1 = Pin1Submission.fromOwnedBytes(initialBytes),
                digest = digest,
            )
        if (result is AuthenticationSignResult.Failure &&
            result.kind == AuthenticationSignFailure.CARD_UNAVAILABLE
        ) {
            val cardReady =
                ensureCardOrAbort(
                    opId = opId,
                    opIdHex = opIdHex,
                    action = RappAuthAction.BROWSER_AUTH,
                    bridge = bridge,
                    forcePrompt = true,
                )
            if (!cardReady) {
                return null
            }
            val retryService = authCardService()
            if (retryService != null) {
                service = retryService
                val retryBytes =
                    try {
                        pin1Submission.copyBytes()
                    } catch (_: IllegalStateException) {
                        return null
                    }
                result =
                    retryService.signAuthenticationDigest(
                        algorithm = algorithm,
                        pin1 = Pin1Submission.fromOwnedBytes(retryBytes),
                        digest = digest,
                    )
            }
        }
        return Pair(service, result)
    }

    private fun handleBrowserAuthSuccess(
        opId: ByteArray,
        opIdHex: String,
        startedNs: Long,
        cacheGeneration: Long?,
        pin1Submission: Pin1Submission,
        service: AuthenticationCardService,
        result: AuthenticationSignResult.Success,
        bridge: RappOperationBridge,
    ) {
        try {
            if (onAuthenticationVerified != null && cacheGeneration != null) {
                if (!onAuthenticationVerified.invoke(pin1Submission.copyBytes(), cacheGeneration)) {
                    result.signature.close()
                    respondCardRemoved(opId, bridge)
                    return
                }
            } else if (pinCache?.recordVerified(pin1Submission.copyBytes(), cacheGeneration) == true &&
                primedCanStore?.isPrimed() == true
            ) {
                primedCanStore.writePin1(pin1Submission.copyBytes())
            }
        } catch (_: IllegalStateException) {
            // If the submission was already closed or consumed, skip caching and proceed.
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
        pin1Submission: Pin1Submission,
        result: AuthenticationSignResult.Failure,
        bridge: RappOperationBridge,
    ) {
        AppTrace.rappOperationFailed("browser_auth", opIdHex, result.kind.name)
        if (result.kind == AuthenticationSignFailure.WRONG_PIN || result.kind == AuthenticationSignFailure.PIN_LOCKED) {
            if (result.kind == AuthenticationSignFailure.WRONG_PIN) {
                pinCache?.recordRejected(pin1Submission.copyBytes())
            }
            primedCanStore?.forgetPin1()
            respondRejectedCredential(opId, result.remainingRetries, bridge)
            onAuthenticationRejected()
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
        pin2Submission: Pin2Submission,
        bridge: RappOperationBridge,
    ) {
        activeOperationJob?.cancel()
        activeOperationJob =
            scope.launch(Dispatchers.IO) {
                try {
                    if (sessionBridge == null || activeListener == null) {
                        respondCardRemoved(opId, bridge)
                        return@launch
                    }
                    val startedNs = System.nanoTime()
                    val opIdHex = opId.joinToString("") { "%02x".format(it) }
                    val algorithm = resolveQualifiedAlgorithm(desc)
                    if (algorithm == null) {
                        AppTrace.rappOperationFailed("document_sign", opIdHex, "unsupported_algorithm")
                        respondBridgeInvalid(opId, bridge)
                        return@launch
                    }
                    if (!ensureCardOrAbort(opId, opIdHex, RappAuthAction.DOCUMENT_SIGN, bridge)) {
                        return@launch
                    }
                    var service = qualifiedCardService()
                    if (service == null) {
                        val cardReady =
                            ensureCardOrAbort(
                                opId = opId,
                                opIdHex = opIdHex,
                                action = RappAuthAction.DOCUMENT_SIGN,
                                bridge = bridge,
                                forcePrompt = true,
                            )
                        if (!cardReady) {
                            return@launch
                        }
                        service = qualifiedCardService()
                    }
                    if (service == null) {
                        AppTrace.rappOperationFailed("document_sign", opIdHex, "service_unavailable")
                        respondCardRemoved(opId, bridge)
                        return@launch
                    }
                    var expectedCert = readSignatureCertificateWithTimeout()
                    if (expectedCert == null) {
                        val cardReady =
                            ensureCardOrAbort(
                                opId = opId,
                                opIdHex = opIdHex,
                                action = RappAuthAction.DOCUMENT_SIGN,
                                bridge = bridge,
                                forcePrompt = true,
                            )
                        if (!cardReady) {
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
                                pin2Submission = pin2Submission,
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
                } finally {
                    pin2Submission.close()
                }
            }
    }

    private suspend fun performQualifiedSignWithRetry(
        opId: ByteArray,
        opIdHex: String,
        desc: RappOperationDescriptor,
        pin2Submission: Pin2Submission,
        algorithm: QualifiedSigningAlgorithm,
        expectedCert: NativeQualifiedCertificate,
        bridge: RappOperationBridge,
    ): QualifiedSignResult? {
        val service = qualifiedCardService() ?: return null
        val pinBytes =
            try {
                pin2Submission.copyBytes()
            } catch (_: IllegalStateException) {
                return null
            }
        val deferred = CompletableDeferred<QualifiedSignResult>()
        service.requestQualifiedDigestSignature(
            algorithm = algorithm,
            pin2 = Pin2Submission.fromOwnedBytes(pinBytes),
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
                val freshCert = readSignatureCertificateWithTimeout() ?: return null
                try {
                    val retryPinBytes = pin2Submission.copyBytes()
                    val retryDeferred = CompletableDeferred<QualifiedSignResult>()
                    retryService.requestQualifiedDigestSignature(
                        algorithm = algorithm,
                        pin2 = Pin2Submission.fromOwnedBytes(retryPinBytes),
                        digest = desc.digest,
                        expectedCertificate = freshCert,
                    ) { rResult ->
                        retryDeferred.complete(rResult)
                    }
                    signResult = retryDeferred.await()
                } catch (_: IllegalStateException) {
                    return null
                } finally {
                    freshCert.close()
                }
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
        when (result.kind) {
            QualifiedSignFailure.WRONG_PIN, QualifiedSignFailure.PIN_LOCKED -> {
                respondRejectedCredential(opId, result.remainingRetries, bridge)
            }

            else -> {
                respondCardRemoved(opId, bridge)
            }
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
        livenessJob?.cancel()
        livenessJob = null
        activeOperationJob?.cancel()
        activeOperationJob = null
        clearPendingPins()
        activeListener?.close()
        activeListener = null
        operationBridge?.close()
        operationBridge = null
        sessionBridge?.close()
        sessionBridge = null
        dismissInbox()
    }
}
