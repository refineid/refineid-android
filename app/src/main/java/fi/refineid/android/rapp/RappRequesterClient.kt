@file:Suppress("TooGenericExceptionCaught", "TooManyFunctions")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappRequesterSessionEnd
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappQuitWithdrawalBoundMs
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappStreamProfileName
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Dials a paired custodian over the stream transport and holds the session
 * (RAPP v26.11.2 sections 6.3 and 8.3). The session opens with the
 * custodian's `session.ready` and this device's `session.hello`, each
 * naming its sender (section 7.1 items 5 and 6), and stays open across
 * operations, one at a time, until either endpoint ends it. Every close is
 * acknowledged (section 7.1 item 7): a received one is echoed, and this
 * device's own waits for the custodian's echo within its bound.
 *
 * One client dials once: [open] browses and runs the handshake, [close]
 * ends the session, and [deliverRevocationNotice] delivers a forgotten
 * pairing's close instead of a session, once per appearance of its
 * custodian (section 4.6 item 6). The [Listener] hears the card's
 * reports, the custodian's name, and how the session ended (section 4.5
 * item 6).
 */
internal class RappRequesterClient(
    private val context: Context,
    private val scope: CoroutineScope,
    private val pairRecord: RappPairRecord,
    private val vault: RappPairVault,
    private val listener: Listener,
    private val localName: () -> RappDisplayName = { RappLocalName.of(context) },
    private val monotonicMs: () -> ULong = RappClock::monotonicMs,
) {
    /** What the driver hears about the session. */
    interface Listener {
        /** The custodian reported its card. */
        fun onCardStatus(status: RappCardStatus)

        /** The session ended; how to treat it (section 4.5 item 6). */
        fun onSessionEnd(end: RappRequesterSessionEnd)

        /** The custodian named itself; the pair record holds it now. */
        fun onCustodianNamed(name: RappDisplayName)
    }

    /** What one dial ends with. */
    sealed interface OpenOutcome {
        /** `session.ready` verified and answered; operations may run. */
        data object Established : OpenOutcome

        /**
         * The dial ended before `session.ready`; [end] is set when a close
         * was exchanged, the custodian's revoking close among it.
         */
        data class Failed(
            val end: RappRequesterSessionEnd?,
        ) : OpenOutcome
    }

    private companion object {
        const val TRACE_TAG = "REQUESTER_CLIENT"

        /** The deadline each request carries (section 8.1 item 2). */
        const val OPERATION_LIFETIME_MS = 120_000UL
        const val CERTIFICATE_READ_TIMEOUT_MS = 15_000L
        const val AUTHENTICATION_TIMEOUT_MS = 60_000L

        /** How long this endpoint waits for the echo of its own close in a session (section 7.1 item 7). */
        val CLOSE_ECHO_WAIT_MS = rappQuitWithdrawalBoundMs().toLong()

        /** How often liveness is checked: a ping after 5 seconds of silence, the end after 30 (section 8.3). */
        const val LIVENESS_POLL_INTERVAL_MS = 1_000L

        val RANDOM_BYTE_COUNTS = rappRandomByteCounts()

        /** The value random material is overwritten with once used. */
        const val ERASED: Byte = 0
    }

    /** Whether an answer completes the run, given the card status received so far. */
    private sealed interface Acceptance<out T> {
        class Accepted<T>(
            val value: T,
        ) : Acceptance<T>

        data object AwaitingCardStatus : Acceptance<Nothing>

        data object Refused : Acceptance<Nothing>
    }

    /** Where a dial stands between its preamble and the established session. */
    private enum class Phase {
        AWAITING_HANDSHAKE,
        AWAITING_READY,

        /** This device's close went out before the session was established; only its echo matters now. */
        AWAITING_CLOSE_ECHO,
        ESTABLISHED,
    }

    private val sendLock = Any()
    private val operationMutex = Mutex()
    private val endReported = AtomicBoolean(false)

    /** Once a local close starts, only a crossing close is still reported. */
    private val closing = AtomicBoolean(false)
    private val tornDown = AtomicBoolean(false)

    private var browser: StreamRelayBrowser? = null
    private var session: RappSessionBridge? = null

    @Volatile
    private var operation: RappOperationBridge? = null

    @Volatile
    private var phase = Phase.AWAITING_HANDSHAKE

    private var livenessJob: Job? = null
    private var echoDeadlineJob: Job? = null

    private var openResult = CompletableDeferred<OpenOutcome>()

    /** The echo a local close waits for, with the crossing end when one crossed it. */
    private var closeResult: CompletableDeferred<RappRequesterSessionEnd?>? = null

    private var cardStatus: RappCardStatus? = null

    /** The operation running on the session, if any. */
    private var liveOperation: LiveOperation<*>? = null

    private inner class LiveOperation<T>(
        val id: RappOperationId,
        val accept: (RappAnswer, RappCardStatus?) -> Acceptance<T>,
        val result: CompletableDeferred<T?> = CompletableDeferred(),
    ) {
        var answer: RappAnswer? = null

        fun decide() {
            val received = answer ?: return
            if (result.isCompleted) return
            when (val acceptance = accept(received, cardStatus)) {
                is Acceptance.Accepted -> {
                    result.complete(acceptance.value)
                }

                Acceptance.AwaitingCardStatus -> {}

                Acceptance.Refused -> {
                    result.complete(null)
                }
            }
        }
    }

    /**
     * Dials once and opens the session, within [timeoutMs]; to
     * [directEndpoint] when set, else to the best phone browsing finds.
     * Established when `session.ready` verified; failed otherwise, with
     * the end when a close was exchanged before it.
     */
    suspend fun open(
        timeoutMs: Long,
        directEndpoint: RappDialCandidates.Endpoint? = null,
    ): OpenOutcome {
        if (!isDialable()) return OpenOutcome.Failed(null)
        openResult = CompletableDeferred()
        val relay =
            StreamRelayBrowser(context, scope, StreamRendezvousName.MODE_SESSION, rank = ::rank) { event ->
                try {
                    handle(event)
                } catch (e: Exception) {
                    trace("session failed", e)
                    transportFailed()
                }
            }
        browser = relay
        if (directEndpoint == null) relay.start() else relay.dialDirect(directEndpoint.host, directEndpoint.port)
        return try {
            withTimeoutOrNull(timeoutMs) { openResult.await() } ?: dialTimedOut()
        } finally {
            if (!isOpen) tearDown()
        }
    }

    /** Whether the session is established and operations may run. */
    val isOpen: Boolean
        get() = phase == Phase.ESTABLISHED && operation != null

    /**
     * Whether the echo of this device's own close arrived (section 7.1
     * item 7): a `session.close` that crossed the local one counts, since
     * it acknowledges it. The driver reads it after [close] to tell a
     * delivered revoking close from one the backlog must keep.
     */
    @Volatile
    var closeEchoReceived = false
        private set

    /** Whether the record may open a session: active, never forgotten. */
    private fun isDialable(): Boolean =
        try {
            pairRecord.pairing().state == RappPairState.Active
        } catch (_: Exception) {
            false
        }

    /**
     * The custodian card's authentication certificate, offered only when the
     * custodian named it by fingerprint in `card.status` on the session
     * (section 8.4 item 2); null when the session is not open or the
     * operation did not complete.
     */
    suspend fun readAuthenticationCertificate(timeoutMs: Long = CERTIFICATE_READ_TIMEOUT_MS): RappCertificate? =
        run(
            timeoutMs,
            begin = { bridge, operationId ->
                bridge.beginReadCertificate(
                    operationId = operationId.toWire(),
                    signatureCertificate = false,
                    localStartMs = monotonicMs(),
                    expiresAfterMs = OPERATION_LIFETIME_MS,
                )
            },
            accept = { answer, status ->
                val certificate = (answer as? RappAnswer.Certificate)?.certificate
                when {
                    certificate == null -> {
                        Acceptance.Refused
                    }

                    status == null -> {
                        Acceptance.AwaitingCardStatus
                    }

                    status is RappCardStatus.Present &&
                        status.fingerprint == RappCertificateFingerprint.of(certificate) -> {
                        Acceptance.Accepted(certificate)
                    }

                    else -> {
                        Acceptance.Refused
                    }
                }
            },
        )

    /** A signature in its section 9.2 wire form over [digest], or null when the operation did not complete. */
    suspend fun browserAuthenticate(
        origin: String,
        keyProfile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digest: ByteArray,
        timeoutMs: Long = AUTHENTICATION_TIMEOUT_MS,
    ): ByteArray? =
        run(
            timeoutMs,
            begin = { bridge, operationId ->
                bridge.beginBrowserAuthentication(
                    operationId.toWire(),
                    origin,
                    keyProfile,
                    algorithm,
                    digest,
                    monotonicMs(),
                    OPERATION_LIFETIME_MS,
                )
            },
            accept = { answer, _ ->
                (answer as? RappAnswer.Signature)?.let { Acceptance.Accepted(it.signature) } ?: Acceptance.Refused
            },
        )

    /**
     * Runs one operation on the open session, within [timeoutMs]; the
     * session carries one at a time. A refused or terminal operation leaves
     * the session open; one abandoned to its timeout closes it as a loss,
     * since it may still be live and no other operation can start beside
     * it.
     */
    private suspend fun <T> run(
        timeoutMs: Long,
        begin: (RappOperationBridge, RappOperationId) -> RappBridgeAction,
        accept: (RappAnswer, RappCardStatus?) -> Acceptance<T>,
    ): T? {
        var timedOut = false
        try {
            return operationMutex.withLock {
                val bridge = operation
                if (bridge == null || !isOpen) return null
                val live = LiveOperation(RappOperationId.random(SecureRandom()), accept)
                liveOperation = live
                try {
                    outcome(act(bridge) { begin(it, live.id) })
                    val awaited = withTimeoutOrNull(timeoutMs) { live.result.await() }
                    if (awaited == null && !live.result.isCompleted) timedOut = true
                    awaited
                } finally {
                    if (liveOperation === live) liveOperation = null
                }
            }
        } catch (cancelled: CancellationException) {
            timedOut = true
            throw cancelled
        } finally {
            if (timedOut) {
                reportEnd(RappRequesterSessionEnd.LOSS)
                close(RappCloseReason.NORMAL)
            }
        }
    }

    /**
     * Closes the open session with [reason] and waits for the custodian's
     * echo, at most [CLOSE_ECHO_WAIT_MS] (section 7.1 item 7). Returns the
     * end when a close crossed this one, which the caller acts on; null
     * otherwise.
     */
    suspend fun close(reason: RappCloseReason): RappRequesterSessionEnd? {
        if (!closing.compareAndSet(false, true)) return null
        liveOperation?.result?.complete(null)
        val bridge = operation
        if (bridge == null || !isOpen) {
            tearDown()
            return null
        }
        val awaited = CompletableDeferred<RappRequesterSessionEnd?>()
        closeResult = awaited
        val sent =
            when (val outcome = act(bridge) { it.closeWithReason(reason) }) {
                is RappBridgeOutcome.Send -> {
                    if (outcome.close is RappSentClose.Own) {
                        reportEnd(outcome.close.end)
                        awaitEcho()
                        true
                    } else {
                        outcome(outcome)
                        false
                    }
                }

                else -> {
                    outcome(outcome)
                    false
                }
            }
        if (!sent) return null
        return try {
            awaited.await()
        } finally {
            tearDown()
        }
    }

    /**
     * Dials once to deliver a forgotten pairing's close as the session's
     * first message and waits for the custodian's echo (section 4.6 item
     * 6, section 7.1 item 7), within [timeoutMs]. The record is destroyed
     * only on the echo; without it the pairing stays in the revocation
     * backlog until its custodian next appears or its idle expiry passes
     * (section 4.6 item 3). True when the echo arrived. Nothing is sent
     * or destroyed for a record that is not forgotten.
     */
    suspend fun deliverRevocationNotice(
        timeoutMs: Long,
        directEndpoint: RappDialCandidates.Endpoint? = null,
    ): Boolean {
        val pairId =
            try {
                pairRecord.pairing().id
            } catch (_: Exception) {
                return false
            }
        if (!isForgotten()) return false
        val echoed =
            withTimeoutOrNull(timeoutMs) {
                RevocationAttempt(directEndpoint).run()
            } == true
        if (echoed) RappPairRevocation.revoke(pairId, pairRecord, vault)
        return echoed
    }

    private fun isForgotten(): Boolean =
        try {
            pairRecord.pairing().state is RappPairState.Forgotten
        } catch (_: Exception) {
            false
        }

    /** Shuts the session down without a close, as after the pairing ended. */
    fun shutdown() {
        closing.set(true)
        tearDown()
    }

    /**
     * A phone whose hint names this pairing first, then one publishing no
     * hints; never one whose hints name only other pairings (discovery
     * hierarchy section 4.3).
     */
    private fun rank(attributes: Map<String, ByteArray?>): Int? {
        val named =
            try {
                pairRecord.matchesDiscoveryRecord(
                    StreamRendezvousName.entries(attributes),
                    StreamRendezvousName.nowUnixSeconds().toULong(),
                )
            } catch (_: Exception) {
                false
            }
        return when {
            named -> RappDialCandidates.BEST_RANK
            !StreamRendezvousName.hasHints(attributes) -> RappDialCandidates.UNHINTED_RANK
            else -> null
        }
    }

    private fun handle(event: StreamRelayEvent) {
        if (closing.get()) {
            if (event is StreamRelayEvent.Frame) receiveWhileClosing(event.data)
            return
        }
        when (event) {
            is StreamRelayEvent.Connected -> {
                // A fresh nonce and routing tag on every dial (section 2.2.1).
                send(pairRecord.sessionPreamble(rappStreamProfileName()))
                val opened = RappSessionBridge.beginRequester(pairRecord, vault, rappStreamProfileName())
                session = opened
                send(opened.writeHandshakeFrame())
            }

            is StreamRelayEvent.Frame -> {
                receive(event.data)
            }

            is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                transportFailed()
            }
        }
    }

    /** Feeds what arrives while a local close waits for its echo; only a close matters now. */
    private fun receiveWhileClosing(data: ByteArray) {
        val bridge = operation
        val opened = session
        try {
            if (bridge != null && phase == Phase.ESTABLISHED) {
                outcome(act(bridge) { it.receiveFrame(data, monotonicMs()) })
            } else if (opened != null && phase == Phase.AWAITING_CLOSE_ECHO) {
                outcome(RappBridgeOutcome.from(opened.receiveCloseEcho(data, monotonicMs())))
            }
        } catch (e: Exception) {
            trace("echo wait failed", e)
            tearDown()
        }
    }

    /** The transport failed: the dial fails, and an open session is a loss. */
    private fun transportFailed() {
        trace(RappSessionFailureLog.TRANSPORT_CLOSED, null)
        failOpen(null)
        liveOperation?.result?.complete(null)
        if (phase == Phase.ESTABLISHED) reportEnd(RappRequesterSessionEnd.LOSS)
        tearDown()
    }

    private fun receive(data: ByteArray) {
        val opened = checkNotNull(session)
        when (phase) {
            Phase.AWAITING_HANDSHAKE -> {
                handshake(opened, data)
            }

            Phase.AWAITING_READY -> {
                ready(opened, data)
            }

            Phase.AWAITING_CLOSE_ECHO -> {
                outcome(RappBridgeOutcome.from(opened.receiveCloseEcho(data, monotonicMs())))
            }

            Phase.ESTABLISHED -> {
                operation?.let { bridge ->
                    outcome(act(bridge) { it.receiveFrame(data, monotonicMs()) })
                }
            }
        }
    }

    /** Completes `Noise_KK`; the session then awaits `session.ready`. */
    private fun handshake(
        opened: RappSessionBridge,
        data: ByteArray,
    ) {
        try {
            opened.readHandshakeFrame(data)
            check(opened.handshakeComplete())
        } catch (e: Exception) {
            trace("handshake failed", e)
            failOpen(null)
            tearDown()
            return
        }
        opened.enterAuthentication()
        phase = Phase.AWAITING_READY
    }

    /**
     * Verifies `session.ready` and answers with `session.hello` naming
     * this device (section 7.1 items 5 and 6). A close in its place, the
     * custodian's revoking close among it, is echoed and ends the dial.
     */
    private fun ready(
        opened: RappSessionBridge,
        data: ByteArray,
    ) {
        val action =
            try {
                opened.receiveReady(data, monotonicMs(), localName().text)
            } catch (e: Exception) {
                trace("ready failed", e)
                failOpen(null)
                tearDown()
                return
            }
        when (val outcome = RappBridgeOutcome.from(action)) {
            is RappBridgeOutcome.Greeted -> {
                send(outcome.hello)
                try {
                    listener.onCustodianNamed(outcome.custodianName)
                } catch (e: Exception) {
                    trace("named listener failed", e)
                }
                opened.enterEstablished()
                val bridge =
                    RappOperationBridge.beginRequester(
                        opened,
                        OPERATION_LIFETIME_MS,
                        monotonicMs(),
                    )
                operation = bridge
                phase = Phase.ESTABLISHED
                startLiveness(bridge)
                openResult.complete(OpenOutcome.Established)
            }

            is RappBridgeOutcome.Send -> {
                send(outcome.frame)
                failOpen(outcome.close?.end)
                if (outcome.close is RappSentClose.Own) {
                    phase = Phase.AWAITING_CLOSE_ECHO
                    awaitEcho()
                } else {
                    tearDown()
                }
            }

            else -> {
                if (outcome is RappBridgeOutcome.Closed || outcome is RappBridgeOutcome.CloseAcknowledged) {
                    val end =
                        (outcome as? RappBridgeOutcome.Closed)?.end
                            ?: (outcome as RappBridgeOutcome.CloseAcknowledged).end
                    failOpen(end)
                } else {
                    failOpen(null)
                }
                tearDown()
            }
        }
    }

    private fun outcome(outcome: RappBridgeOutcome?) {
        when (outcome) {
            null -> {
                liveOperation?.result?.complete(null)
                if (phase == Phase.ESTABLISHED) reportEnd(RappRequesterSessionEnd.LOSS)
                tearDown()
            }

            is RappBridgeOutcome.Send -> {
                when (val close = outcome.close) {
                    null -> {}

                    is RappSentClose.Echo -> {
                        // While a local close runs, the peer's close crossed
                        // it and is still acted on (section 7.1 item 7).
                        reportEnd(close.end, crossing = true)
                        liveOperation?.result?.complete(null)
                        tearDown()
                    }

                    is RappSentClose.Own -> {
                        reportEnd(close.end)
                        awaitEcho()
                    }
                }
            }

            is RappBridgeOutcome.CloseAcknowledged -> {
                // A crossing close is acted on as the reason it carries
                // says; a plain echo completes the local close.
                closeEchoReceived = true
                if (outcome.end != null) reportEnd(outcome.end, crossing = true)
                liveOperation?.result?.complete(null)
                closeResult?.complete(outcome.end)
                tearDown()
            }

            is RappBridgeOutcome.Completed -> {
                val live = liveOperation
                if (live != null && outcome.operationId == live.id) {
                    live.answer = outcome.answer
                    live.decide()
                }
            }

            is RappBridgeOutcome.CardStatus -> {
                cardStatus = outcome.status
                try {
                    listener.onCardStatus(outcome.status)
                } catch (e: Exception) {
                    trace("card status listener failed", e)
                }
                @Suppress("UNCHECKED_CAST")
                (liveOperation as? LiveOperation<Any?>)?.decide()
            }

            is RappBridgeOutcome.Terminal -> {
                if (outcome.operationId == liveOperation?.id) {
                    trace("operation ended: ${outcome.reason}", null)
                    liveOperation?.result?.complete(null)
                }
            }

            is RappBridgeOutcome.Closed -> {
                liveOperation?.result?.complete(null)
                // A close that crossed the local one arrives as its echo,
                // whatever its reason (section 7.1 item 7).
                if (closing.get()) closeEchoReceived = true
                if (phase == Phase.ESTABLISHED) {
                    reportEnd(outcome.end ?: RappRequesterSessionEnd.LOSS)
                } else {
                    failOpen(outcome.end)
                }
                closeResult?.complete(null)
                tearDown()
            }

            RappBridgeOutcome.Idle,
            is RappBridgeOutcome.Progress,
            is RappBridgeOutcome.Admitted,
            is RappBridgeOutcome.AwaitApproval,
            is RappBridgeOutcome.ExecuteRead,
            is RappBridgeOutcome.ExecuteCommand,
            is RappBridgeOutcome.Greeted,
            is RappBridgeOutcome.PeerNamed,
            -> {}
        }
    }

    /**
     * Reports how the session ended, once. After a local close started,
     * only a crossing close is still reported.
     */
    private fun reportEnd(
        end: RappRequesterSessionEnd?,
        crossing: Boolean = false,
    ) {
        if (end == null) return
        if (closing.get() && !crossing) return
        if (endReported.compareAndSet(false, true)) {
            trace(RappSessionFailureLog.sessionEnd(end), null)
            try {
                listener.onSessionEnd(end)
            } catch (e: Exception) {
                trace("end listener failed", e)
            }
        }
    }

    /** Fails the dial, unless it already ended; [end] says what a close exchanged. */
    private fun failOpen(end: RappRequesterSessionEnd?) {
        if (end != null) trace(RappSessionFailureLog.sessionEnd(end), null)
        openResult.complete(OpenOutcome.Failed(end))
    }

    private fun dialTimedOut(): OpenOutcome {
        trace(RappSessionFailureLog.DIAL_TIMED_OUT, null)
        openResult.complete(OpenOutcome.Failed(null))
        return OpenOutcome.Failed(null)
    }

    private fun startLiveness(bridge: RappOperationBridge) {
        livenessJob =
            scope.launch(Dispatchers.IO) {
                val random = SecureRandom()
                while (isActive && operation === bridge) {
                    delay(LIVENESS_POLL_INTERVAL_MS)
                    val challenge = ByteArray(RANDOM_BYTE_COUNTS.livenessChallenge.toInt()).also(random::nextBytes)
                    try {
                        outcome(act(bridge) { it.pollLiveness(monotonicMs(), challenge) })
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (e: Exception) {
                        trace("liveness failed", e)
                    } finally {
                        challenge.fill(ERASED)
                    }
                }
            }
    }

    /** Runs one bridge call, types its action at the binding border, and sends the frame it sealed. */
    private fun act(
        bridge: RappOperationBridge,
        call: (RappOperationBridge) -> RappBridgeAction,
    ): RappBridgeOutcome? =
        synchronized(sendLock) {
            try {
                val outcome = RappBridgeOutcome.from(call(bridge))
                if (outcome is RappBridgeOutcome.Send) browser?.send(outcome.frame)
                outcome
            } catch (e: Exception) {
                trace("bridge call failed", e)
                null
            }
        }

    private fun send(frame: ByteArray) {
        synchronized(sendLock) { (browser ?: throw IOException("dial closed")).send(frame) }
    }

    /**
     * Keeps the link for the custodian's echo of this device's close, at
     * most [CLOSE_ECHO_WAIT_MS] (section 7.1 item 7).
     */
    private fun awaitEcho() {
        if (echoDeadlineJob != null) return
        echoDeadlineJob =
            scope.launch {
                delay(CLOSE_ECHO_WAIT_MS)
                closeResult?.complete(null)
                tearDown()
            }
    }

    /** Closes the bridges and the link once nothing more is awaited on it. */
    private fun tearDown() {
        liveOperation?.result?.complete(null)
        if (!tornDown.compareAndSet(false, true)) return
        openResult.complete(OpenOutcome.Failed(null))
        closeResult?.complete(null)
        livenessJob?.cancel()
        livenessJob = null
        echoDeadlineJob?.cancel()
        echoDeadlineJob = null
        val bridge = operation
        operation = null
        bridge?.close()
        session?.close()
        session = null
        browser?.close()
        browser = null
    }

    /**
     * One revocation attempt: the routing preamble, `Noise_KK`, and the
     * forgotten pairing's close as the session's only message, with the
     * wait for the custodian's echo left to the caller's bound.
     */
    private inner class RevocationAttempt(
        private val directEndpoint: RappDialCandidates.Endpoint?,
    ) {
        private val echoed = CompletableDeferred<Boolean>()
        private var browser: StreamRelayBrowser? = null
        private var session: RappSessionBridge? = null
        private var handshakeDone = false

        suspend fun run(): Boolean {
            val relay =
                StreamRelayBrowser(context, scope, StreamRendezvousName.MODE_SESSION, rank = ::rank) { event ->
                    try {
                        handle(event)
                    } catch (e: Exception) {
                        trace("revocation attempt failed", e)
                        echoed.complete(false)
                    }
                }
            browser = relay
            if (directEndpoint == null) relay.start() else relay.dialDirect(directEndpoint.host, directEndpoint.port)
            return try {
                echoed.await()
            } finally {
                session?.close()
                session = null
                relay.close()
                browser = null
            }
        }

        private fun handle(event: StreamRelayEvent) {
            when (event) {
                is StreamRelayEvent.Connected -> {
                    val relay = checkNotNull(browser)
                    relay.send(pairRecord.sessionPreamble(rappStreamProfileName()))
                    val opened = RappSessionBridge.beginRequester(pairRecord, vault, rappStreamProfileName())
                    session = opened
                    relay.send(opened.writeHandshakeFrame())
                }

                is StreamRelayEvent.Frame -> {
                    val opened = checkNotNull(session)
                    if (!handshakeDone) {
                        opened.readHandshakeFrame(event.data)
                        check(opened.handshakeComplete())
                        opened.enterAuthentication()
                        handshakeDone = true
                        checkNotNull(browser).send(opened.deliverRevocationNotice(RappClock.wallMs()))
                    } else {
                        val outcome = RappBridgeOutcome.from(opened.receiveCloseEcho(event.data, monotonicMs()))
                        if (outcome is RappBridgeOutcome.CloseAcknowledged) {
                            echoed.complete(true)
                        }
                    }
                }

                is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                    echoed.complete(false)
                }
            }
        }
    }

    /**
     * The dev log: every line names the paired phone and the stream
     * transport, so a failed session says who was talking. The name is the
     * pair record's device label, refreshed every session (RAPP v26.11.2
     * section 4.3 items 3 and 4).
     */
    private fun trace(
        message: String,
        error: Exception?,
    ) {
        if (BuildConfig.DEBUG) {
            android.util.Log.w(
                TRACE_TAG,
                message + ", " + RappSessionFailureLog.peerName(pairRecord) +
                    ", " + RappSessionFailureLog.NETWORK_TRANSPORT,
                error,
            )
        }
    }
}
