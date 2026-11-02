@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappRequesterSessionEnd
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappQuitWithdrawalBoundMs
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappRevocationAttemptBoundMs
import uniffi.refineid_rapp.rappStreamProfileName
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Dials a paired custodian over the stream transport and runs one operation
 * on its card per session (RAPP v26.11.2 sections 6.3 and 8). The session
 * opens with the custodian's `session.ready` and this device's
 * `session.hello`, each naming its sender (section 7.1 items 5 and 6). A
 * pairing the local user forgot delivers its `pairing_revoked` close instead
 * (section 4.6 items 2 and 6), and a custodian that forgot this pairing
 * revokes it here (section 4.6 item 4) and calls [onPairingRevoked]; the
 * custodian's name from `session.ready` reaches [onCustodianNamed]. Every
 * close is acknowledged (section 7.1 item 7): a received one is echoed, and
 * this device's own waits for the custodian's echo within its bound.
 */
internal class RappRequesterClient(
    private val context: Context,
    private val scope: CoroutineScope,
    private val pairRecord: RappPairRecord,
    private val vault: AndroidRappVault,
    private val onPairingRevoked: () -> Unit = {},
    private val onCustodianNamed: (RappDisplayName) -> Unit = {},
) {
    private companion object {
        const val TRACE_TAG = "REQUESTER_CLIENT"

        /** The deadline each request carries (section 8.1 item 2). */
        const val OPERATION_LIFETIME_MS = 120_000UL
        const val CERTIFICATE_READ_TIMEOUT_MS = 15_000L
        const val AUTHENTICATION_TIMEOUT_MS = 60_000L

        /** How long a forgotten pairing's one attempt to deliver its close lasts (section 4.6 item 6). */
        val REVOCATION_ATTEMPT_MS = rappRevocationAttemptBoundMs().toLong()

        /** How long this endpoint waits for the echo of its own close in a session (section 7.1 item 7). */
        val CLOSE_ECHO_WAIT_MS = rappQuitWithdrawalBoundMs().toLong()

        /** How often liveness is checked: a ping after 5 seconds of silence, the end after 30 (section 8.3). */
        const val LIVENESS_POLL_INTERVAL_MS = 1_000L

        val RANDOM_BYTE_COUNTS = rappRandomByteCounts()

        /** The value random material is overwritten with once used. */
        const val ERASED: Byte = 0
    }

    /**
     * The custodian card's authentication certificate, offered only when the
     * custodian named it by fingerprint in `card.status` on the same session
     * (section 8.4 item 2); null otherwise.
     */
    suspend fun readAuthenticationCertificate(timeoutMs: Long = CERTIFICATE_READ_TIMEOUT_MS): RappCertificate? =
        run(
            timeoutMs,
            begin = { bridge, operationId ->
                bridge.beginReadCertificate(
                    operationId = operationId.toWire(),
                    signatureCertificate = false,
                    localStartMs = RappClock.monotonicMs(),
                    expiresAfterMs = OPERATION_LIFETIME_MS,
                )
            },
            accept = { answer, status ->
                val certificate = (answer as? RappAnswer.Certificate)?.certificate
                when {
                    certificate == null -> Acceptance.Refused

                    status == null -> Acceptance.AwaitingCardStatus

                    status is RappCardStatus.Present &&
                        status.fingerprint ==
                        RappCertificateFingerprint.of(
                            certificate,
                        )
                    -> Acceptance.Accepted(certificate)

                    else -> Acceptance.Refused
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
                    RappClock.monotonicMs(),
                    OPERATION_LIFETIME_MS,
                )
            },
            accept = { answer, _ ->
                (answer as? RappAnswer.Signature)?.let { Acceptance.Accepted(it.signature) } ?: Acceptance.Refused
            },
        )

    /**
     * Dials once, within the revocation attempt's bound, to deliver a
     * forgotten pairing's close and waits for the custodian's echo (section
     * 4.6 item 6, section 7.1 item 7), then destroys the record, echo or
     * not. True when the echo arrived.
     */
    suspend fun deliverRevocationNotice(timeoutMs: Long = REVOCATION_ATTEMPT_MS): Boolean {
        val pairId = pairRecord.pairing().id
        val echoed =
            withTimeoutOrNull(timeoutMs) {
                Session(begin = null, accept = { _, _ -> Acceptance.Refused }, delivered = Unit).run()
            } != null
        RappPairRevocation.revoke(pairId, pairRecord, vault)
        return echoed
    }

    /** Whether an answer completes the run, given the card status received so far. */
    private sealed interface Acceptance<out T> {
        class Accepted<T>(
            val value: T,
        ) : Acceptance<T>

        data object AwaitingCardStatus : Acceptance<Nothing>

        data object Refused : Acceptance<Nothing>
    }

    private suspend fun <T> run(
        timeoutMs: Long,
        begin: (RappOperationBridge, RappOperationId) -> RappBridgeAction,
        accept: (RappAnswer, RappCardStatus?) -> Acceptance<T>,
    ): T? = withTimeoutOrNull(timeoutMs) { Session(begin, accept, delivered = null).run() }

    /** Where a dial stands between its preamble and the established session. */
    private enum class Phase {
        AWAITING_HANDSHAKE,
        AWAITING_READY,

        /** This device's close went out before the session was established; only its echo matters now. */
        AWAITING_CLOSE_ECHO,
        ESTABLISHED,
    }

    /**
     * One dial: routing preamble, `Noise_KK`, `session.ready` answered with
     * `session.hello`, then the one operation [begin] starts. A forgotten
     * pairing ends with [delivered] once the custodian echoed its close.
     */
    private inner class Session<T>(
        private val begin: ((RappOperationBridge, RappOperationId) -> RappBridgeAction)?,
        private val accept: (RappAnswer, RappCardStatus?) -> Acceptance<T>,
        private val delivered: T?,
    ) {
        private val result = CompletableDeferred<T?>()
        private val closed = AtomicBoolean(false)
        private val tornDown = AtomicBoolean(false)
        private val sendLock = Any()
        private val operationId = RappOperationId.random(SecureRandom())
        private var browser: StreamRelayBrowser? = null
        private var session: RappSessionBridge? = null
        private var phase = Phase.AWAITING_HANDSHAKE

        @Volatile
        private var operation: RappOperationBridge? = null
        private var livenessJob: Job? = null
        private var echoDeadlineJob: Job? = null
        private var cardStatus: RappCardStatus? = null
        private var answer: RappAnswer? = null

        /** Whether this device's own close went out and waits for the custodian's echo. */
        @Volatile
        private var awaitingEcho = false

        suspend fun run(): T? {
            val relay =
                StreamRelayBrowser(context, scope, StreamRendezvousName.MODE_SESSION, rank = ::rank) { event ->
                    try {
                        handle(event)
                    } catch (e: Exception) {
                        trace("session failed", e)
                        finish(null)
                    }
                }
            browser = relay
            relay.start()
            return try {
                result.await()
            } finally {
                finish(null)
                // A revocation attempt ends with its caller's bound, echo or not.
                if (begin == null) tearDown()
            }
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
                    finish(null)
                    tearDown()
                }
            }
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
                    outcome(RappBridgeOutcome.from(opened.receiveCloseEcho(data, RappClock.monotonicMs())))
                }

                Phase.ESTABLISHED -> {
                    operation?.let { bridge ->
                        outcome(act(bridge) { it.receiveFrame(data, RappClock.monotonicMs()) })
                    }
                }
            }
        }

        /** Completes `Noise_KK`; a forgotten pairing then sends its close as the session's only message. */
        private fun handshake(
            opened: RappSessionBridge,
            data: ByteArray,
        ) {
            opened.readHandshakeFrame(data)
            check(opened.handshakeComplete())
            opened.enterAuthentication()
            if (pairRecord.pairing().state is RappPairState.Forgotten) {
                phase = Phase.AWAITING_CLOSE_ECHO
                send(opened.deliverRevocationNotice())
                awaitEcho()
            } else {
                phase = Phase.AWAITING_READY
            }
        }

        /**
         * Verifies `session.ready` and answers with `session.hello` naming
         * this device (section 7.1 items 5 and 6), then starts the operation.
         */
        private fun ready(
            opened: RappSessionBridge,
            data: ByteArray,
        ) {
            val action = opened.receiveReady(data, RappClock.monotonicMs(), RappLocalName.of(context).text)
            when (val outcome = RappBridgeOutcome.from(action)) {
                is RappBridgeOutcome.Greeted -> {
                    send(outcome.hello)
                    onCustodianNamed(outcome.custodianName)
                    opened.enterEstablished()
                    val bridge =
                        RappOperationBridge.beginRequester(
                            opened,
                            OPERATION_LIFETIME_MS,
                            RappClock.monotonicMs(),
                        )
                    operation = bridge
                    phase = Phase.ESTABLISHED
                    startLiveness(bridge)
                    val start = begin
                    if (start == null) {
                        finish(null)
                    } else {
                        outcome(act(bridge) { start(it, operationId) })
                    }
                }

                is RappBridgeOutcome.Send -> {
                    send(outcome.frame)
                    if (outcome.close is RappSentClose.Own) phase = Phase.AWAITING_CLOSE_ECHO
                    outcome(outcome)
                }

                else -> {
                    outcome(outcome)
                }
            }
        }

        private fun outcome(outcome: RappBridgeOutcome?) {
            when (outcome) {
                null -> {
                    finish(null)
                    tearDown()
                }

                is RappBridgeOutcome.Send -> {
                    when (val close = outcome.close) {
                        null -> {}

                        is RappSentClose.Echo -> {
                            ended(close.end)
                            finish(null)
                            tearDown()
                        }

                        is RappSentClose.Own -> {
                            ended(close.end)
                            awaitEcho()
                            finish(null)
                        }
                    }
                }

                is RappBridgeOutcome.CloseAcknowledged -> {
                    ended(outcome.end)
                    finish(if (outcome.reason == RappCloseReason.PAIRING_REVOKED) delivered else null)
                    tearDown()
                }

                is RappBridgeOutcome.Completed -> {
                    if (outcome.operationId == operationId) {
                        answer = outcome.answer
                        decide()
                    }
                }

                is RappBridgeOutcome.CardStatus -> {
                    cardStatus = outcome.status
                    decide()
                }

                is RappBridgeOutcome.Terminal -> {
                    trace("operation ended: ${outcome.reason}", null)
                    finish(null)
                }

                is RappBridgeOutcome.Closed -> {
                    ended(outcome.end)
                    finish(null)
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
         * The session ended as [end] says (section 4.5 item 6). Only a
         * revocation changes what this device stores: the record is
         * destroyed and the identity withdrawn. A withdrawal, a violation
         * or a loss keeps the pairing, and with one operation per session
         * nothing is dialed until a consumer asks again. A revocation
         * attempt destroys the record itself once it ends.
         */
        private fun ended(end: RappRequesterSessionEnd?) {
            if (end != RappRequesterSessionEnd.REVOKED || begin == null) return
            RappPairRevocation.revoke(pairRecord.pairing().id, pairRecord, vault)
            onPairingRevoked()
        }

        private fun decide() {
            val received = answer ?: return
            when (val acceptance = accept(received, cardStatus)) {
                is Acceptance.Accepted -> {
                    finish(acceptance.value)
                }

                Acceptance.AwaitingCardStatus -> {}

                Acceptance.Refused -> {
                    finish(null)
                }
            }
        }

        private fun startLiveness(bridge: RappOperationBridge) {
            livenessJob =
                scope.launch(Dispatchers.IO) {
                    val random = SecureRandom()
                    while (isActive && operation === bridge) {
                        delay(LIVENESS_POLL_INTERVAL_MS)
                        val challenge = ByteArray(RANDOM_BYTE_COUNTS.livenessChallenge.toInt()).also(random::nextBytes)
                        try {
                            outcome(act(bridge) { it.pollLiveness(RappClock.monotonicMs(), challenge) })
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
         * most [CLOSE_ECHO_WAIT_MS] (section 7.1 item 7); a forgotten
         * pairing's attempt waits as long as the caller's bound allows.
         */
        private fun awaitEcho() {
            if (awaitingEcho) return
            awaitingEcho = true
            if (phase == Phase.AWAITING_CLOSE_ECHO && begin == null) return
            echoDeadlineJob =
                scope.launch {
                    delay(CLOSE_ECHO_WAIT_MS)
                    tearDown()
                }
        }

        /**
         * Ends the run with [value]. A session that is still open is closed
         * with reason `normal`, and its link stays until the custodian's echo
         * arrives or [CLOSE_ECHO_WAIT_MS] passes.
         */
        private fun finish(value: T?) {
            result.complete(value)
            if (!closed.compareAndSet(false, true)) return
            livenessJob?.cancel()
            livenessJob = null
            if (awaitingEcho) return
            val bridge = operation
            val own =
                bridge?.let { open ->
                    act(open) { it.closeWithReason(RappCloseReason.NORMAL) }
                } as? RappBridgeOutcome.Send
            if (own?.close is RappSentClose.Own) awaitEcho() else tearDown()
        }

        /** Closes the bridges and the link once nothing more is awaited on it. */
        private fun tearDown() {
            result.complete(null)
            if (!tornDown.compareAndSet(false, true)) return
            closed.set(true)
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

        private fun trace(
            message: String,
            error: Exception?,
        ) {
            if (BuildConfig.DEBUG) {
                android.util.Log.w(TRACE_TAG, message, error)
            }
        }
    }
}
