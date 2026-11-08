@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappNextCandidate
import uniffi.refineid_rapp.RappNextEndpoint
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappPairingCandidates
import uniffi.refineid_rapp.RappPeerHello
import uniffi.refineid_rapp.rappPairingBusyRetryAfterMs
import uniffi.refineid_rapp.rappPairingPreamble
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappStreamProfileName
import java.util.concurrent.ConcurrentHashMap

/**
 * The phones in pairing mode one search tries, by the service instance
 * each was found under and the address it resolved to.
 */
internal interface RappPairingEndpoints : AutoCloseable {
    /** Reports every phone found in pairing mode until [close]. */
    fun start(onFound: (instance: String, host: String, port: Int) -> Unit)
}

/** The phones in pairing mode on the local network. */
internal class RappNetworkPairingEndpoints(
    context: Context,
    scope: CoroutineScope,
) : RappPairingEndpoints {
    private val discovery =
        RappRequesterDiscovery(context, scope) { event ->
            if (event is RappRequesterDiscovery.Event.Resolved &&
                StreamRendezvousName.matches(event.attributes, StreamRendezvousName.MODE_PAIRING)
            ) {
                found?.invoke(event.instance, event.host, event.port)
            }
        }
    private var found: ((String, String, Int) -> Unit)? = null

    override fun start(onFound: (instance: String, host: String, port: Int) -> Unit) {
        found = onFound
        discovery.start()
    }

    override fun close() {
        found = null
        discovery.close()
    }
}

/**
 * Tries one typed pairing code against the custodians in pairing mode
 * (RAPP v26.11.2 section 4.2, "Trying Each Custodian in Pairing Mode"):
 * each in turn, one guess per custodian, at most eight connections, the
 * core's ledger ([RappPairingCandidates]) deciding who is next and what a
 * closed connection means.
 *
 * A custodian that proves it holds the code is paired with: no other
 * custodian is tried, and a later failure ends the search. The code is
 * reported not accepted only once every custodian tried refused it, and
 * none in pairing mode is reported only when none was tried and none
 * answered busy; neither report names a custodian. The search is
 * cancelled through its coroutine.
 */
internal class RappPairingSearch(
    private val context: Context,
    private val scope: CoroutineScope,
    private val vault: RappPairVault,
    private val endpoints: RappPairingEndpoints,
    private val localName: () -> RappDisplayName = { RappLocalName.of(context) },
    private val monotonicMs: () -> ULong = RappClock::monotonicMs,
    private val initialDiscoveryMs: Long = INITIAL_DISCOVERY_MS,
) {
    /** What the search ends with. */
    sealed interface Outcome {
        /** The pairing completed; [record] is confirmed and stored. */
        data class Paired(
            val record: RappPairRecord,
            val peer: RappPeerHello,
        ) : Outcome

        /** Every custodian tried refused the code. */
        data object NotAccepted : Outcome

        /**
         * No custodian in pairing mode was found: none was found, or one
         * that opened a connection served no offer.
         */
        data object NoneFound : Outcome

        /**
         * A custodian was found but none could be reached: every connection
         * failed to open, and none opened.
         */
        data object Unreachable : Outcome

        /** The code was accepted but the ceremony did not complete. */
        data object CeremonyEnded : Outcome

        /** The local network is closed to the app. */
        data object LocalNetworkClosed : Outcome
    }

    private data class Endpoint(
        val host: String,
        val port: Int,
    )

    /** What one connection to a custodian ends with. */
    private sealed interface Attempt {
        data class Paired(
            val record: RappPairRecord,
            val peer: RappPeerHello,
        ) : Attempt

        /** The custodian answered busy, asking for a wait of [retryAfterMs]. */
        data class Busy(
            val retryAfterMs: ULong,
        ) : Attempt

        /** The custodian refused the code, or the open connection closed before it took it. */
        data object Refused : Attempt

        /** The connection to the custodian could not be opened. */
        data object NotOpened : Attempt

        /** The code was accepted but the ceremony did not complete. */
        data object CeremonyEnded : Attempt
    }

    suspend fun search(code: String): Outcome {
        if (!LocalNetworkPermission.isGranted(context)) return Outcome.LocalNetworkClosed
        val ledger = RappPairingCandidates()
        val table = ConcurrentHashMap<String, Endpoint>()
        val foundSignal = Channel<Unit>(Channel.UNLIMITED)
        endpoints.start { instance, host, port ->
            // An instance can resolve to more than one address, and to a new
            // one when its record changes; each resolved address is its own
            // endpoint (section 4.2 item 1). The offer_id still allows one
            // guess per phone (item 2), and the connection limit bounds the
            // openings (item 5).
            val endpoint = endpointKey(instance, host, port)
            table.putIfAbsent(endpoint, Endpoint(host, port))
            try {
                ledger.found(endpoint)
            } catch (_: RappBindingException) {
            }
            foundSignal.trySend(Unit)
        }
        val reach = Reach()
        try {
            val graceUntilMs = monotonicMs().toLong() + initialDiscoveryMs
            while (true) {
                scope.ensureActive()
                when (val next = ledger.nextEndpoint(monotonicMs())) {
                    is RappNextEndpoint.Open -> {
                        val attempt = tryEndpoint(table[next.endpoint], code, ledger)
                        reach.record(attempt)
                        when (attempt) {
                            is Attempt.Paired -> {
                                return Outcome.Paired(attempt.record, attempt.peer)
                            }

                            is Attempt.Busy -> {
                                afterClosed(
                                    ledger.busy(attempt.retryAfterMs, monotonicMs()),
                                    foundSignal,
                                    graceUntilMs,
                                    reach,
                                )?.let { return it }
                            }

                            Attempt.Refused, Attempt.NotOpened -> {
                                afterClosed(ledger.closed(), foundSignal, graceUntilMs, reach)?.let { return it }
                            }

                            Attempt.CeremonyEnded -> {
                                return Outcome.CeremonyEnded
                            }
                        }
                    }

                    is RappNextEndpoint.NotBefore -> {
                        val waitMs =
                            (next.monotonicMs.toLong() - monotonicMs().toLong()).coerceAtLeast(0L)
                        withTimeoutOrNull(waitMs) { foundSignal.receive() }
                    }

                    is RappNextEndpoint.Exhausted -> {
                        if (!awaitFound(foundSignal, graceUntilMs)) return reach.noneTried()
                    }
                }
            }
        } finally {
            endpoints.close()
        }
    }

    /**
     * Whether the connections of one search reached any custodian: what a
     * search that tried none ends with, as RefineID-Apple tells it. A
     * custodian that opened a connection and served no offer is not in
     * pairing mode, while one that could not be reached says nothing of it.
     */
    private class Reach {
        private var anyOpened = false
        private var anyNotOpened = false

        fun record(attempt: Attempt) {
            if (attempt == Attempt.NotOpened) anyNotOpened = true else anyOpened = true
        }

        fun noneTried(): Outcome = if (anyNotOpened && !anyOpened) Outcome.Unreachable else Outcome.NoneFound
    }

    /**
     * What the search ends with after [candidate] closed an attempt, or
     * null to go on: a refused code after every custodian tried, or, when
     * none was tried before the discovery grace ends, why ([reach]).
     */
    private suspend fun afterClosed(
        candidate: RappNextCandidate,
        foundSignal: Channel<Unit>,
        graceUntilMs: Long,
        reach: Reach,
    ): Outcome? =
        when (candidate) {
            RappNextCandidate.TRY, RappNextCandidate.DEFERRED -> {
                null
            }

            RappNextCandidate.NOT_ACCEPTED -> {
                Outcome.NotAccepted
            }

            RappNextCandidate.NONE_TRIED -> {
                if (!awaitFound(foundSignal, graceUntilMs)) reach.noneTried() else null
            }
        }

    /**
     * Whether another phone is found before the discovery grace ends: the
     * search that tried nothing waits for one, or reports that none was
     * found.
     */
    private suspend fun awaitFound(
        foundSignal: Channel<Unit>,
        graceUntilMs: Long,
    ): Boolean {
        val remainingMs = (graceUntilMs - monotonicMs().toLong()).coerceAtLeast(0L)
        return withTimeoutOrNull(remainingMs) { foundSignal.receive() } != null
    }

    /**
     * Tries [code] against one custodian: the pairing preamble, the offer
     * bootstrap, CPace, Noise, and the confirmation and storage exchange.
     */
    private suspend fun tryEndpoint(
        endpoint: Endpoint?,
        code: String,
        ledger: RappPairingCandidates,
    ): Attempt {
        if (endpoint == null) return Attempt.NotOpened
        val link = Link()
        val browser =
            StreamRelayBrowser(context, scope, StreamRendezvousName.MODE_PAIRING, onEvent = link::handle)
        var bridge: RappPairingBridge? = null
        var ceremony: RappRequesterPairingCeremony? = null
        var paired = false
        try {
            browser.dialDirect(endpoint.host, endpoint.port)
            if (!link.awaitConnected(CONNECT_TIMEOUT_MS)) return Attempt.NotOpened
            browser.send(rappPairingPreamble(rappStreamProfileName()))
            val bootstrap = link.awaitFrame(BOOTSTRAP_TIMEOUT_MS) ?: return Attempt.Refused
            val offer =
                try {
                    RappPairingBridge.fromBootstrap(bootstrap, rappStreamProfileName(), monotonicMs())
                } catch (_: RappBindingException.CustodianBusy) {
                    return busy(bootstrap)
                } catch (_: RappBindingException) {
                    return Attempt.Refused
                }
            bridge = offer
            if (!ledger.beginTry(offer)) {
                // The same custodian, found on another transport: it gets no second guess.
                return Attempt.Refused
            }
            val candidateId =
                offer.offerCandidates().first { it.profile == rappStreamProfileName() }.candidateId
            val attempt =
                RappRequesterPairingCeremony(
                    bridge = offer,
                    pairingCode = code,
                    candidateId = candidateId,
                    displayName = localName(),
                    platform = RappLocalName.OPERATING_SYSTEM,
                    monotonicMs = monotonicMs,
                    wallMs = RappClock::wallMs,
                    random64 = { randomBytes(RANDOM_BYTE_COUNTS.cpaceRandom.toInt()) },
                    persistUnconfirmed = { record -> record.persistDeviceOnly(vault) },
                )
            ceremony = attempt
            browser.send(attempt.start())
            val result = runCeremony(browser, link, ledger, attempt)
            paired = result is Attempt.Paired
            return result
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return Attempt.Refused
        } finally {
            browser.close()
            try {
                bridge?.cancelPairing()
            } catch (_: Exception) {
            }
            if (!paired) ceremony?.let(::revokeUnconfirmed)
        }
    }

    private suspend fun runCeremony(
        browser: StreamRelayBrowser,
        link: Link,
        ledger: RappPairingCandidates,
        ceremony: RappRequesterPairingCeremony,
    ): Attempt {
        val stepTwo = link.awaitFrame(CPACE_STEP_TWO_TIMEOUT_MS) ?: return Attempt.Refused
        if (isPairingBusy(stepTwo)) return busy(stepTwo)
        try {
            sendAll(browser, ceremony.receive(stepTwo))
            ledger.accepted()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return Attempt.Refused
        }
        return try {
            var outcome = receiveNext(browser, link, ceremony, HANDSHAKE_TIMEOUT_MS)
            while (outcome is RappRequesterPairingCeremony.Outcome.Send) {
                outcome = receiveNext(browser, link, ceremony, CONFIRMATION_TIMEOUT_MS)
            }
            val paired = outcome as RappRequesterPairingCeremony.Outcome.Paired
            paired.record.replaceDeviceOnly(vault)
            Attempt.Paired(paired.record, paired.peer)
        } catch (_: CeremonyFailedException) {
            revokeUnconfirmed(ceremony)
            Attempt.CeremonyEnded
        }
    }

    private suspend fun receiveNext(
        browser: StreamRelayBrowser,
        link: Link,
        ceremony: RappRequesterPairingCeremony,
        timeoutMs: Long,
    ): RappRequesterPairingCeremony.Outcome {
        val frame = link.awaitFrame(timeoutMs) ?: throw CeremonyFailedException()
        try {
            val outcome = ceremony.receive(frame)
            sendAll(browser, outcome)
            return outcome
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            throw CeremonyFailedException()
        }
    }

    private fun sendAll(
        browser: StreamRelayBrowser,
        outcome: RappRequesterPairingCeremony.Outcome,
    ) {
        if (outcome is RappRequesterPairingCeremony.Outcome.Send) {
            outcome.frames.forEach(browser::send)
        }
    }

    /** Destroys the record a ceremony stored but the custodian never confirmed (section 4.3 item 4). */
    private fun revokeUnconfirmed(ceremony: RappRequesterPairingCeremony) {
        val stored = ceremony.storedRecord ?: return
        try {
            RappPairRevocation.revoke(stored.pairing().id, stored, vault)
        } catch (_: Exception) {
        }
    }

    private fun busy(frame: ByteArray): Attempt =
        try {
            Attempt.Busy(rappPairingBusyRetryAfterMs(frame))
        } catch (_: RappBindingException) {
            Attempt.Refused
        }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also { java.security.SecureRandom().nextBytes(it) }

    /**
     * One connection's events: the connect and every frame in order. A
     * disconnect or an error ends the attempt; frames queued before it are
     * still read.
     */
    private class Link {
        private val connected = CompletableDeferred<Boolean>()
        private val frames = Channel<ByteArray>(Channel.UNLIMITED)

        fun handle(event: StreamRelayEvent) {
            when (event) {
                is StreamRelayEvent.Connected -> {
                    connected.complete(true)
                }

                is StreamRelayEvent.Frame -> {
                    frames.trySend(event.data)
                }

                is StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                    connected.complete(false)
                    frames.close()
                }
            }
        }

        suspend fun awaitConnected(timeoutMs: Long): Boolean =
            withTimeoutOrNull(timeoutMs) { connected.await() } == true

        suspend fun awaitFrame(timeoutMs: Long): ByteArray? =
            try {
                withTimeoutOrNull(timeoutMs) { frames.receive() }
            } catch (_: ClosedReceiveChannelException) {
                null
            }
    }

    /** The ceremony failed after the code was accepted. */
    private class CeremonyFailedException : Exception()

    internal companion object {
        private val RANDOM_BYTE_COUNTS = rappRandomByteCounts()

        /** Separates the parts of an endpoint's ledger name; no host or port holds it. */
        private const val ENDPOINT_KEY_SEPARATOR = "\n"

        /**
         * The ledger's name for the endpoint [instance] resolved to at
         * [host] and [port]. It names nothing outside this search.
         */
        private fun endpointKey(
            instance: String,
            host: String,
            port: Int,
        ): String = listOf(instance, host, port.toString()).joinToString(ENDPOINT_KEY_SEPARATOR)

        /**
         * How long a search waits for a phone in pairing mode before
         * reporting none found or none reachable: RefineID-Apple's discovery
         * window, so both platforms give up at the same time.
         */
        const val INITIAL_DISCOVERY_MS = 15_000L

        /** How long one pairing connection may take to connect. */
        const val CONNECT_TIMEOUT_MS = 10_000L

        /** How long the offer bootstrap may take after the pairing preamble. */
        const val BOOTSTRAP_TIMEOUT_MS = 10_000L

        /** How long CPace step 2 may take after step 1 (section 3.3 item 3). */
        const val CPACE_STEP_TWO_TIMEOUT_MS = 5_000L

        /** How long each Noise and confirmation frame may take. */
        const val HANDSHAKE_TIMEOUT_MS = 10_000L
        const val CONFIRMATION_TIMEOUT_MS = 10_000L
    }
}
