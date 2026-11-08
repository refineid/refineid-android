@file:Suppress("TooGenericExceptionCaught", "SwallowedException", "TooManyFunctions")

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.BuildConfig
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.CertificateHolderName
import fi.refineid.android.core.PersonCardDetails
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappRequesterSessionEnd
import uniffi.refineid_rapp.RappSignatureAlgorithm

/**
 * Manages the client-side lifecycle and state for a remote ID card
 * accessed through a paired phone (RAPP v26.11.2 sections 4.5-4.7, 8.3,
 * 8.4; discovery hierarchy section 5.2).
 *
 * Remote use is the pairing: the holder's switch, off until turned on,
 * holds at most one pairing. With one, discovery runs and the view of the
 * custodian ([RappViewOfCustodian]) dials on appearance, on a consumer's
 * ask, or within the redial window after a loss, holding one session.
 * Without one, the pairing code entry is offered; pairing another phone
 * replaces the pairing. Turning remote use off forgets the pairing into
 * the revocation backlog (section 4.6 item 6): a forgotten pairing dials
 * only when its custodian appears, sends the `pairing_revoked` close as
 * the session's first message, and is destroyed on the echo.
 *
 * The custodian is presented only through its card: the offered identity
 * while a session confirms it, nothing otherwise, never a reason. The one
 * line naming the custodian is the notice that the phone forgot this
 * computer.
 *
 * All driver state moves on one thread; sessions, searches and timers run
 * beside it and report back to it.
 */
internal class RemoteCardModel(
    private val context: Context,
    private val scope: CoroutineScope,
    private val vault: RappPairVault,
    private val catalog: RappPairCatalog,
    private val settings: RappSettings = RappSettings(context),
    private val searchEndpoints: () -> RappPairingEndpoints = { RappNetworkPairingEndpoints(context, scope) },
    private val directDialEndpoint: RappDialCandidates.Endpoint? = null,
    private val openDiscovery: (CoroutineScope, (RappRequesterDiscovery.Event) -> Unit) -> AutoCloseable =
        { discoveryScope, onEvent ->
            RappRequesterDiscovery(context, discoveryScope, onEvent).also { it.start() }
        },
    private val localName: () -> RappDisplayName = { RappLocalName.of(context) },
) {
    /** Where the pairing code entry stands. */
    sealed interface SearchPhase {
        /** The code entry is offered. */
        data object Entry : SearchPhase

        /** A typed code is being tried. */
        data object Searching : SearchPhase

        /** The search ended without a pairing; [outcome] says how. */
        data class Failed(
            val outcome: RappPairingSearch.Outcome,
        ) : SearchPhase
    }

    private val _holderName = MutableStateFlow<String?>(null)
    val holderName: StateFlow<String?> = _holderName.asStateFlow()

    private val _cardDetails = MutableStateFlow<PersonCardDetails?>(null)
    val cardDetails: StateFlow<PersonCardDetails?> = _cardDetails.asStateFlow()

    private val _certificateDer = MutableStateFlow<ByteArray?>(null)
    val certificateDer: StateFlow<ByteArray?> = _certificateDer.asStateFlow()

    /** The offered certificate's DER, or null while no remote card is offered. */
    val offeredCertificateDer: ByteArray?
        get() = _certificateDer.value

    private val _remoteUseEnabled = MutableStateFlow(settings.isRequesterRemoteUseEnabled)
    val remoteUseEnabled: StateFlow<Boolean> = _remoteUseEnabled.asStateFlow()

    private val _searchPhase = MutableStateFlow<SearchPhase>(SearchPhase.Entry)
    val searchPhase: StateFlow<SearchPhase> = _searchPhase.asStateFlow()

    /** The phone that forgot this computer, by name, until the next pairing or the switch. */
    private val _phoneThatForgot = MutableStateFlow<String?>(null)
    val phoneThatForgot: StateFlow<String?> = _phoneThatForgot.asStateFlow()

    val authenticationCardService: AuthenticationCardService by lazy {
        RemoteAuthenticationCardService(scope, this)
    }

    private companion object {
        const val TRACE_TAG = "REMOTE_CARD_MODEL"
        const val CERTIFICATE_READ_TIMEOUT_MS = 15_000L

        /** How long one dial browses, connects and shakes hands before it counts as failed. */
        const val DIAL_ATTEMPT_MS = 30_000L

        const val MILLIS_PER_SECOND = 1_000L
    }

    /** The driver moves here, one transition at a time. */
    private val driverContext = Dispatchers.Default.limitedParallelism(1)

    private fun launchDriver(block: suspend () -> Unit) {
        scope.launch(driverContext) { block() }
    }

    private val identity = RappIdentityOffer()

    /** The view's state for waiting consumers; null while no discovery runs. */
    private val viewStates = MutableStateFlow<RappViewOfCustodian.State?>(null)

    private var view: RappViewOfCustodian? = null
    private var discovery: AutoCloseable? = null
    private var sightings = RappRequesterSightings()
    private var pairRecord: RappPairRecord? = null
    private var heldPeer: PairedPeer? = null
    private var associatedInstance: String? = null

    @Volatile
    private var sessionClient: RappRequesterClient? = null
    private var dialJob: Job? = null
    private var redialJob: Job? = null
    private var windowJob: Job? = null
    private var searchJob: Job? = null

    /** The peer's name as last held, for the notice after its revoking close. */
    private var lastPeerName: String? = null

    /** The card status the session last reported, by fingerprint when present. */
    private var lastStatusFingerprint: RappCertificateFingerprint? = null

    /** The forgotten pairings with a revocation dial under way, by catalogued id. */
    private val attemptingRevocation = HashSet<String>()

    /** The pairing whose revoking close the open session carries, if any, by catalogued id. */
    private var inSessionRevocation: String? = null

    /** Discovery watching for the custodians of forgotten pairings, while any wait. */
    private var backlogDiscovery: AutoCloseable? = null

    /** Appearances seen per forgotten pairing, by catalogued id. */
    private val backlogSightings = HashMap<String, RappRequesterSightings>()

    /** The instance each forgotten pairing's discovery is associated with, by catalogued id. */
    private val backlogAssociated = HashMap<String, String?>()

    init {
        scope.launch {
            while (true) {
                delay(RappIdleExpiry.SWEEP_INTERVAL_MS)
                launchDriver { sweepExpiry() }
            }
        }
        refresh()
    }

    /**
     * The holder turned remote use on or off. The switch moves only here,
     * keeps its position, and off forgets the held pairing into the
     * revocation backlog (section 4.6 item 6).
     */
    fun setRemoteUseEnabled(enabled: Boolean) {
        settings.isRequesterRemoteUseEnabled = enabled
        _remoteUseEnabled.value = enabled
        launchDriver {
            if (enabled) remoteUseOn() else remoteUseOff()
        }
    }

    /** Forgets the pairing and turns remote use off, as the identity reset does. */
    fun forget() {
        setRemoteUseEnabled(false)
    }

    /**
     * Reconciles with the switch and the pairing: a launch or a return to
     * the foreground restores discovery, the revocation backlog is swept
     * and watched, and the offer is rechecked. A search under way is left
     * alone.
     */
    fun refresh() {
        launchDriver {
            updateOfferedFlows()
            sweepBacklog()
            ensureBacklogDiscovery()
            if (searchJob?.isActive == true) return@launchDriver
            if (!_remoteUseEnabled.value || view != null) return@launchDriver
            val peer = newestActiveRequesterPeer()
            if (peer == null) {
                _searchPhase.value = SearchPhase.Entry
            } else {
                startDiscovery(peer)
            }
        }
    }

    /** Tries the typed pairing code; the entry offers nothing while a remote card is presented. */
    fun submitPairingCode(code: String) {
        launchDriver {
            if (!_remoteUseEnabled.value || searchJob?.isActive == true) return@launchDriver
            if (identity.offered(monotonicMs()) != null) return@launchDriver
            val filtered = RappPairingCode.filterEntry(code)
            if (!RappPairingCode.isCompleteEntry(filtered)) return@launchDriver
            startSearch(filtered)
        }
    }

    /**
     * Ends a search under way, restoring the held pairing's discovery when
     * [restoreDiscovery]; leaving the pairing screen does, turning remote
     * use off does not.
     */
    fun cancelSearch(restoreDiscovery: Boolean = true) {
        launchDriver {
            searchJob?.cancel()
            searchJob = null
            if (_searchPhase.value == SearchPhase.Searching) {
                _searchPhase.value = SearchPhase.Entry
            }
            if (restoreDiscovery && _remoteUseEnabled.value && view == null) {
                newestActiveRequesterPeer()?.let(::startDiscovery)
            }
        }
    }

    /** Leaves a failed search for the code entry. */
    fun dismissFailure() {
        _searchPhase.value = SearchPhase.Entry
    }

    /**
     * The offered authentication certificate, dialing for it when no
     * session is open, within [timeoutMs]; null when no remote card is
     * available.
     */
    suspend fun readAuthenticationCertificate(timeoutMs: Long = CERTIFICATE_READ_TIMEOUT_MS): RappCertificate? {
        val deadlineMs = monotonicMs() + timeoutMs
        val session = awaitSession(timeoutMs) ?: return null
        return session.readAuthenticationCertificate((deadlineMs - monotonicMs()).coerceAtLeast(0L))
    }

    /** A signature over [digest], dialing for it when no session is open; null when refused. */
    suspend fun browserAuthenticate(
        origin: String,
        keyProfile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digest: ByteArray,
        timeoutMs: Long,
    ): ByteArray? {
        val deadlineMs = monotonicMs() + timeoutMs
        val session = awaitSession(timeoutMs) ?: return null
        return session.browserAuthenticate(
            origin,
            keyProfile,
            algorithm,
            digest,
            (deadlineMs - monotonicMs()).coerceAtLeast(0L),
        )
    }

    /**
     * The open session, dialing for it when the view allows, within
     * [timeoutMs]; null when the custodian is withdrawn or the pairing is
     * gone.
     */
    private suspend fun awaitSession(timeoutMs: Long): RappRequesterClient? {
        withContext(driverContext) {
            val state = view?.state
            if (state == RappViewOfCustodian.State.IDLE || state == RappViewOfCustodian.State.CONNECTING) {
                feed(RappViewOfCustodian.Event.ConsumerRequest)
            }
        }
        return withTimeoutOrNull(timeoutMs) {
            viewStates.first {
                it == null ||
                    (it != RappViewOfCustodian.State.IDLE && it != RappViewOfCustodian.State.CONNECTING)
            }
            sessionClient?.takeIf { it.isOpen }
        }
    }

    private val sessionListener =
        object : RappRequesterClient.Listener {
            override fun onCardStatus(status: RappCardStatus) {
                launchDriver { handleCardStatus(status) }
            }

            override fun onSessionEnd(end: RappRequesterSessionEnd) {
                launchDriver { handleSessionEnd(end) }
            }

            override fun onCustodianNamed(name: RappDisplayName) {
                launchDriver {
                    val peer = heldPeer ?: return@launchDriver
                    catalog.updateDisplayName(peer.pairIdHex, name.text)
                    heldPeer = peer.copy(displayName = name.text)
                    lastPeerName = name.text
                }
            }
        }

    private fun remoteUseOn() {
        _phoneThatForgot.value = null
        cancelSearchJob()
        val peer = newestActiveRequesterPeer()
        if (peer == null) {
            _searchPhase.value = SearchPhase.Entry
        } else {
            startDiscovery(peer)
        }
    }

    private fun remoteUseOff() {
        cancelSearchJob()
        _searchPhase.value = SearchPhase.Entry
        _phoneThatForgot.value = null
        lastPeerName = null
        forgetHeldPairings()
        stopDiscovery(RappCloseReason.PAIRING_REVOKED)
        ensureBacklogDiscovery()
    }

    private fun cancelSearchJob() {
        searchJob?.cancel()
        searchJob = null
    }

    private fun startDiscovery(peer: PairedPeer) {
        stopDiscovery(null)
        val record =
            loadRequesterRecord(peer) ?: run {
                catalog.removePair(peer.pairIdHex)
                _searchPhase.value = SearchPhase.Entry
                return
            }
        pairRecord = record
        heldPeer = peer
        lastPeerName = peer.displayName
        lastStatusFingerprint = null
        sightings = RappRequesterSightings()
        associatedInstance = null
        view = RappViewOfCustodian()
        viewStates.value = RappViewOfCustodian.State.IDLE
        discovery =
            try {
                openDiscovery(scope) { event -> launchDriver { handleDiscovery(event) } }
            } catch (e: Exception) {
                trace("discovery failed to start", e)
                pairRecord = null
                heldPeer = null
                view = null
                viewStates.value = null
                record.close()
                null
            }
    }

    /**
     * Ends the view with the pairing leaving: the identity is withdrawn, a
     * dial is dropped, and the open session, if any, closes with
     * [localClose]; null shuts it without a close.
     */
    private fun stopDiscovery(localClose: RappCloseReason?) {
        discovery?.close()
        discovery = null
        redialJob?.cancel()
        redialJob = null
        windowJob?.cancel()
        windowJob = null
        view?.let { feed(RappViewOfCustodian.Event.PairingLeft, localClose) }
        view = null
        viewStates.value = null
        pairRecord?.close()
        pairRecord = null
        heldPeer = null
        lastStatusFingerprint = null
    }

    private fun handleDiscovery(event: RappRequesterDiscovery.Event) {
        val record = pairRecord ?: return
        if (view == null) return
        when (event) {
            is RappRequesterDiscovery.Event.Resolved -> {
                when (
                    val sighting =
                        sightings.resolved(
                            event.instance,
                            event.attributes,
                            associatedInstance,
                            record,
                            System.currentTimeMillis() / MILLIS_PER_SECOND,
                        )
                ) {
                    is RappSighting.Appeared -> {
                        // The association follows appearances; a hint match
                        // outranks an unhinted record.
                        if (sighting.hintMatched || associatedInstance == null) {
                            associatedInstance = event.instance
                        }
                        feed(RappViewOfCustodian.Event.RecordAppeared)
                    }

                    RappSighting.WithdrawnMatched -> {
                        feed(RappViewOfCustodian.Event.WithdrawnRecordMatched)
                    }

                    null -> {}
                }
            }

            is RappRequesterDiscovery.Event.Lost -> {
                sightings.lost(event.instance)
            }
        }
    }

    /** Feeds [event] to the view and carries out its actions. */
    private fun feed(
        event: RappViewOfCustodian.Event,
        localClose: RappCloseReason? = null,
    ) {
        val actions = view?.event(event, monotonicMs()) ?: return
        for (action in actions) {
            carryOut(action, localClose)
        }
        viewStates.value = view?.state
        reconcileWindowTimer()
    }

    private fun carryOut(
        action: RappViewOfCustodian.Action,
        localClose: RappCloseReason?,
    ) {
        when (action) {
            RappViewOfCustodian.Action.OpenDial -> {
                dial()
            }

            RappViewOfCustodian.Action.AbortDial -> {
                abortDial()
            }

            is RappViewOfCustodian.Action.ScheduleRedial -> {
                scheduleRedial(action.delayMs)
            }

            RappViewOfCustodian.Action.EndRedialWindow -> {
                redialJob?.cancel()
                redialJob = null
                windowJob?.cancel()
                windowJob = null
            }

            RappViewOfCustodian.Action.StartOfferGrace -> {
                startOfferGrace()
            }

            RappViewOfCustodian.Action.WithdrawIdentity -> {
                identity.withdraw()
                updateOfferedFlows()
            }

            RappViewOfCustodian.Action.ShowPeerForgot -> {
                _phoneThatForgot.value = lastPeerName
            }

            RappViewOfCustodian.Action.RefuseConsumer -> {
                // Waiting consumers wake on the withdrawn state.
            }

            RappViewOfCustodian.Action.RequestLocalClose -> {
                closeSession(localClose)
            }
        }
    }

    /** Opens one dial, unless one runs. */
    private fun dial() {
        if (dialJob?.isActive == true) return
        val record = pairRecord ?: return
        if (heldPeer == null) return
        val client =
            RappRequesterClient(context, scope, record, vault, sessionListener, localName = localName)
        sessionClient = client
        dialJob =
            scope.launch(Dispatchers.IO) {
                val outcome =
                    try {
                        client.open(DIAL_ATTEMPT_MS, directDialEndpoint)
                    } catch (cancelled: CancellationException) {
                        client.shutdown()
                        throw cancelled
                    } catch (e: Exception) {
                        trace("dial failed", e)
                        client.shutdown()
                        RappRequesterClient.OpenOutcome.Failed(null)
                    }
                launchDriver {
                    dialJob = null
                    when (outcome) {
                        RappRequesterClient.OpenOutcome.Established -> {
                            recordSessionTime(record)
                            feed(RappViewOfCustodian.Event.DialSucceeded)
                        }

                        is RappRequesterClient.OpenOutcome.Failed -> {
                            if (sessionClient === client) sessionClient = null
                            client.shutdown()
                            // A close before session.ready is treated as
                            // section 4.5 item 6 says; only a loss redials.
                            when (outcome.end) {
                                RappRequesterSessionEnd.REVOKED -> {
                                    revokeHeldPairing()
                                    feed(RappViewOfCustodian.Event.PairingRevoked)
                                    stopDiscovery(null)
                                    if (searchJob?.isActive != true) {
                                        _searchPhase.value = SearchPhase.Entry
                                    }
                                }

                                RappRequesterSessionEnd.WITHDRAWN -> {
                                    feed(RappViewOfCustodian.Event.Withdrawn)
                                }

                                RappRequesterSessionEnd.VIOLATION -> {
                                    feed(RappViewOfCustodian.Event.ProtocolViolation)
                                }

                                else -> {
                                    feed(RappViewOfCustodian.Event.DialFailed)
                                }
                            }
                        }
                    }
                }
            }
    }

    private fun abortDial() {
        dialJob?.cancel()
        dialJob = null
        sessionClient?.shutdown()
        sessionClient = null
    }

    private fun scheduleRedial(delayMs: Long) {
        redialJob?.cancel()
        redialJob =
            scope.launch {
                delay(delayMs)
                launchDriver { feed(RappViewOfCustodian.Event.RedialDue) }
            }
    }

    private fun reconcileWindowTimer() {
        val untilMs = view?.redialWindowUntilMs
        if (untilMs == null) {
            windowJob?.cancel()
            windowJob = null
            return
        }
        if (windowJob?.isActive == true) return
        windowJob =
            scope.launch {
                delay((untilMs - monotonicMs()).coerceAtLeast(0L))
                launchDriver {
                    feed(RappViewOfCustodian.Event.RedialWindowEnded(dialJob?.isActive == true))
                }
            }
    }

    /** Closes the open session with [reason], or shuts it when null, recording its time. */
    private fun closeSession(reason: RappCloseReason?) {
        val client = sessionClient ?: return
        sessionClient = null
        pairRecord?.let(::recordSessionTime)
        // A revoking close carries the forgotten pairing's goodbye; the
        // key and the record go only on the custodian's echo, within one
        // second (section 4.6 item 6). Without the echo the pairing stays
        // in the revocation backlog for its next appearance.
        val revoking = if (reason == RappCloseReason.PAIRING_REVOKED) heldPeer?.pairIdHex else null
        if (revoking != null) inSessionRevocation = revoking
        scope.launch(Dispatchers.IO) {
            var echoed = false
            try {
                if (reason == null) {
                    client.shutdown()
                } else {
                    client.close(reason)
                    echoed = client.closeEchoReceived
                }
            } finally {
                client.shutdown()
                if (revoking != null) {
                    withContext(driverContext) {
                        if (echoed) {
                            RappPairId.fromKey(revoking)?.let { pairId ->
                                RappPairRevocation.revoke(pairId, vault)
                            }
                            catalog.removePair(revoking)
                            backlogSightings.remove(revoking)
                            backlogAssociated.remove(revoking)
                        } else if (reason == RappCloseReason.PAIRING_REVOKED) {
                            catalog.markForgotten(revoking, System.currentTimeMillis())
                            ensureBacklogDiscovery()
                        }
                        inSessionRevocation = null
                    }
                }
            }
        }
    }

    private fun handleCardStatus(status: RappCardStatus) {
        val client = sessionClient ?: return
        if (!client.isOpen) return
        when (status) {
            is RappCardStatus.Present -> {
                lastStatusFingerprint = status.fingerprint
                val offered = identity.offered(monotonicMs())
                if (offered != null && RappCertificateFingerprint.of(offered) == status.fingerprint) {
                    identity.confirmCard(offered)
                    return
                }
                if (offered != null) {
                    // A different card is present: the old offer goes at
                    // once, and the new card is read before anything is
                    // offered (section 8.4 items 2 and 3).
                    identity.withdraw()
                    updateOfferedFlows()
                }
                scope.launch(Dispatchers.IO) {
                    val certificate = client.readAuthenticationCertificate(CERTIFICATE_READ_TIMEOUT_MS)
                    launchDriver {
                        if (confirmable(status, certificate)) {
                            identity.confirmCard(checkNotNull(certificate))
                            if (sessionClient !== client || !client.isOpen) {
                                startOfferGrace()
                            } else {
                                updateOfferedFlows()
                            }
                        }
                    }
                }
            }

            RappCardStatus.Absent -> {
                lastStatusFingerprint = null
                // A report of absence is not a different card; the offer
                // stands through the grace, then is withdrawn.
                startOfferGrace()
            }
        }
    }

    private fun handleSessionEnd(end: RappRequesterSessionEnd) {
        pairRecord?.let(::recordSessionTime)
        sessionClient?.shutdown()
        sessionClient = null
        when (end) {
            RappRequesterSessionEnd.REVOKED -> {
                revokeHeldPairing()
                feed(RappViewOfCustodian.Event.PairingRevoked)
                // Discovery stops and the code entry is offered, with the
                // switch left on; a search under way owns the phase.
                stopDiscovery(null)
                if (searchJob?.isActive != true) {
                    _searchPhase.value = SearchPhase.Entry
                }
            }

            RappRequesterSessionEnd.WITHDRAWN -> {
                feed(RappViewOfCustodian.Event.Withdrawn)
            }

            RappRequesterSessionEnd.VIOLATION -> {
                feed(RappViewOfCustodian.Event.ProtocolViolation)
            }

            RappRequesterSessionEnd.LOSS -> {
                feed(RappViewOfCustodian.Event.SessionLost)
            }
        }
    }

    /** The peer revoked the pairing: its record is destroyed at once and it leaves the catalog. */
    private fun revokeHeldPairing() {
        val peer = heldPeer
        val pairId = peer?.let { RappPairId.fromKey(it.pairIdHex) }
        if (pairId != null) {
            RappPairRevocation.revoke(pairId, vault)
        }
        if (peer != null) {
            catalog.removePair(peer.pairIdHex)
        }
        pairRecord?.close()
        pairRecord = null
        heldPeer = null
    }

    /** The holder forgot the held pairings: each joins the revocation backlog with its key for the close. */
    private fun forgetHeldPairings() {
        identity.withdraw()
        updateOfferedFlows()
        for (peer in catalog.listPairs()) {
            forgetOneRequesterPairing(peer, except = null)
        }
        ensureBacklogDiscovery()
    }

    /**
     * Forgets one catalogued requester pairing, keeping [except]; one
     * whose id does not parse leaves the catalog.
     */
    private fun forgetOneRequesterPairing(
        peer: PairedPeer,
        except: RappPairId?,
    ) {
        val pairId = RappPairId.fromKey(peer.pairIdHex)
        if (pairId == null) {
            catalog.removePair(peer.pairIdHex)
            return
        }
        if (pairId == except || !isRequesterRecord(pairId)) return
        if (RappPairRevocation.forget(pairId, vault)) {
            catalog.markForgotten(peer.pairIdHex, System.currentTimeMillis())
        } else {
            catalog.removePair(peer.pairIdHex)
        }
    }

    /**
     * Watches for the custodians of forgotten pairings while any wait in
     * the revocation backlog (section 4.6 item 6). The backlog runs whether
     * remote use is on, off or suspended, and is then the only remote
     * activity; it offers no identity and starts no operation.
     */
    private fun ensureBacklogDiscovery() {
        if (catalog.forgottenPairs().isEmpty()) {
            backlogDiscovery?.close()
            backlogDiscovery = null
            return
        }
        if (backlogDiscovery != null) return
        backlogDiscovery =
            try {
                openDiscovery(scope) { event -> launchDriver { handleBacklogDiscovery(event) } }
            } catch (e: Exception) {
                trace("backlog discovery failed to start", e)
                null
            }
    }

    /**
     * One forgotten pairing's appearance: at most one connection per
     * appearance, never on a timer (section 4.6 item 6). A dial already
     * under way, or the open session carrying the close, leaves this one
     * out.
     */
    private fun handleBacklogDiscovery(event: RappRequesterDiscovery.Event) {
        when (event) {
            is RappRequesterDiscovery.Event.Resolved -> {
                for (peer in catalog.forgottenPairs()) {
                    val sighting = classifyBacklogSighting(peer, event) ?: continue
                    if (sighting is RappSighting.Appeared) {
                        if (sighting.hintMatched || backlogAssociated[peer.pairIdHex] == null) {
                            backlogAssociated[peer.pairIdHex] = event.instance
                        }
                        startBacklogDial(peer, RappDialCandidates.Endpoint(event.host, event.port))
                    }
                }
            }

            is RappRequesterDiscovery.Event.Lost -> {
                for (sightings in backlogSightings.values) {
                    sightings.lost(event.instance)
                }
            }
        }
    }

    /**
     * What the resolved service [event] means to forgotten [peer], or null
     * when it means nothing. A withdrawn record counts only on the
     * instance the pairing is associated with; anything else without the
     * pairing's hint is unannounced loss and means nothing here.
     */
    private fun classifyBacklogSighting(
        peer: PairedPeer,
        event: RappRequesterDiscovery.Event.Resolved,
    ): RappSighting? {
        val record = loadForgottenRequesterRecord(peer) ?: return null
        try {
            return backlogSightings
                .getOrPut(peer.pairIdHex) { RappRequesterSightings() }
                .resolved(
                    event.instance,
                    event.attributes,
                    backlogAssociated[peer.pairIdHex],
                    record,
                    System.currentTimeMillis() / MILLIS_PER_SECOND,
                )
        } finally {
            record.close()
        }
    }

    /** Dials the forgotten pairing once at [endpoint], destroying it only on the custodian's echo. */
    private fun startBacklogDial(
        peer: PairedPeer,
        endpoint: RappDialCandidates.Endpoint,
    ) {
        if (peer.pairIdHex == inSessionRevocation || !attemptingRevocation.add(peer.pairIdHex)) return
        val record = loadForgottenRequesterRecord(peer)
        if (record == null) {
            attemptingRevocation.remove(peer.pairIdHex)
            ensureBacklogDiscovery()
            return
        }
        scope.launch(Dispatchers.IO) {
            var echoed = false
            try {
                echoed =
                    RappRequesterClient(context, scope, record, vault, sessionListener, localName = localName)
                        .deliverRevocationNotice(DIAL_ATTEMPT_MS, directDialEndpoint ?: endpoint)
            } catch (_: Exception) {
                echoed = false
            } finally {
                record.close()
                withContext(driverContext) {
                    attemptingRevocation.remove(peer.pairIdHex)
                    if (echoed) {
                        RappPairId.fromKey(peer.pairIdHex)?.let { pairId ->
                            RappPairRevocation.revoke(pairId, vault)
                        }
                        catalog.removePair(peer.pairIdHex)
                        backlogSightings.remove(peer.pairIdHex)
                        backlogAssociated.remove(peer.pairIdHex)
                    }
                    ensureBacklogDiscovery()
                }
            }
        }
    }

    /**
     * The record of [peer] when this device is its forgotten requester;
     * null otherwise. A pairing listed forgotten whose record is gone
     * leaves the list; anything else, the custodian's own notices among
     * it, is left alone.
     */
    private fun loadForgottenRequesterRecord(peer: PairedPeer): RappPairRecord? {
        val pairId =
            RappPairId.fromKey(peer.pairIdHex) ?: run {
                catalog.removePair(peer.pairIdHex)
                return null
            }
        val record =
            try {
                RappPairRecord.loadFromVault(pairId.toWire(), vault)
            } catch (_: RappBindingException) {
                catalog.removePair(peer.pairIdHex)
                return null
            }
        val forgottenRequester =
            try {
                val pairing = record.pairing()
                pairing.role == RappEndpointRole.REQUESTER && pairing.state is RappPairState.Forgotten
            } catch (_: Exception) {
                false
            }
        if (!forgottenRequester) {
            record.close()
            return null
        }
        return record
    }

    private fun startSearch(code: String) {
        stopDiscovery(RappCloseReason.NORMAL)
        _searchPhase.value = SearchPhase.Searching
        searchJob =
            scope.launch(Dispatchers.IO) {
                val outcome =
                    RappPairingSearch(context, this, vault, searchEndpoints(), localName = localName).search(code)
                launchDriver { onSearchOutcome(outcome) }
            }
    }

    private fun onSearchOutcome(outcome: RappPairingSearch.Outcome) {
        searchJob = null
        try {
            when (outcome) {
                is RappPairingSearch.Outcome.Paired -> {
                    val pairing = outcome.record.pairing()
                    catalog.savePair(
                        pairId = pairing.id.toWire(),
                        displayName = outcome.peer.displayName,
                        platform = outcome.peer.platform,
                        createdAtMs = System.currentTimeMillis(),
                    )
                    outcome.record.close()
                    forgetPreviousPairings(pairing.id)
                    _phoneThatForgot.value = null
                    _searchPhase.value = SearchPhase.Entry
                    newestActiveRequesterPeer()?.let(::startDiscovery)
                }

                else -> {
                    _searchPhase.value = SearchPhase.Failed(outcome)
                    newestActiveRequesterPeer()?.let(::startDiscovery)
                }
            }
        } catch (e: Exception) {
            trace("pairing outcome failed", e)
            _searchPhase.value = SearchPhase.Failed(RappPairingSearch.Outcome.CeremonyEnded)
            newestActiveRequesterPeer()?.let(::startDiscovery)
        }
    }

    /** A stored pairing replaces the ones held: each forgotten one joins the revocation backlog. */
    private fun forgetPreviousPairings(except: RappPairId) {
        identity.withdraw()
        updateOfferedFlows()
        for (peer in catalog.listPairs()) {
            forgetOneRequesterPairing(peer, except)
        }
        ensureBacklogDiscovery()
    }

    /**
     * Destroys the forgotten pairings whose idle expiry passed without
     * their custodian echoing the close: 30 days after their latest
     * established session (section 4.6 item 3). Nothing is sent.
     */
    private fun sweepBacklog() {
        val nowMs = System.currentTimeMillis().toULong()
        for (peer in catalog.forgottenPairs()) {
            val pairId = RappPairId.fromKey(peer.pairIdHex) ?: continue
            val expired =
                try {
                    RappPairRecord.loadFromVault(pairId.toWire(), vault).use { record ->
                        record.revocationNoticeExpired(nowMs)
                    }
                } catch (_: Exception) {
                    false
                }
            if (expired) {
                RappPairRevocation.revoke(pairId, vault)
                catalog.removePair(peer.pairIdHex)
                backlogSightings.remove(peer.pairIdHex)
                backlogAssociated.remove(peer.pairIdHex)
            }
        }
        ensureBacklogDiscovery()
    }

    private fun sweepExpiry() {
        sweepBacklog()
        val peer = newestActiveRequesterPeer() ?: return
        val pairId = RappPairId.fromKey(peer.pairIdHex) ?: return
        val session =
            when (view?.state) {
                RappViewOfCustodian.State.CONNECTED -> RappOpenSession(pairId, established = true)
                RappViewOfCustodian.State.CONNECTING -> RappOpenSession(pairId, established = false)
                else -> null
            }
        val expired =
            RappIdleExpiry.sweepRequester(catalog, vault, System.currentTimeMillis().toULong(), session)
        if (expired.contains(pairId)) {
            lastPeerName = null
            stopDiscovery(null)
            _searchPhase.value = SearchPhase.Entry
        }
    }

    /**
     * Whether the card read on the session may be offered: the pairing
     * still offers, the view is not withdrawn or ended, and the session
     * still reports the read card. A revocation or a withdrawal since
     * the read refuses it; a loss since the read does not, and the
     * confirmed offer then stands through the grace (section 8.4 item 3).
     */
    private fun confirmable(
        status: RappCardStatus.Present,
        certificate: RappCertificate?,
    ): Boolean {
        val state = view?.state
        return heldPeer != null &&
            state != null &&
            state != RappViewOfCustodian.State.WITHDRAWN &&
            state != RappViewOfCustodian.State.ENDED &&
            lastStatusFingerprint == status.fingerprint &&
            certificate != null &&
            RappCertificateFingerprint.of(certificate) == status.fingerprint
    }

    /** The offer stands through the grace, then is withdrawn. */
    private fun startOfferGrace() {
        identity.startGrace(monotonicMs())
        updateOfferedFlows()
        scope.launch {
            delay(RappIdentityOffer.GRACE_MS)
            launchDriver { updateOfferedFlows() }
        }
    }

    /** Shows the offered identity, or no remote card. */
    private fun updateOfferedFlows() {
        val certificate = identity.offered(monotonicMs())
        val der = certificate?.toWire()
        _certificateDer.value = der
        if (der == null) {
            _holderName.value = null
            _cardDetails.value = null
            return
        }
        val name = CertificateHolderName.lineFromDer(der)
        _holderName.value = name
        _cardDetails.value =
            if (name != null) {
                PersonCardDetails.fromDer(der) ?: PersonCardDetails.fromHolderName(name)
            } else {
                null
            }
    }

    /** The most recently created pairing the holder has not forgotten. */
    private fun newestActiveRequesterPeer(): PairedPeer? =
        catalog.listPairs().filter { isActiveRequesterRecord(it) }.maxByOrNull { it.createdAtMs }

    private fun isActiveRequesterRecord(peer: PairedPeer): Boolean {
        val pairId = RappPairId.fromKey(peer.pairIdHex) ?: return false
        return try {
            RappPairRecord.loadFromVault(pairId.toWire(), vault).use { record ->
                val pairing = record.pairing()
                pairing.role == RappEndpointRole.REQUESTER && pairing.state == RappPairState.Active
            }
        } catch (_: RappBindingException) {
            false
        }
    }

    private fun isRequesterRecord(pairId: RappPairId): Boolean {
        return try {
            RappPairRecord.loadFromVault(pairId.toWire(), vault).use { record ->
                record.pairing().role == RappEndpointRole.REQUESTER
            }
        } catch (_: RappBindingException) {
            false
        }
    }

    /** The record of [peer] when this device is its requester; null otherwise. */
    private fun loadRequesterRecord(peer: PairedPeer): RappPairRecord? {
        val pairId = RappPairId.fromKey(peer.pairIdHex) ?: return null
        val record =
            try {
                RappPairRecord.loadFromVault(pairId.toWire(), vault)
            } catch (_: RappBindingException) {
                return null
            }
        val requester =
            try {
                record.pairing().role == RappEndpointRole.REQUESTER
            } catch (_: Exception) {
                false
            }
        if (!requester) record.close()
        return record.takeIf { requester }
    }

    /** Records that the held pairing carried a session now. */
    private fun recordSessionTime(record: RappPairRecord) {
        try {
            RappIdleExpiry.recordSession(record, vault, System.currentTimeMillis().toULong())
        } catch (_: Exception) {
        }
    }

    private fun monotonicMs(): Long = RappClock.monotonicMs().toLong()

    private fun trace(
        message: String,
        error: Exception?,
    ) {
        if (BuildConfig.DEBUG) {
            android.util.Log.w(TRACE_TAG, message, error)
        }
    }
}
