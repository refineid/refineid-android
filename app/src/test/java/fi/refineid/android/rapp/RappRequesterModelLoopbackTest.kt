// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.ContextWrapper
import fi.refineid.android.core.CertificateHolderName
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappAnnouncementCandidate
import uniffi.refineid_rapp.RappCardReader
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSweepOutcome
import uniffi.refineid_rapp.rappSessionRecord
import uniffi.refineid_rapp.rappWithdrawnRecord
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.TimeUnit

/**
 * The requester's held session over loopback against a scripted custodian
 * (RAPP v26.11.2 sections 4.5-4.7, 8.3, 8.4): an appearance dials, the
 * confirmed card is offered and nothing else ever is, a loss redials
 * within its window, a withdrawal drops the offer until the next
 * announcement, and a revocation forgets the pairing with the notice.
 */
class RappRequesterModelLoopbackTest {
    private companion object {
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication")
        const val FLOW_TIMEOUT_MS = 30_000L
        const val CONSUMER_TIMEOUT_MS = 5_000L
        const val LOOPBACK_HOST = "127.0.0.1"
        const val INSTANCE = "refineid-test01"
        const val FRESH_INSTANCE = "refineid-test02"
        const val NANOS_PER_MILLI = 1_000_000L
        const val MILLIS_PER_SECOND = 1_000L
        val READY_NONCE_BYTES =
            uniffi.refineid_rapp
                .rappRandomByteCounts()
                .sessionReadyNonce
                .toInt()
        const val LIFETIME_MS = 120_000UL
        const val USE_ORDER = 0UL

        /** How long the withdrawn quiet is observed with no redial. */
        const val WITHDRAWN_QUIET_MS = 2_500L

        /** How long the quiet is observed with no backlog dial. */
        const val NO_DIAL_QUIET_MS = 1_000L

        /** How long event waits sleep between polls. */
        const val EVENT_POLL_MS = 10L

        /** How long a withdrawn record waits before it is emitted again. */
        const val WITHDRAWN_RETRY_MS = 300L

        /** Days before the wall clock a backlog test's last session was established. */
        const val SESSION_AGO_DAYS = 10L

        fun monotonicMs(): ULong = (System.nanoTime() / NANOS_PER_MILLI).toULong()

        fun sessionAtMs(nowMs: ULong): ULong = nowMs - TimeUnit.DAYS.toMillis(SESSION_AGO_DAYS).toULong()

        fun unixSeconds(): Long = System.currentTimeMillis() / MILLIS_PER_SECOND
    }

    private lateinit var scope: CoroutineScope

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    @After
    fun tearDown() {
        scope.cancel()
    }

    /** A context that offers no system service, so nothing is advertised or browsed. */
    private class DummyContext : ContextWrapper(null) {
        override fun getSystemService(name: String): Any? = null

        override fun getApplicationContext(): android.content.Context = this
    }

    /** Both sides of one pairing, the requester's catalogued and held. */
    private class Fixture(
        val requester: RappPairRecord,
        val vault: RappMemoryVault,
        val catalog: RappPairCatalog,
        val custodian: RappPairRecord,
        val custodianVault: RappMemoryVault,
        val certificate: RappCertificate,
    ) : AutoCloseable {
        override fun close() {
            requester.close()
            custodian.close()
        }
    }

    private fun fixture(): Fixture {
        val der = RappTestCertificate.der
        assumeTrue("OpenSSL makes the synthetic certificate", der != null)
        val certificate = checkNotNull(RappCertificate.fromDer(checkNotNull(der)))
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, monotonicMs())
        val vault = RappMemoryVault()
        requester.persistDeviceOnly(vault)
        val custodianVault = RappMemoryVault()
        custodian.persistDeviceOnly(custodianVault)
        val catalog = RappPairCatalog(FakeSharedPreferences())
        catalog.savePair(
            requester.pairing().id.toWire(),
            RappTestOffers.PHONE_NAME,
            RappTestOffers.PHONE_PLATFORM,
            System.currentTimeMillis(),
        )
        return Fixture(requester, vault, catalog, custodian, custodianVault, certificate)
    }

    /**
     * Dates [held] for a backlog delivery at the wall clock: its last
     * session stays within the 30-day idle window, so the later forget
     * still owes the close.
     */
    private fun dateForDelivery(held: Fixture) {
        val sessionAt = sessionAtMs(System.currentTimeMillis().toULong())
        assertEquals(RappSweepOutcome.RECORDED, held.requester.sweep(held.vault, sessionAt, true))
    }

    /** Scripted session discovery, emitting on the test's word. */
    private class FakeDiscovery(
        val onEvent: (RappRequesterDiscovery.Event) -> Unit,
    ) : AutoCloseable {
        var closed = false

        fun emit(event: RappRequesterDiscovery.Event) {
            if (!closed) onEvent(event)
        }

        override fun close() {
            closed = true
        }
    }

    /** One scripted custodian connection over loopback. */
    private class Peer(
        private val socket: Socket,
        private val fixture: Fixture,
    ) : AutoCloseable {
        private val input = DataInputStream(socket.getInputStream())
        private val output = DataOutputStream(socket.getOutputStream())
        private var session: RappSessionBridge? = null
        var operation: RappOperationBridge? = null
            private set

        fun readFrame(): ByteArray = StreamRelayFraming.read(input)

        fun writeFrame(frame: ByteArray) {
            output.write(checkNotNull(StreamRelayFraming.encode(frame)))
            output.flush()
        }

        fun establish() {
            readFrame()
            val opened =
                RappSessionBridge.beginProxy(fixture.custodian, fixture.custodianVault, RappTestOffers.STREAM_PROFILE)
            session = opened
            opened.readHandshakeFrame(readFrame())
            writeFrame(opened.writeHandshakeFrame())
            opened.enterAuthentication()
            val nonce = ByteArray(READY_NONCE_BYTES).also(SecureRandom()::nextBytes)
            writeFrame(opened.sendReady(nonce, RappTestOffers.PHONE_NAME))
            opened.enterEstablished()
            val bridge = RappOperationBridge.beginProxy(opened, LIFETIME_MS, monotonicMs())
            operation = bridge
            val named = RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs()))
            check(named is RappBridgeOutcome.PeerNamed)
        }

        /** Reports the card present and answers certificate reads until the script moves on. */
        fun servePresentCard() {
            val bridge = checkNotNull(operation)
            val reported =
                RappBridgeOutcome.from(
                    bridge.reportCardStatus(fixture.certificate.toWire(), RappCardReader.ABSENT),
                ) as RappBridgeOutcome.Send
            writeFrame(reported.frame)
        }

        /** Answers one certificate read. */
        fun answerCertificateRead() {
            val bridge = checkNotNull(operation)
            val admitted =
                RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs()))
                    as RappBridgeOutcome.Admitted
            val read =
                RappBridgeOutcome.from(bridge.prerequisitesComplete(admitted.operationId.toWire(), monotonicMs()))
                    as RappBridgeOutcome.ExecuteRead
            check(read.request == RappRequest.ReadAuthenticationCertificate)
            val completed =
                RappBridgeOutcome.from(
                    bridge.completeCertificate(admitted.operationId.toWire(), fixture.certificate.toWire()),
                ) as RappBridgeOutcome.Send
            writeFrame(completed.frame)
        }

        /** Closes with [reason] and reads the echo. */
        fun closeWith(reason: RappCloseReason) {
            val bridge = checkNotNull(operation)
            val closing = RappBridgeOutcome.from(bridge.closeWithReason(reason)) as RappBridgeOutcome.Send
            writeFrame(closing.frame)
            val acknowledged = RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs()))
            check(acknowledged is RappBridgeOutcome.CloseAcknowledged)
        }

        /** Reads this device's close and echoes it; returns the reason it carried. */
        fun echoClose(): RappCloseReason {
            val bridge = checkNotNull(operation)
            val echoed =
                RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs())) as RappBridgeOutcome.Send
            val echo = echoed.close as RappSentClose.Echo
            writeFrame(echoed.frame)
            return echo.reason
        }

        /**
         * The custodian side of one revocation delivery: the handshake, its
         * `session.ready`, then the forgotten pairing's close as the first
         * message, which it echoes (section 4.6 item 2).
         */
        fun echoRevocationClose() {
            readFrame()
            val opened =
                RappSessionBridge.beginProxy(fixture.custodian, fixture.custodianVault, RappTestOffers.STREAM_PROFILE)
            session = opened
            opened.readHandshakeFrame(readFrame())
            writeFrame(opened.writeHandshakeFrame())
            opened.enterAuthentication()
            val nonce = ByteArray(READY_NONCE_BYTES).also(SecureRandom()::nextBytes)
            writeFrame(opened.sendReady(nonce, RappTestOffers.PHONE_NAME))
            opened.enterEstablished()
            val bridge = RappOperationBridge.beginProxy(opened, LIFETIME_MS, monotonicMs())
            operation = bridge
            val noticed =
                RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs())) as RappBridgeOutcome.Send
            val echo = noticed.close as RappSentClose.Echo
            check(echo.reason == RappCloseReason.PAIRING_REVOKED)
            writeFrame(noticed.frame)
        }

        override fun close() {
            try {
                operation?.close()
            } catch (_: Exception) {
            }
            try {
                session?.close()
            } catch (_: Exception) {
            }
            try {
                socket.close()
            } catch (_: IOException) {
            }
        }
    }

    private fun sessionAttributes(fixture: Fixture): Map<String, ByteArray?> =
        StreamRendezvousName
            .attributes(
                rappSessionRecord(
                    listOf(
                        RappAnnouncementCandidate(
                            fixture.custodian.discoveryHint(unixSeconds().toULong()),
                            USE_ORDER,
                        ),
                    ),
                ),
            ).mapValues { (_, value) -> value.encodeToByteArray() }

    private fun withdrawnAttributes(
        fixture: Fixture,
        instance: String,
    ): Map<String, ByteArray?> =
        StreamRendezvousName
            .attributes(
                rappWithdrawnRecord(
                    listOf(
                        RappAnnouncementCandidate(
                            fixture.custodian.withdrawalHint(instance, unixSeconds().toULong()),
                            USE_ORDER,
                        ),
                    ),
                ),
            ).mapValues { (_, value) -> value.encodeToByteArray() }

    /** The model under test, dialing [server] directly on appearances the test emits. */
    private class Harness(
        val model: RemoteCardModel,
        val settings: RappSettings,
        val discoveries: MutableList<FakeDiscovery>,
        val server: ServerSocket,
        val connections: MutableList<Unit>,
    ) : AutoCloseable {
        suspend fun discovery(): FakeDiscovery =
            withTimeout(FLOW_TIMEOUT_MS) {
                while (discoveries.isEmpty()) delay(EVENT_POLL_MS)
                discoveries.last()
            }

        override fun close() {
            server.close()
        }
    }

    private fun harness(fixture: Fixture): Harness {
        val server = ServerSocket(0)
        val settings = RappSettings(FakeSharedPreferences())
        val discoveries = Collections.synchronizedList(mutableListOf<FakeDiscovery>())
        val model =
            RemoteCardModel(
                DummyContext(),
                scope,
                fixture.vault,
                fixture.catalog,
                settings = settings,
                searchEndpoints = {
                    object : RappPairingEndpoints {
                        override fun start(onFound: (String, String, Int) -> Unit) = Unit

                        override fun close() = Unit
                    }
                },
                directDialEndpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort),
                openDiscovery = { _, onEvent ->
                    FakeDiscovery(onEvent).also(discoveries::add)
                },
                localName = { checkNotNull(RappDisplayName.parse(RappTestOffers.COMPUTER_NAME)) },
            )
        return Harness(model, settings, discoveries, server, Collections.synchronizedList(mutableListOf()))
    }

    @Test
    fun anAppearanceDialsAndTheConfirmedCardIsOffered() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    assertTrue(harness.settings.isRequesterRemoteUseEnabled)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    assertEquals(
                        CertificateHolderName.lineFromDer(held.certificate.toWire()),
                        harness.model.holderName.value,
                    )
                    assertEquals(1, harness.connections.size)
                }
            }
        }

    @Test
    fun aLostSessionRedialsWithinItsWindow() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                            }
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    // The first session drops; the offer stands through its
                    // grace and the redial brings the session back.
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (harness.connections.size < 2) delay(EVENT_POLL_MS)
                    }
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    assertEquals(2, harness.connections.size)
                }
            }
        }

    @Test
    fun aWithdrawalDropsTheOfferUntilTheNextAnnouncement() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    // The withdrawal waits until the offer it drops is
                    // observed: a close racing the confirmation converges to
                    // the same dropped state, with no transient to observe.
                    val offerObserved = CompletableDeferred<Unit>()
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                                offerObserved.await()
                                peer.closeWith(RappCloseReason.SERVICE_WITHDRAWN)
                            }
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    offerObserved.complete(Unit)
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it == null }
                    }
                    // A consumer while withdrawn is refused at once.
                    assertNull(harness.model.readAuthenticationCertificate(CONSUMER_TIMEOUT_MS))
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            FRESH_INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    assertEquals(2, harness.connections.size)
                }
            }
        }

    @Test
    fun aVerifiedWithdrawalStopsTheRedial() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    // The session dropped; the withdrawn record, verified on
                    // the associated instance, stops the redial at once.
                    repeat(2) {
                        discovery.emit(
                            RappRequesterDiscovery.Event.Resolved(
                                INSTANCE,
                                LOOPBACK_HOST,
                                harness.server.localPort,
                                withdrawnAttributes(held, INSTANCE),
                            ),
                        )
                        delay(WITHDRAWN_RETRY_MS)
                    }
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it == null }
                    }
                    delay(WITHDRAWN_QUIET_MS)
                    assertEquals(1, harness.connections.size)
                }
            }
        }

    @Test
    fun aRevocationForgetsThePairingWithTheNotice() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    // The revoking close waits until the offer it forgets is
                    // observed: a close racing the confirmation converges to
                    // the same forgotten state, with no transient to observe.
                    val offerObserved = CompletableDeferred<Unit>()
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                                offerObserved.await()
                                peer.closeWith(RappCloseReason.PAIRING_REVOKED)
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    offerObserved.complete(Unit)
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.phoneThatForgot.first { it != null }
                    }
                    assertEquals(RappTestOffers.PHONE_NAME, harness.model.phoneThatForgot.value)
                    assertNull(harness.model.holderName.value)
                    assertTrue(held.catalog.allPairs().isEmpty())
                    assertTrue(harness.model.remoteUseEnabled.value)
                    assertEquals(
                        RemoteCardModel.SearchPhase.Entry,
                        harness.model.searchPhase.value,
                    )
                }
            }
        }

    @Test
    fun noDialHappensWithoutAnAppearance() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val pairId = held.requester.pairing().id
                    harness.model.forget()
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (held.catalog.forgottenPairs().isEmpty()) delay(EVENT_POLL_MS)
                    }
                    // The backlog watches, but nothing is dialed until the custodian appears.
                    val backlog = harness.discovery()
                    assertFalse(backlog.closed)
                    harness.server.soTimeout = NO_DIAL_QUIET_MS.toInt()
                    try {
                        harness.server.accept().close()
                        fail("no dial happens without an appearance")
                    } catch (_: SocketTimeoutException) {
                    }
                    assertEquals(
                        pairId.key,
                        held.catalog
                            .forgottenPairs()
                            .single()
                            .pairIdHex,
                    )
                    assertFalse(held.vault.isRevoked(pairId.toWire()))
                }
            }
        }

    @Test
    fun anAppearanceDialsTheBacklogAndDestroysItOnTheEcho() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val pairId = held.requester.pairing().id
                    dateForDelivery(held)
                    harness.model.forget()
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (held.catalog.forgottenPairs().isEmpty()) delay(EVENT_POLL_MS)
                    }
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.echoRevocationClose()
                            }
                        }
                    val backlog = harness.discovery()
                    val appearance =
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        )
                    // A repeat sight while the dial runs opens nothing more.
                    backlog.emit(appearance)
                    backlog.emit(appearance)
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (held.catalog.allPairs().isNotEmpty()) delay(EVENT_POLL_MS)
                    }
                    assertEquals(1, harness.connections.size)
                    assertTrue(held.vault.isRevoked(pairId.toWire()))
                    assertNull(harness.model.offeredCertificateDer)
                }
            }
        }

    @Test
    fun aRevokingCloseWithoutAnEchoStaysInTheBacklog() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val pairId = held.requester.pairing().id
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                                // The switch going off closes the session with
                                // the revoking close; the custodian drops it
                                // unheard instead of echoing it.
                                peer.readFrame()
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    harness.model.setRemoteUseEnabled(false)
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    // Without the echo the key and the record stay for the next appearance.
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (held.catalog.forgottenPairs().isEmpty()) delay(EVENT_POLL_MS)
                    }
                    assertEquals(
                        pairId.key,
                        held.catalog
                            .forgottenPairs()
                            .single()
                            .pairIdHex,
                    )
                    assertFalse(held.vault.isRevoked(pairId.toWire()))
                    assertNull(harness.model.holderName.value)
                }
            }
        }

    @Test
    fun turningRemoteUseOffForgetsThePairingWithAnEchoedClose() =
        runBlocking {
            fixture().use { held ->
                harness(held).use { harness ->
                    val peerDone =
                        scope.launch {
                            Peer(harness.server.accept(), held).use { peer ->
                                harness.connections.add(Unit)
                                peer.establish()
                                peer.servePresentCard()
                                peer.answerCertificateRead()
                                // The switch going off closes the session
                                // with the revoking close, echoed here.
                                assertEquals(RappCloseReason.PAIRING_REVOKED, peer.echoClose())
                            }
                        }
                    harness.model.setRemoteUseEnabled(true)
                    val discovery = harness.discovery()
                    discovery.emit(
                        RappRequesterDiscovery.Event.Resolved(
                            INSTANCE,
                            LOOPBACK_HOST,
                            harness.server.localPort,
                            sessionAttributes(held),
                        ),
                    )
                    withTimeout(FLOW_TIMEOUT_MS) {
                        harness.model.holderName.first { it != null }
                    }
                    harness.model.setRemoteUseEnabled(false)
                    withTimeout(FLOW_TIMEOUT_MS) { peerDone.join() }
                    assertFalse(harness.settings.isRequesterRemoteUseEnabled)
                    assertNull(harness.model.holderName.value)
                    withTimeout(FLOW_TIMEOUT_MS) {
                        while (held.catalog.allPairs().isNotEmpty()) delay(EVENT_POLL_MS)
                    }
                }
            }
        }
}
