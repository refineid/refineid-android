// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappCardReader
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappRequesterSessionEnd
import uniffi.refineid_rapp.RappSessionBridge
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.Collections

/**
 * Holds a session over loopback against a scripted custodian speaking the
 * stamped wire (RAPP v26.11.2 sections 6.3, 7.1, 8.3): the dial opens with
 * `session.ready` and this device's `session.hello`, operations run one at
 * a time on the open session, every close is acknowledged, and each end
 * reports how the driver treats it (section 4.5 item 6).
 */
class RappRequesterClientLoopbackTest {
    private companion object {
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication")
        const val OPEN_TIMEOUT_MS = 10_000L
        const val OPERATION_TIMEOUT_MS = 10_000L
        const val LOOPBACK_HOST = "127.0.0.1"
        const val NANOS_PER_MILLI = 1_000_000L
        val READY_NONCE_BYTES =
            uniffi.refineid_rapp
                .rappRandomByteCounts()
                .sessionReadyNonce
                .toInt()
        const val LIFETIME_MS = 120_000UL

        /** How long event waits sleep between polls. */
        const val EVENT_POLL_MS = 10L

        fun monotonicMs(): ULong = (System.nanoTime() / NANOS_PER_MILLI).toULong()
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

    /** Both sides of one pairing, each persisted to its own vault. */
    private class Fixture(
        val requester: RappPairRecord,
        val requesterVault: RappMemoryVault,
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
        val requesterVault = RappMemoryVault()
        requester.persistDeviceOnly(requesterVault)
        val custodianVault = RappMemoryVault()
        custodian.persistDeviceOnly(custodianVault)
        return Fixture(requester, requesterVault, custodian, custodianVault, certificate)
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

        /** The routing preamble, `Noise_KK`, `session.ready` and this device's `session.hello`. */
        fun establish(): RappDisplayName {
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
            return named.name
        }

        /** Reports the card present, then answers one certificate read with it. */
        fun servePresentCard() {
            val bridge = checkNotNull(operation)
            val reported =
                RappBridgeOutcome.from(
                    bridge.reportCardStatus(fixture.certificate.toWire(), RappCardReader.ABSENT),
                ) as RappBridgeOutcome.Send
            writeFrame(reported.frame)
            val admitted =
                RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs()))
                    as RappBridgeOutcome.Admitted
            val read =
                RappBridgeOutcome.from(bridge.prerequisitesComplete(admitted.operationId.toWire(), monotonicMs()))
                    as RappBridgeOutcome.ExecuteRead
            assertSame(RappRequest.ReadAuthenticationCertificate, read.request)
            val completed =
                RappBridgeOutcome.from(
                    bridge.completeCertificate(admitted.operationId.toWire(), fixture.certificate.toWire()),
                ) as RappBridgeOutcome.Send
            writeFrame(completed.frame)
        }

        /** Reads this device's close and echoes it; returns the reason it carried. */
        fun echoClose(): RappCloseReason {
            val bridge = checkNotNull(operation)
            val echoed =
                RappBridgeOutcome.from(bridge.receiveFrame(readFrame(), monotonicMs()))
                    as RappBridgeOutcome.Send
            val echo = echoed.close as RappSentClose.Echo
            writeFrame(echoed.frame)
            return echo.reason
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

    private data class ListenerEvents(
        val statuses: MutableList<RappCardStatus> = Collections.synchronizedList(mutableListOf()),
        val ends: MutableList<RappRequesterSessionEnd> = Collections.synchronizedList(mutableListOf()),
        val names: MutableList<RappDisplayName> = Collections.synchronizedList(mutableListOf()),
    )

    private fun client(
        fixture: Fixture,
        events: ListenerEvents,
    ): RappRequesterClient =
        RappRequesterClient(
            DummyContext(),
            scope,
            fixture.requester,
            fixture.requesterVault,
            object : RappRequesterClient.Listener {
                override fun onCardStatus(status: RappCardStatus) {
                    events.statuses.add(status)
                }

                override fun onSessionEnd(end: RappRequesterSessionEnd) {
                    events.ends.add(end)
                }

                override fun onCustodianNamed(name: RappDisplayName) {
                    events.names.add(name)
                }
            },
            localName = { checkNotNull(RappDisplayName.parse(RappTestOffers.COMPUTER_NAME)) },
            monotonicMs = { monotonicMs() },
        )

    @Test
    fun aSessionOpensServesAnOperationAndClosesAcknowledged() =
        runBlocking {
            fixture().use { held ->
                val server = ServerSocket(0)
                try {
                    val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort)
                    val peerDone =
                        scope.launch {
                            Peer(server.accept(), held).use { peer ->
                                assertEquals(RappTestOffers.COMPUTER_NAME, peer.establish().text)
                                peer.servePresentCard()
                                assertEquals(RappCloseReason.NORMAL, peer.echoClose())
                            }
                        }
                    val events = ListenerEvents()
                    val dialed = client(held, events)
                    try {
                        assertSame(RappRequesterClient.OpenOutcome.Established, dialed.open(OPEN_TIMEOUT_MS, endpoint))
                        withTimeout(OPERATION_TIMEOUT_MS) {
                            val certificate = dialed.readAuthenticationCertificate(OPERATION_TIMEOUT_MS)
                            assertArrayEquals(held.certificate.toWire(), checkNotNull(certificate).toWire())
                        }
                        assertNull(dialed.close(RappCloseReason.NORMAL))
                    } finally {
                        dialed.shutdown()
                    }
                    withTimeout(OPERATION_TIMEOUT_MS) { peerDone.join() }
                    assertEquals(listOf(RappTestOffers.PHONE_NAME), events.names.map { it.text })
                    val status = events.statuses.single() as RappCardStatus.Present
                    assertEquals(RappCertificateFingerprint.of(held.certificate), status.fingerprint)
                    assertTrue(events.ends.isEmpty())
                } finally {
                    server.close()
                }
            }
        }

    @Test
    fun aRevokingCloseIsEchoedAndReported() {
        pendingClose(RappCloseReason.PAIRING_REVOKED, RappRequesterSessionEnd.REVOKED)
    }

    @Test
    fun aWithdrawalIsEchoedAndReported() {
        pendingClose(RappCloseReason.SERVICE_WITHDRAWN, RappRequesterSessionEnd.WITHDRAWN)
    }

    private fun pendingClose(
        reason: RappCloseReason,
        end: RappRequesterSessionEnd,
    ) = runBlocking {
        fixture().use { held ->
            val server = ServerSocket(0)
            try {
                val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort)
                val peerDone =
                    scope.launch {
                        Peer(server.accept(), held).use { peer ->
                            peer.establish()
                            val bridge = checkNotNull(peer.operation)
                            val closing =
                                RappBridgeOutcome.from(bridge.closeWithReason(reason))
                                    as RappBridgeOutcome.Send
                            peer.writeFrame(closing.frame)
                            val acknowledged =
                                RappBridgeOutcome.from(bridge.receiveFrame(peer.readFrame(), monotonicMs()))
                            assertTrue(acknowledged is RappBridgeOutcome.CloseAcknowledged)
                        }
                    }
                val events = ListenerEvents()
                val dialed = client(held, events)
                try {
                    assertSame(RappRequesterClient.OpenOutcome.Established, dialed.open(OPEN_TIMEOUT_MS, endpoint))
                    withTimeout(OPERATION_TIMEOUT_MS) { peerDone.join() }
                    withTimeout(OPERATION_TIMEOUT_MS) {
                        while (events.ends.isEmpty()) delay(EVENT_POLL_MS)
                    }
                } finally {
                    dialed.shutdown()
                }
                assertEquals(listOf(end), events.ends)
            } finally {
                server.close()
            }
        }
    }

    @Test
    fun aDroppedTransportIsALoss() =
        runBlocking {
            fixture().use { held ->
                val server = ServerSocket(0)
                try {
                    val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort)
                    val peerDone =
                        scope.launch {
                            val peer = Peer(server.accept(), held)
                            peer.establish()
                            peer.close()
                        }
                    val events = ListenerEvents()
                    val dialed = client(held, events)
                    try {
                        assertSame(RappRequesterClient.OpenOutcome.Established, dialed.open(OPEN_TIMEOUT_MS, endpoint))
                        withTimeout(OPERATION_TIMEOUT_MS) { peerDone.join() }
                        withTimeout(OPERATION_TIMEOUT_MS) {
                            while (events.ends.isEmpty()) delay(EVENT_POLL_MS)
                        }
                    } finally {
                        dialed.shutdown()
                    }
                    assertEquals(listOf(RappRequesterSessionEnd.LOSS), events.ends)
                } finally {
                    server.close()
                }
            }
        }

    @Test
    fun aRevokingCloseBeforeReadyEndsTheDialWithItsEnd() =
        runBlocking {
            fixture().use { held ->
                val server = ServerSocket(0)
                try {
                    val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort)
                    val peerDone =
                        scope.launch {
                            Peer(server.accept(), held).use { peer ->
                                peer.readFrame()
                                held.custodian.forget(held.custodianVault, System.currentTimeMillis().toULong())
                                val opened =
                                    RappSessionBridge.beginProxy(
                                        held.custodian,
                                        held.custodianVault,
                                        RappTestOffers.STREAM_PROFILE,
                                    )
                                try {
                                    opened.readHandshakeFrame(peer.readFrame())
                                    peer.writeFrame(opened.writeHandshakeFrame())
                                    opened.enterAuthentication()
                                    peer.writeFrame(opened.deliverRevocationNotice())
                                    val echoed =
                                        RappBridgeOutcome.from(opened.receiveCloseEcho(peer.readFrame(), monotonicMs()))
                                    assertTrue(echoed is RappBridgeOutcome.CloseAcknowledged)
                                } finally {
                                    opened.close()
                                }
                            }
                        }
                    val events = ListenerEvents()
                    val dialed = client(held, events)
                    try {
                        val outcome = dialed.open(OPEN_TIMEOUT_MS, endpoint) as RappRequesterClient.OpenOutcome.Failed
                        assertEquals(RappRequesterSessionEnd.REVOKED, outcome.end)
                        withTimeout(OPERATION_TIMEOUT_MS) { peerDone.join() }
                    } finally {
                        dialed.shutdown()
                    }
                    assertTrue(events.ends.isEmpty())
                } finally {
                    server.close()
                }
            }
        }

    @Test
    fun aRevocationNoticeIsDeliveredAndEchoed() =
        runBlocking {
            fixture().use { held ->
                held.requester.forget(held.requesterVault, System.currentTimeMillis().toULong())
                val server = ServerSocket(0)
                try {
                    val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, server.localPort)
                    val peerDone =
                        scope.launch {
                            Peer(server.accept(), held).use { peer ->
                                peer.readFrame()
                                val opened =
                                    RappSessionBridge.beginProxy(
                                        held.custodian,
                                        held.custodianVault,
                                        RappTestOffers.STREAM_PROFILE,
                                    )
                                try {
                                    opened.readHandshakeFrame(peer.readFrame())
                                    peer.writeFrame(opened.writeHandshakeFrame())
                                    opened.enterAuthentication()
                                    val nonce = ByteArray(READY_NONCE_BYTES).also(SecureRandom()::nextBytes)
                                    peer.writeFrame(opened.sendReady(nonce, RappTestOffers.PHONE_NAME))
                                    opened.enterEstablished()
                                    val operation =
                                        RappOperationBridge.beginProxy(opened, LIFETIME_MS, monotonicMs())
                                    try {
                                        val noticed =
                                            RappBridgeOutcome.from(
                                                operation.receiveFrame(peer.readFrame(), monotonicMs()),
                                            ) as RappBridgeOutcome.Send
                                        val echo = noticed.close as RappSentClose.Echo
                                        assertEquals(RappCloseReason.PAIRING_REVOKED, echo.reason)
                                        peer.writeFrame(noticed.frame)
                                    } finally {
                                        operation.close()
                                    }
                                } finally {
                                    opened.close()
                                }
                            }
                        }
                    val events = ListenerEvents()
                    val dialed = client(held, events)
                    val pairId = held.requester.pairing().id
                    try {
                        assertTrue(dialed.deliverRevocationNotice(OPEN_TIMEOUT_MS, endpoint))
                        withTimeout(OPERATION_TIMEOUT_MS) { peerDone.join() }
                    } finally {
                        dialed.shutdown()
                    }
                    assertTrue(held.requesterVault.isRevoked(pairId.toWire()))
                    assertTrue(events.ends.isEmpty())
                } finally {
                    server.close()
                }
            }
        }

    @Test
    fun aForgottenRecordNeverOpensASession() =
        runBlocking {
            fixture().use { held ->
                held.requester.forget(held.requesterVault, System.currentTimeMillis().toULong())
                val events = ListenerEvents()
                val dialed = client(held, events)
                try {
                    val endpoint = RappDialCandidates.Endpoint(LOOPBACK_HOST, serverPort())
                    val outcome = dialed.open(OPEN_TIMEOUT_MS, endpoint) as RappRequesterClient.OpenOutcome.Failed
                    assertNull(outcome.end)
                } finally {
                    dialed.shutdown()
                }
            }
        }

    private fun serverPort(): Int {
        ServerSocket(0).use { return it.localPort }
    }
}
