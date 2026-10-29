// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.rappPairingBusyRetryAfterMs
import uniffi.refineid_rapp.rappPairingPreamble
import uniffi.refineid_rapp.rappRandomByteCounts
import uniffi.refineid_rapp.rappStreamProfileName
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * While Remote Access is on, the Remote Access page always shows a pairing
 * code, with a computer connected or not: when Remote Access turns on, when
 * the offer expires, after a pairing completes and after a pairing is
 * removed. While it is off, it shows none.
 */
class RappPairingOfferTest {
    private companion object {
        const val NOW = 1_000UL
        const val CREATED_AT_MS = 1_700_000_000_000L
        const val WALL_MS = 1_700_000_000_000UL
        const val PEER_NAME = "Workstation"
        const val PEER_PLATFORM = "Windows"
        val CONNECTED_PAIR_ID = checkNotNull(RappPairId.fromWire("connected pair!!".encodeToByteArray())).key

        /** How long the custodian may take to finish a pairing it received the last frame of. */
        const val SETTLE_LIMIT_MS = 5_000L
        const val SETTLE_STEP_MS = 10L
        const val SOCKET_TIMEOUT_MS = 5_000
        val PROFILES = listOf("fi.refineid.card-status")
        val CPACE_RANDOM_BYTES = rappRandomByteCounts().cpaceRandom.toInt()

        /** How long an admitted attempt may run (RAPP v26.10.29 section 3.3 item 3). */
        const val ATTEMPT_WINDOW_MS = 5_000L

        /** How far into the first computer's attempt the second one connects. */
        const val ATTEMPT_ELAPSED_MS = 1_000L

        /** What a stream read returns once the peer closed the connection. */
        const val END_OF_STREAM = -1

        /** How often a requester asks a busy custodian again before the test gives up. */
        const val BUSY_REOPENINGS = 8
    }

    /** A context whose preferences live in memory and which offers no system service. */
    private class PreferencesContext : ContextWrapper(null) {
        private val preferences = HashMap<String, FakeSharedPreferences>()

        override fun getSharedPreferences(
            name: String,
            mode: Int,
        ): SharedPreferences = preferences.getOrPut(name) { FakeSharedPreferences() }

        override fun getSystemService(name: String): Any? = null

        override fun getApplicationContext(): Context = this
    }

    private val context = PreferencesContext()
    private val vault = RappMemoryVault()
    private val scope = CoroutineScope(Dispatchers.Unconfined)

    /** The custodian's open session: another computer stays connected throughout. */
    private val connected =
        MutableStateFlow<PairedPeer?>(PairedPeer(CONNECTED_PAIR_ID, PEER_NAME, PEER_PLATFORM, CREATED_AT_MS))
    private var model: RappPairingModel? = null

    /** The custodian's continuous clock, which only the test moves. */
    private val clock = AtomicLong(NOW.toLong())

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    @After
    fun tearDown() {
        model?.close()
        scope.cancel()
    }

    /** One stored, confirmed custodian pairing, as a completed ceremony leaves it; its catalog key. */
    private fun storePairing(): String {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        requester.close()
        val id = custodian.pairing().id
        custodian.persistDeviceOnly(vault)
        custodian.close()
        RappPairCatalog(context).savePair(id.toWire(), PEER_NAME, PEER_PLATFORM, CREATED_AT_MS)
        return id.key
    }

    private fun model(remoteAccessOn: Boolean): RappPairingModel {
        RappSettings(context).isCardRemoteAccessEnabled = remoteAccessOn
        return RappPairingModel(context, scope, Dispatchers.Unconfined, vault, connected) { clock.get().toULong() }
            .also { model = it }
    }

    private fun RappPairingModel.code(): String = (phase as PairingPhase.Offering).code

    @Test
    fun turningRemoteAccessOnShowsACodeWithAComputerConnected() {
        storePairing()
        val model = model(remoteAccessOn = false)
        assertEquals(connected.value, model.activeConnectedPeer)

        model.setRemoteAccessEnabled(true)

        assertTrue(model.phase is PairingPhase.Offering)
    }

    @Test
    fun openingThePageShowsACodeWithAComputerConnected() {
        storePairing()
        val model = model(remoteAccessOn = true)

        model.offerWhileOn()

        assertTrue(model.phase is PairingPhase.Offering)
    }

    @Test
    fun aShownCodeStaysUntilItExpiresAndTheNextFollows() {
        val model = model(remoteAccessOn = true)
        model.offerWhileOn()
        val first = model.code()

        model.offerWhileOn()
        assertEquals(first, model.code())

        model.offerExpired()
        assertNotEquals(first, model.code())
    }

    @Test
    fun removingTheLastPairingWhileRemoteAccessIsOnShowsANewCode() {
        val pairing = storePairing()
        // On, with no code on screen: the state a completed pairing used to leave.
        val model = model(remoteAccessOn = true)
        assertEquals(PairingPhase.Idle, model.phase)

        model.removePair(pairing)

        assertTrue(model.pairedDevices.isEmpty())
        assertTrue(model.phase is PairingPhase.Offering)
    }

    @Test
    fun removingAPairingWhileRemoteAccessIsOffShowsNoCode() {
        val pairing = storePairing()
        val model = model(remoteAccessOn = false)

        model.removePair(pairing)

        assertTrue(model.pairedDevices.isEmpty())
        assertEquals(PairingPhase.Idle, model.phase)
    }

    @Test
    fun aCompletedPairingShowsTheNextCode() {
        val model = model(remoteAccessOn = true)
        model.offerWhileOn()
        val first = model.code()

        pairOverLoopback(checkNotNull(model.offerPort), first)

        val deadline = System.currentTimeMillis() + SETTLE_LIMIT_MS
        while ((model.pairedDevices.isEmpty() || model.phase !is PairingPhase.Offering) &&
            System.currentTimeMillis() < deadline
        ) {
            Thread.sleep(SETTLE_STEP_MS)
        }
        assertEquals(listOf(PEER_NAME), model.pairedDevices.map { it.displayName })
        assertNotEquals(first, model.code())
    }

    @Test
    fun aSecondComputerIsAnsweredBusyWhileTheFirstHoldsTheAttemptAndTheScreenStays() {
        val model = model(remoteAccessOn = true)
        model.offerWhileOn()
        val code = model.code()
        val port = checkNotNull(model.offerPort)

        StreamPeer(port).use { first ->
            first.send(rappPairingPreamble(rappStreamProfileName()))
            val requester = RappPairingBridge.fromBootstrap(first.receive(), RappTestOffers.STREAM_PROFILE, NOW)
            val random = ByteArray(CPACE_RANDOM_BYTES).also(SecureRandom()::nextBytes)
            requester.beginCpace(RappTestOffers.STREAM_CANDIDATE_ID, code, random, NOW)
            first.send(requester.writeCpaceFrame(NOW))
            requester.readCpaceFrame(first.receive(), NOW)
            val during = model.phase
            clock.addAndGet(ATTEMPT_ELAPSED_MS)

            StreamPeer(port).use { second ->
                second.send(rappPairingPreamble(rappStreamProfileName()))
                val busy = second.receive()
                assertThrows(RappBindingException.CustodianBusy::class.java) {
                    RappPairingBridge.fromBootstrap(busy, RappTestOffers.STREAM_PROFILE, NOW)
                }
                assertEquals((ATTEMPT_WINDOW_MS - ATTEMPT_ELAPSED_MS).toULong(), rappPairingBusyRetryAfterMs(busy))
                assertEquals(END_OF_STREAM, second.input.read())
            }
            assertEquals(during, model.phase)
            requester.close()
        }

        awaitOffering(model)
        assertEquals(code, model.code())
        var answer = bootstrapAnswer(port)
        var openings = 1
        while (busyWait(answer) != null && openings < BUSY_REOPENINGS) {
            assertEquals(code, model.code())
            clock.addAndGet(checkNotNull(busyWait(answer)).toLong())
            answer = bootstrapAnswer(port)
            openings++
        }
        RappPairingBridge.fromBootstrap(answer, RappTestOffers.STREAM_PROFILE, NOW).close()
        awaitOffering(model)
        assertEquals(code, model.code())
    }

    /** The custodian's bootstrap answer to a new pairing connection on [port], which then closes. */
    private fun bootstrapAnswer(port: Int): ByteArray =
        StreamPeer(port).use { peer ->
            peer.send(rappPairingPreamble(rappStreamProfileName()))
            peer.receive()
        }

    /** The wait [answer] asks for when it is a busy answer, or null for an offer. */
    private fun busyWait(answer: ByteArray): ULong? =
        try {
            rappPairingBusyRetryAfterMs(answer)
        } catch (_: RappBindingException) {
            null
        }

    private fun awaitOffering(model: RappPairingModel) {
        val deadline = System.currentTimeMillis() + SETTLE_LIMIT_MS
        while (model.phase !is PairingPhase.Offering && System.currentTimeMillis() < deadline) {
            Thread.sleep(SETTLE_STEP_MS)
        }
    }

    /** A requester's stream connection to the custodian on [port] (RAPP v26.10.29 section 2.1). */
    private class StreamPeer(
        port: Int,
    ) : AutoCloseable {
        private val socket = Socket(InetAddress.getLoopbackAddress(), port).apply { soTimeout = SOCKET_TIMEOUT_MS }
        val input = DataInputStream(socket.getInputStream())
        private val output = DataOutputStream(socket.getOutputStream())

        fun send(frame: ByteArray) {
            output.write(checkNotNull(StreamRelayFraming.encode(frame)))
            output.flush()
        }

        fun receive(): ByteArray = ByteArray(input.readUnsignedShort()).also(input::readFully)

        override fun close() = socket.close()
    }

    /** A requester pairing with [code] over the stream on [port], frame by frame (RAPP v26.10.29 section 2.1). */
    private fun pairOverLoopback(
        port: Int,
        code: String,
    ) {
        Socket(InetAddress.getLoopbackAddress(), port).use { socket ->
            socket.soTimeout = SOCKET_TIMEOUT_MS
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())

            fun send(frame: ByteArray) {
                output.write(checkNotNull(StreamRelayFraming.encode(frame)))
                output.flush()
            }

            fun receive(): ByteArray = ByteArray(input.readUnsignedShort()).also(input::readFully)

            send(rappPairingPreamble(rappStreamProfileName()))
            val requester = RappPairingBridge.fromBootstrap(receive(), RappTestOffers.STREAM_PROFILE, NOW)
            val random = ByteArray(CPACE_RANDOM_BYTES).also(SecureRandom()::nextBytes)
            requester.beginCpace(RappTestOffers.STREAM_CANDIDATE_ID, code, random, NOW)
            send(requester.writeCpaceFrame(NOW))
            requester.readCpaceFrame(receive(), NOW)
            send(requester.writeCpaceFrame(NOW))
            send(requester.writeHandshakeFrame(NOW))
            requester.readHandshakeFrame(receive(), NOW)
            send(requester.writeHandshakeFrame(NOW))
            requester.enterConfirmation(NOW)
            send(requester.sendHello(PEER_NAME, PEER_PLATFORM, NOW))
            requester.receiveHello(receive(), NOW)
            val granted = requester.receiveConfirmation(receive(), NOW)
            send(requester.sendConfirmation(granted, NOW))
            requester.buildPairRecord(WALL_MS, NOW).close()
            send(requester.sendStored(NOW))
            requester.receiveStored(receive(), NOW)
            checkNotNull(requester.activatePairing(NOW)).close()
            requester.close()
        }
    }
}
