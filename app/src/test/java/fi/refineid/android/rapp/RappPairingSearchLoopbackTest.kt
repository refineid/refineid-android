// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairingBridge
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom

/**
 * Tries a typed pairing code over loopback against a scripted custodian
 * (RAPP v26.11.2 section 4.2, "Trying Each Custodian in Pairing Mode"):
 * each custodian in turn, one guess each, a busy answer waited out, and
 * the code reported not accepted only once every custodian tried refused
 * it.
 */
class RappPairingSearchLoopbackTest {
    private companion object {
        val PROFILES =
            listOf(
                "fi.refineid.card-status",
                "fi.refineid.authentication",
                "fi.refineid.document-signing",
            )
        const val SEARCH_TIMEOUT_MS = 30_000L

        /** The discovery grace an empty search waits out. */
        const val EMPTY_SEARCH_GRACE_MS = 100L
        const val LOOPBACK_HOST = "127.0.0.1"
        const val INSTANCE = "test-pairing-instance"
        const val NANOS_PER_MILLI = 1_000_000L
        const val CPACE_RANDOM_BYTES = 64
        const val OFFER_ID_BYTES = 32

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

    /** The endpoints one search is told about. */
    private class ScriptedEndpoints(
        private val found: List<Triple<String, String, Int>>,
    ) : RappPairingEndpoints {
        override fun start(onFound: (instance: String, host: String, port: Int) -> Unit) {
            found.forEach { (instance, host, port) -> onFound(instance, host, port) }
        }

        override fun close() = Unit
    }

    /** One scripted custodian connection over loopback. */
    private class Peer(
        private val socket: Socket,
    ) : AutoCloseable {
        private val input = DataInputStream(socket.getInputStream())
        private val output = DataOutputStream(socket.getOutputStream())

        fun readFrame(): ByteArray = StreamRelayFraming.read(input)

        fun writeFrame(frame: ByteArray) {
            output.write(checkNotNull(StreamRelayFraming.encode(frame)))
            output.flush()
        }

        override fun close() {
            try {
                socket.close()
            } catch (_: IOException) {
            }
        }
    }

    private fun search(
        port: Int,
        vault: RappMemoryVault,
        instances: List<Triple<String, String, Int>> =
            listOf(Triple(INSTANCE, LOOPBACK_HOST, port)),
        initialDiscoveryMs: Long = RappPairingSearch.INITIAL_DISCOVERY_MS,
    ): RappPairingSearch =
        RappPairingSearch(
            DummyContext(),
            scope,
            vault,
            ScriptedEndpoints(instances),
            localName = { checkNotNull(RappDisplayName.parse(RappTestOffers.COMPUTER_NAME)) },
            monotonicMs = { monotonicMs() },
            initialDiscoveryMs = initialDiscoveryMs,
        )

    /**
     * Serves one connection with the offer ceremony for [code], pairing
     * into [vault]; returns the custodian's confirmed record bytes.
     */
    private fun Peer.serveOffer(
        code: String,
        vault: RappMemoryVault,
        offerId: ByteArray = ByteArray(OFFER_ID_BYTES).also(SecureRandom()::nextBytes),
    ): ByteArray {
        val now = monotonicMs()
        val bridge =
            RappPairingBridge.createCustodianOffer(
                offerId,
                PROFILES,
                listOf(RappTestOffers.STREAM_PROFILE),
                now,
            )
        readFrame()
        writeFrame(bridge.bootstrapBytes(now))
        val random = ByteArray(CPACE_RANDOM_BYTES).also(SecureRandom()::nextBytes)
        try {
            bridge.beginCpace(RappTestOffers.STREAM_CANDIDATE_ID, code, random, monotonicMs())
        } finally {
            random.fill(0)
        }
        val ceremony =
            RappCustodianPairingCeremony(
                bridge = bridge,
                offeredProfiles = PROFILES,
                displayName = checkNotNull(RappDisplayName.parse(RappTestOffers.PHONE_NAME)),
                platform = RappTestOffers.PHONE_PLATFORM,
                monotonicMs = { monotonicMs() },
                wallMs = { System.currentTimeMillis().toULong() },
                persistUnconfirmed = { record -> record.persistDeviceOnly(vault) },
            )
        while (true) {
            when (val outcome = ceremony.receive(readFrame())) {
                is RappCustodianPairingCeremony.Outcome.Send -> {
                    outcome.frames.forEach(::writeFrame)
                }

                is RappCustodianPairingCeremony.Outcome.Paired -> {
                    outcome.record.replaceDeviceOnly(vault)
                    val pairId =
                        outcome.record
                            .pairing()
                            .id
                            .toWire()
                    outcome.record.close()
                    return pairId
                }
            }
        }
    }

    /**
     * Serves one connection with the bootstrap of offer [offerId] and
     * reports whether the requester sent anything after it.
     */
    private fun Peer.serveBootstrapOnly(offerId: ByteArray): Boolean {
        val now = monotonicMs()
        val bridge =
            RappPairingBridge.createCustodianOffer(
                offerId,
                PROFILES,
                listOf(RappTestOffers.STREAM_PROFILE),
                now,
            )
        readFrame()
        writeFrame(bridge.bootstrapBytes(now))
        return try {
            readFrame()
            true
        } catch (_: IOException) {
            false
        }
    }

    /** Serves one connection with a busy bootstrap answer. */
    private fun Peer.serveBusy() {
        val now = monotonicMs()
        val offerId = ByteArray(OFFER_ID_BYTES).also(SecureRandom()::nextBytes)
        val bridge =
            RappPairingBridge.createCustodianOffer(
                offerId,
                PROFILES,
                listOf(RappTestOffers.STREAM_PROFILE),
                now,
            )
        readFrame()
        writeFrame(bridge.busyBytes(now, 0UL))
    }

    @Test
    fun aTypedCodePairsWithThePhoneInPairingMode() =
        runBlocking {
            val code = RappPairingCode.generate()
            val requesterVault = RappMemoryVault()
            val custodianVault = RappMemoryVault()
            val server = ServerSocket(0)
            try {
                val peerPairId =
                    scope.async {
                        Peer(server.accept()).use { peer ->
                            peer.serveOffer(code, custodianVault)
                        }
                    }
                val outcome =
                    withTimeout(SEARCH_TIMEOUT_MS) {
                        search(server.localPort, requesterVault).search(code)
                    }
                val paired = outcome as RappPairingSearch.Outcome.Paired
                assertEquals(RappTestOffers.PHONE_NAME, paired.peer.displayName)
                val pairId =
                    paired.record
                        .pairing()
                        .id
                        .toWire()
                paired.record.close()
                withTimeout(SEARCH_TIMEOUT_MS) {
                    assertArrayEquals(pairId, peerPairId.await())
                }
                assertArrayEquals(
                    pairId,
                    RappPairRecord.loadFromVault(pairId, requesterVault).use { it.pairing().id.toWire() },
                )
            } finally {
                server.close()
            }
        }

    @Test
    fun aWrongCodeIsNotAcceptedOnceEveryPhoneRefusedIt() =
        runBlocking {
            val code = RappPairingCode.generate()
            var wrong = RappPairingCode.generate()
            while (wrong == code) {
                wrong = RappPairingCode.generate()
            }
            val requesterVault = RappMemoryVault()
            val custodianVault = RappMemoryVault()
            val server = ServerSocket(0)
            try {
                val peerDone =
                    scope.launch {
                        Peer(server.accept()).use { peer ->
                            try {
                                peer.serveOffer(code, custodianVault)
                            } catch (_: Exception) {
                                // The search drops a refusal without goodbye.
                            }
                        }
                    }
                val outcome =
                    withTimeout(SEARCH_TIMEOUT_MS) {
                        search(server.localPort, requesterVault).search(wrong)
                    }
                withTimeout(SEARCH_TIMEOUT_MS) { peerDone.join() }
                assertEquals(RappPairingSearch.Outcome.NotAccepted, outcome)
            } finally {
                server.close()
            }
        }

    @Test
    fun aBusyAnswerIsWaitedOutAndTheRetryPairs() =
        runBlocking {
            val code = RappPairingCode.generate()
            val requesterVault = RappMemoryVault()
            val custodianVault = RappMemoryVault()
            val server = ServerSocket(0)
            try {
                val peerDone =
                    scope.launch {
                        Peer(server.accept()).use { busy ->
                            busy.serveBusy()
                        }
                        Peer(server.accept()).use { peer ->
                            peer.serveOffer(code, custodianVault)
                        }
                    }
                val outcome =
                    withTimeout(SEARCH_TIMEOUT_MS) {
                        search(server.localPort, requesterVault).search(code)
                    }
                withTimeout(SEARCH_TIMEOUT_MS) { peerDone.join() }
                assertTrue(outcome is RappPairingSearch.Outcome.Paired)
            } finally {
                server.close()
            }
        }

    @Test
    fun aPhoneReannouncedOnANewPortPairsPastItsStaleRecord() =
        runBlocking {
            val code = RappPairingCode.generate()
            val requesterVault = RappMemoryVault()
            val custodianVault = RappMemoryVault()
            // A listener the phone no longer runs: its port refuses connections.
            // It closes only once the live listener holds its own port.
            val staleListener = ServerSocket(0)
            val stalePort = staleListener.localPort
            val server = ServerSocket(0)
            staleListener.close()
            try {
                val peerDone =
                    scope.launch {
                        Peer(server.accept()).use { peer ->
                            peer.serveOffer(code, custodianVault)
                        }
                    }
                val instances =
                    listOf(
                        Triple(INSTANCE, LOOPBACK_HOST, stalePort),
                        Triple(INSTANCE, LOOPBACK_HOST, server.localPort),
                    )
                val outcome =
                    withTimeout(SEARCH_TIMEOUT_MS) {
                        search(server.localPort, requesterVault, instances).search(code)
                    }
                assertTrue("outcome was $outcome", outcome is RappPairingSearch.Outcome.Paired)
                (outcome as RappPairingSearch.Outcome.Paired).record.close()
                withTimeout(SEARCH_TIMEOUT_MS) { peerDone.join() }
            } finally {
                server.close()
            }
        }

    @Test
    fun onlyStaleRecordsOfAPhoneFindNone() =
        runBlocking {
            val code = RappPairingCode.generate()
            val first = ServerSocket(0)
            val second = ServerSocket(0)
            val stalePorts = listOf(first.localPort, second.localPort)
            first.close()
            second.close()
            val instances = stalePorts.map { port -> Triple(INSTANCE, LOOPBACK_HOST, port) }
            val outcome =
                withTimeout(SEARCH_TIMEOUT_MS) {
                    search(0, RappMemoryVault(), instances, initialDiscoveryMs = EMPTY_SEARCH_GRACE_MS).search(code)
                }
            assertEquals(RappPairingSearch.Outcome.NoneFound, outcome)
        }

    @Test
    fun aPhoneReannouncedAfterRefusingTheCodeGetsNoSecondGuess() =
        runBlocking {
            val code = RappPairingCode.generate()
            var wrong = RappPairingCode.generate()
            while (wrong == code) {
                wrong = RappPairingCode.generate()
            }
            val offerId = ByteArray(OFFER_ID_BYTES).also(SecureRandom()::nextBytes)
            val before = ServerSocket(0)
            val after = ServerSocket(0)
            try {
                val refused =
                    scope.launch {
                        Peer(before.accept()).use { peer ->
                            try {
                                peer.serveOffer(code, RappMemoryVault(), offerId)
                            } catch (_: Exception) {
                                // The search drops a refusal without goodbye.
                            }
                        }
                    }
                val sentAfterBootstrap =
                    scope.async {
                        Peer(after.accept()).use { peer -> peer.serveBootstrapOnly(offerId) }
                    }
                val instances =
                    listOf(
                        Triple(INSTANCE, LOOPBACK_HOST, before.localPort),
                        Triple(INSTANCE, LOOPBACK_HOST, after.localPort),
                    )
                val outcome =
                    withTimeout(SEARCH_TIMEOUT_MS) {
                        search(before.localPort, RappMemoryVault(), instances).search(wrong)
                    }
                assertEquals(RappPairingSearch.Outcome.NotAccepted, outcome)
                withTimeout(SEARCH_TIMEOUT_MS) { refused.join() }
                assertFalse(withTimeout(SEARCH_TIMEOUT_MS) { sentAfterBootstrap.await() })
            } finally {
                before.close()
                after.close()
            }
        }

    @Test
    fun noPhoneInPairingModeIsFoundNone() =
        runBlocking {
            val code = RappPairingCode.generate()
            val outcome =
                withTimeout(SEARCH_TIMEOUT_MS) {
                    search(0, RappMemoryVault(), emptyList(), initialDiscoveryMs = EMPTY_SEARCH_GRACE_MS).search(code)
                }
            assertEquals(RappPairingSearch.Outcome.NoneFound, outcome)
        }
}
