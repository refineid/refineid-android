// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber")

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import java.security.SecureRandom

class RappCpacePairingFlowTest {
    companion object {
        private const val STREAM_CANDIDATE_ID = RappTestOffers.STREAM_CANDIDATE_ID
        private const val CPACE_RANDOM_BYTES = 64
    }

    private val profiles =
        listOf(
            "fi.refineid.card-status.v1",
            "fi.refineid.authentication.v1",
            "fi.refineid.document-signing.v1",
        )

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    @Test
    fun cpacePairingSucceedsBetweenRequesterAndProxy() {
        val code = RappPairingCode.generate()
        val nowMono = RappClock.monotonicMs()

        val (proxy, requester) = RappTestOffers.custodianAndRequester(profiles, nowMono)

        val randomReq = ByteArray(CPACE_RANDOM_BYTES).apply { SecureRandom().nextBytes(this) }
        val randomProxy = ByteArray(CPACE_RANDOM_BYTES).apply { SecureRandom().nextBytes(this) }

        try {
            requester.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = code,
                randomBytes64 = randomReq,
                nowMonotonicMs = RappClock.monotonicMs(),
            )
            proxy.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = code,
                randomBytes64 = randomProxy,
                nowMonotonicMs = RappClock.monotonicMs(),
            )

            // 1. CPace KC2 3-step mutual exchange
            // Step 1: Requester -> Custodian/Proxy (YA, 32 bytes)
            val reqStep1Frame = requester.writeCpaceFrame(RappClock.monotonicMs())
            proxy.readCpaceFrame(reqStep1Frame, RappClock.monotonicMs())

            // Step 2: Custodian/Proxy -> Requester (YB || TB, 64 bytes)
            val proxyStep2Frame = proxy.writeCpaceFrame(RappClock.monotonicMs())
            requester.readCpaceFrame(proxyStep2Frame, RappClock.monotonicMs())

            // Step 3: Requester -> Custodian/Proxy (TA, 32 bytes)
            // Writing step3 transitions Requester to Handshake
            val reqStep3Frame = requester.writeCpaceFrame(RappClock.monotonicMs())
            // Reading step3 transitions Proxy to Handshake
            proxy.readCpaceFrame(reqStep3Frame, RappClock.monotonicMs())

            // 2. Noise handshake
            val h1 = requester.writeHandshakeFrame(RappClock.monotonicMs())
            proxy.readHandshakeFrame(h1, RappClock.monotonicMs())

            val h2 = proxy.writeHandshakeFrame(RappClock.monotonicMs())
            requester.readHandshakeFrame(h2, RappClock.monotonicMs())

            val h3 = requester.writeHandshakeFrame(RappClock.monotonicMs())
            proxy.readHandshakeFrame(h3, RappClock.monotonicMs())

            assertTrue(requester.handshakeComplete(RappClock.monotonicMs()))
            assertTrue(proxy.handshakeComplete(RappClock.monotonicMs()))

            // 3. Bilateral confirmation
            requester.enterConfirmation(RappClock.monotonicMs())
            proxy.enterConfirmation(RappClock.monotonicMs())

            val reqHello = requester.sendHello("MacBook Pro", "macOS", RappClock.monotonicMs())
            val proxyHello = proxy.sendHello("Pixel Phone", "Android", RappClock.monotonicMs())

            requester.receiveHello(proxyHello, RappClock.monotonicMs())
            proxy.receiveHello(reqHello, RappClock.monotonicMs())

            val proxyConfirm = proxy.sendConfirmation(profiles, RappClock.monotonicMs())
            val reqConfirm = requester.sendConfirmation(profiles, RappClock.monotonicMs())

            requester.receiveConfirmation(proxyConfirm, RappClock.monotonicMs())
            proxy.receiveConfirmation(reqConfirm, RappClock.monotonicMs())

            // 4. Session established with matching pair ID
            val reqPair = requester.finishPairing(RappClock.wallMs(), RappClock.monotonicMs())
            val proxyPair = proxy.finishPairing(RappClock.wallMs(), RappClock.monotonicMs())

            assertArrayEquals(reqPair.metadata().pairId, proxyPair.metadata().pairId)
        } finally {
            randomReq.fill(0)
            randomProxy.fill(0)
        }
    }

    @Test
    fun cpacePairingFailsWithWrongPairingCode() {
        val correctCode = RappPairingCode.generate()
        val wrongCode = RappPairingCode.generate()
        val nowMono = RappClock.monotonicMs()

        val (proxy, requester) = RappTestOffers.custodianAndRequester(profiles, nowMono)

        val randomReq = ByteArray(CPACE_RANDOM_BYTES).apply { SecureRandom().nextBytes(this) }
        val randomProxy = ByteArray(CPACE_RANDOM_BYTES).apply { SecureRandom().nextBytes(this) }

        try {
            requester.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = correctCode,
                randomBytes64 = randomReq,
                nowMonotonicMs = RappClock.monotonicMs(),
            )
            proxy.beginCpace(
                candidateId = STREAM_CANDIDATE_ID,
                pairingCode = wrongCode,
                randomBytes64 = randomProxy,
                nowMonotonicMs = RappClock.monotonicMs(),
            )

            // Step 1: Requester -> Proxy
            val reqStep1Frame = requester.writeCpaceFrame(RappClock.monotonicMs())
            proxy.readCpaceFrame(reqStep1Frame, RappClock.monotonicMs())

            // Step 2: Proxy -> Requester
            val proxyStep2Frame = proxy.writeCpaceFrame(RappClock.monotonicMs())

            // CPace KC2 verification: Requester reading Step 2 must fail tag verification
            // because different pairing codes produce different shared keys and tags
            assertThrows(RappBindingException::class.java) {
                requester.readCpaceFrame(proxyStep2Frame, RappClock.monotonicMs())
            }
        } finally {
            randomReq.fill(0)
            randomProxy.fill(0)
        }
    }
}
