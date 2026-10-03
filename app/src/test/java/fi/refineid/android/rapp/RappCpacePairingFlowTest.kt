// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber")

package fi.refineid.android.rapp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappPairingBridge
import uniffi.refineid_rapp.RappTransportCandidate
import java.io.File
import java.security.SecureRandom

class RappCpacePairingFlowTest {
    companion object {
        private const val STREAM_CANDIDATE_ID = "stream-1"
        private const val STREAM_PROFILE = "fi.refineid.stream.v1"
        private val EMPTY_CBOR_MAP = byteArrayOf(0xa0.toByte())
        private const val CPACE_RANDOM_BYTES = 64
        private var libraryFound: Boolean = false

        init {
            val libNames = listOf("librefineid_rapp.dylib", "librefineid_rapp.so", "refineid_rapp.dll")
            val candidate = findNativeLibrary(libNames)
            if (candidate != null) {
                libraryFound = true
                val parentDir = candidate.parentFile?.canonicalPath ?: candidate.parent ?: ""
                val existing = System.getProperty("jna.library.path")
                System.setProperty(
                    "jna.library.path",
                    if (existing != null) "$existing:$parentDir" else parentDir,
                )
                System.setProperty(
                    "uniffi.component.refineid_rapp.libraryOverride",
                    candidate.canonicalPath,
                )
            }
        }

        private fun findNativeLibrary(names: List<String>): File? {
            val jnaPath = System.getProperty("jna.library.path")
            if (!jnaPath.isNullOrBlank()) {
                val jnaDirs = jnaPath.split(File.pathSeparator).map { File(it) }
                for (dir in jnaDirs) {
                    for (name in names) {
                        val file = File(dir, name)
                        if (file.exists()) return file
                    }
                }
            }

            var dir: File? = File(".").canonicalFile
            while (dir != null) {
                val found =
                    names
                        .map { File(dir, "native/refineid-rapp-android/target/debug/$it") }
                        .firstOrNull { it.exists() }
                if (found != null) {
                    return found
                }
                dir = dir.parentFile
            }
            return null
        }
    }

    private val profiles =
        listOf(
            "fi.refineid.card-status.v1",
            "fi.refineid.authentication.v1",
            "fi.refineid.document-signing.v1",
        )

    private val candidates: List<RappTransportCandidate> =
        listOf(
            RappTransportCandidate(
                profile = STREAM_PROFILE,
                candidateId = STREAM_CANDIDATE_ID,
                parametersCbor = EMPTY_CBOR_MAP,
            ),
        )

    @Before
    fun setUp() {
        val isCi = System.getenv("CI") == "true" || System.getenv("GITHUB_ACTIONS") == "true"
        if (isCi) {
            assertTrue("RAPP native host library must be built and available on CI", libraryFound)
        } else {
            assumeTrue("RAPP native library available", libraryFound)
        }
    }

    @Test
    fun cpacePairingSucceedsBetweenRequesterAndProxy() {
        val code = RappPairingCode.generate()
        val nowMono = RappClock.monotonicMs()

        val requester =
            RappPairingBridge.createRequesterCodeOffer(
                pairingCode = code,
                profiles = profiles,
                transports = candidates,
                offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                startedAtMonotonicMs = nowMono,
            )
        val proxy =
            RappPairingBridge.fromProxyCodeOffer(
                pairingCode = code,
                profiles = profiles,
                transports = candidates,
                offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                startedAtMonotonicMs = nowMono,
            )

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

            val reqHello = requester.sendHello(displayName = "MacBook Pro", platform = "macOS")
            val proxyHello = proxy.sendHello(displayName = "Pixel Phone", platform = "Android")

            requester.receiveHello(proxyHello, RappClock.wallMs())
            proxy.receiveHello(reqHello, RappClock.wallMs())

            val proxyConfirm = proxy.sendConfirmation(profiles)
            val reqConfirm = requester.sendConfirmation(profiles)

            requester.receiveConfirmation(proxyConfirm, RappClock.wallMs())
            proxy.receiveConfirmation(reqConfirm, RappClock.wallMs())

            // 4. Session established with matching pair ID
            val reqPair = requester.finishPairing(RappClock.wallMs())
            val proxyPair = proxy.finishPairing(RappClock.wallMs())

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

        val requester =
            RappPairingBridge.createRequesterCodeOffer(
                pairingCode = correctCode,
                profiles = profiles,
                transports = candidates,
                offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                startedAtMonotonicMs = nowMono,
            )
        val proxy =
            RappPairingBridge.fromProxyCodeOffer(
                pairingCode = wrongCode,
                profiles = profiles,
                transports = candidates,
                offerTtlMs = RappPairingCode.DEFAULT_LIFETIME_MS.toULong(),
                startedAtMonotonicMs = nowMono,
            )

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
