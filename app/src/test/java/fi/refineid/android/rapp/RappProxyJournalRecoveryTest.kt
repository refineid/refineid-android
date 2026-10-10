// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappLivenessConfiguration
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappOperationVault
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.RappStoredProxyJournal
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator

/**
 * The custodian's process dies after the in-flight entry is written and
 * before the card answers. A fresh process recovers the operation from disk
 * as ambiguous and never offers it again (RAPP v26.10.1 section 8.3).
 */
class RappProxyJournalRecoveryTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val key = KeyGenerator.getInstance("AES").apply { init(AesGcmJournalSealer.KEY_BITS) }.generateKey()

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    /** Pair records stay in memory across the simulated restart, as preferences do on a device. */
    private class TestVault(
        private val journal: RappProxyJournalStore?,
        private val pairs: MutableMap<String, ByteArray>,
    ) : RappPairVault,
        RappOperationVault {
        private val requester = ConcurrentHashMap<String, ByteArray>()

        private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

        override fun insertDeviceOnly(
            pairId: ByteArray,
            record: ByteArray,
        ) {
            pairs[hex(pairId)] = record.copyOf()
        }

        override fun loadDeviceOnly(pairId: ByteArray): ByteArray? = pairs[hex(pairId)]?.copyOf()

        override fun revokeDeviceOnly(
            pairId: ByteArray,
            revokedAtMs: ULong,
        ) {
            pairs.remove(hex(pairId))
            journal?.purge(pairId)
        }

        override fun isRevoked(pairId: ByteArray): Boolean = false

        override fun persistRequester(
            pairId: ByteArray,
            operationId: ByteArray,
            record: ByteArray,
        ) {
            requester[hex(operationId)] = record.copyOf()
        }

        override fun loadRequester(pairId: ByteArray): List<ByteArray> = requester.values.toList()

        override fun persistProxy(
            pairId: ByteArray,
            operationId: ByteArray,
            record: ByteArray,
        ) = checkNotNull(journal).persist(pairId, operationId, record)

        override fun persistProxyResult(
            pairId: ByteArray,
            operationId: ByteArray,
            record: ByteArray,
            result: ByteArray,
        ) = checkNotNull(journal).persistWithResult(pairId, operationId, record, result)

        override fun retainProxyUncertain(
            pairId: ByteArray,
            operationId: ByteArray,
            record: ByteArray,
        ) = checkNotNull(journal).retainUncertain(pairId, operationId, record)

        override fun acknowledgeProxyResult(
            pairId: ByteArray,
            operationId: ByteArray,
            record: ByteArray,
        ) = checkNotNull(journal).acknowledge(pairId, operationId, record)

        override fun loadProxy(pairId: ByteArray): List<RappStoredProxyJournal> = checkNotNull(journal).load(pairId)
    }

    private fun journal(root: File) = RappProxyJournalStore(root, AesGcmJournalSealer { key })

    private fun random(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    private fun pair(): Pair<RappPairRecord, RappPairRecord> = RappTestOffers.pairRecords(PROFILES, NOW)

    private fun session(
        requesterPair: RappPairRecord,
        requesterVault: TestVault,
        custodianPair: RappPairRecord,
        custodianVault: TestVault,
    ): Pair<RappOperationBridge, RappOperationBridge> {
        val requester = RappSessionBridge.beginRequester(requesterPair, requesterVault, RappTestOffers.STREAM_PROFILE)
        val custodian = RappSessionBridge.beginProxy(custodianPair, custodianVault, RappTestOffers.STREAM_PROFILE)
        custodian.readHandshakeFrame(requester.writeHandshakeFrame())
        val handshakeTwo = custodian.writeHandshakeFrame()
        custodian.enterAuthentication()
        val custodianReady = custodian.sendReady(random(SESSION_NONCE_BYTES))
        requester.readHandshakeFrame(handshakeTwo)
        requester.enterAuthentication()
        val requesterReady = requester.sendReady(random(SESSION_NONCE_BYTES))
        requester.receiveReady(custodianReady, WALL)
        custodian.receiveReady(requesterReady, WALL)
        requester.enterEstablished()
        custodian.enterEstablished()
        return RappOperationBridge.beginRequester(requester, requesterVault, LIFETIME_MS, LIVENESS, NOW) to
            RappOperationBridge.beginProxy(custodian, custodianVault, LIFETIME_MS, LIVENESS, NOW)
    }

    @Test
    fun aCommandInterruptedByProcessDeathRecoversAsAmbiguous() {
        val root = folder.newFolder("journal")
        val (requesterPair, custodianPair) = pair()
        val pairId = custodianPair.metadata().pairId
        val custodianPairs = ConcurrentHashMap<String, ByteArray>()
        val requesterVault = TestVault(null, ConcurrentHashMap())
        val firstVault = TestVault(journal(root), custodianPairs)
        custodianPair.persistDeviceOnly(firstVault)
        requesterPair.persistDeviceOnly(requesterVault)

        val (requester, custodian) = session(requesterPair, requesterVault, custodianPair, firstVault)
        val operationId = random(OPERATION_ID_BYTES)
        val request =
            requester.beginBrowserAuthentication(
                operationId,
                "https://login.example.test",
                RappCardKeyProfile.ECDSA_P256,
                RappSignatureAlgorithm.ECDSA_SHA256,
                ByteArray(SHA256_BYTES),
                NOW,
                LIFETIME_MS,
            )
        val inspect = custodian.receiveFrame(checkNotNull(request.frame), NOW)
        assertEquals(RappBridgeActionKind.INSPECT_PREREQUISITES, inspect.kind)
        custodian.prerequisitesComplete(operationId)
        val command = custodian.approve(operationId, NOW)
        assertEquals(RappBridgeActionKind.EXECUTE_CARD_COMMAND, command.kind)

        // The process dies here: no result, no close. Only the files remain.
        val afterRestart = journal(root)
        assertEquals("in-flight entry is durable", 1, afterRestart.load(pairId).size)
        val secondVault = TestVault(afterRestart, custodianPairs)
        val reloadedCustodianPair = RappPairRecord.loadFromVault(pairId, secondVault)
        val reloadedRequesterPair = RappPairRecord.loadFromVault(requesterPair.metadata().pairId, requesterVault)
        session(reloadedRequesterPair, requesterVault, reloadedCustodianPair, secondVault)

        val recovered = journal(root).load(pairId).single()
        assertTrue(
            "recovery records the interrupted command as ambiguous",
            recovered.record.toString(Charsets.ISO_8859_1).contains("ambiguous"),
        )
    }

    private companion object {
        const val STREAM_CANDIDATE_ID = "stream-1"
        const val CPACE_RANDOM_BYTES = 64
        const val SESSION_NONCE_BYTES = 32
        const val OPERATION_ID_BYTES = 16
        const val SHA256_BYTES = 32
        const val NOW = 1_000UL
        const val WALL = 1_700_000_000_000UL
        const val LIFETIME_MS = 120_000UL
        val PROFILES =
            listOf(
                "fi.refineid.card-status.v1",
                "fi.refineid.authentication.v1",
                "fi.refineid.document-signing.v1",
            )
        val LIVENESS =
            RappLivenessConfiguration(
                baseIntervalMs = 5_000UL,
                responseTimeoutMs = 10_000UL,
                maximumIntervalMs = 60_000UL,
                maximumJitterMs = 500UL,
                maximumMisses = 3.toUByte(),
            )
    }
}
