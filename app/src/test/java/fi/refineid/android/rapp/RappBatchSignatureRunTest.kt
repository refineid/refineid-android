// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappLivenessConfiguration
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappOperationKind
import uniffi.refineid_rapp.RappOperationVault
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappResultKind
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.RappStoredProxyJournal
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class RappBatchSignatureRunTest {
    private val digests = List(DOCUMENT_COUNT) { index -> ByteArray(SHA256_BYTES) { index.toByte() } }

    private fun fakeSignature(digest: ByteArray) = ByteArray(SIGNATURE_BYTES) { digest.first() }

    @Test
    fun signsEveryDocumentInOrderAndRecordsEachBeforeTheNext() =
        runBlocking {
            val events = mutableListOf<String>()
            val outcome =
                RappBatchSignatureRun(
                    digests = digests,
                    sign = { digest ->
                        events += "sign ${digest.first()}"
                        RappBatchSignatureRun.Step.Signed(fakeSignature(digest))
                    },
                    record = { signature -> events += "record ${signature.first()}" },
                ).run()
            assertSame(RappBatchSignatureRun.Outcome.Completed, outcome)
            assertEquals(listOf("sign 0", "record 0", "sign 1", "record 1", "sign 2", "record 2"), events)
        }

    @Test
    fun stopsAtTheFirstUnsignedDocumentAndNeverSignsAgain() =
        runBlocking {
            val signed = mutableListOf<Byte>()
            val failure = QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE)
            val outcome =
                RappBatchSignatureRun(
                    digests = digests,
                    sign = { digest ->
                        signed += digest.first()
                        if (digest.first() == SECOND_DOCUMENT) {
                            RappBatchSignatureRun.Step.Failed(failure)
                        } else {
                            RappBatchSignatureRun.Step.Signed(fakeSignature(digest))
                        }
                    },
                    record = {},
                ).run()
            assertTrue(outcome is RappBatchSignatureRun.Outcome.Stopped)
            outcome as RappBatchSignatureRun.Outcome.Stopped
            assertEquals(1, outcome.signedCount)
            assertSame(failure, outcome.failure)
            assertEquals(listOf<Byte>(0, SECOND_DOCUMENT), signed)
        }

    /** Host-bridge round trips through refineid-core's batch operation. */
    class Bridge {
        @Before
        fun setUp() {
            RappNativeTestLibrary.require()
        }

        private val digests = List(DOCUMENT_COUNT) { index -> ByteArray(SHA256_BYTES) { index.toByte() } }
        private val names = List(DOCUMENT_COUNT) { index -> "Document $index.pdf" }

        private class MemoryVault :
            RappPairVault,
            RappOperationVault {
            private val pairs = ConcurrentHashMap<String, ByteArray>()
            private val requester = ConcurrentHashMap<String, ByteArray>()
            private val proxy = ConcurrentHashMap<String, RappStoredProxyJournal>()

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
            ) {
                proxy[hex(operationId)] = RappStoredProxyJournal(record.copyOf(), null)
            }

            override fun persistProxyResult(
                pairId: ByteArray,
                operationId: ByteArray,
                record: ByteArray,
                result: ByteArray,
            ) {
                proxy[hex(operationId)] = RappStoredProxyJournal(record.copyOf(), result.copyOf())
            }

            override fun retainProxyUncertain(
                pairId: ByteArray,
                operationId: ByteArray,
                record: ByteArray,
            ) {
                val current = proxy[hex(operationId)]
                proxy[hex(operationId)] = RappStoredProxyJournal(record.copyOf(), current?.retainedResult)
            }

            override fun acknowledgeProxyResult(
                pairId: ByteArray,
                operationId: ByteArray,
                record: ByteArray,
            ) {
                proxy[hex(operationId)] = RappStoredProxyJournal(record.copyOf(), null)
            }

            override fun loadProxy(pairId: ByteArray): List<RappStoredProxyJournal> = proxy.values.toList()
        }

        private fun random(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

        private fun session(): Pair<RappOperationBridge, RappOperationBridge> {
            val (requesterPair, custodianPair) = RappTestOffers.pairRecords(PROFILES, NOW)
            val requesterVault = MemoryVault()
            val custodianVault = MemoryVault()
            requesterPair.persistDeviceOnly(requesterVault)
            custodianPair.persistDeviceOnly(custodianVault)
            return session(requesterPair, requesterVault, custodianPair, custodianVault)
        }

        private fun session(
            requesterPair: RappPairRecord,
            requesterVault: MemoryVault,
            custodianPair: RappPairRecord,
            custodianVault: MemoryVault,
        ): Pair<RappOperationBridge, RappOperationBridge> {
            val requester =
                RappSessionBridge.beginRequester(
                    requesterPair,
                    requesterVault,
                    RappTestOffers.STREAM_PROFILE,
                )
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

        /** Brings a batch request to the custodian's single card command. */
        private fun approvedBatch(
            requester: RappOperationBridge,
            custodian: RappOperationBridge,
            operationId: ByteArray,
        ) {
            val request =
                requester.beginBatchSignDocuments(
                    operationId,
                    names,
                    RappCardKeyProfile.ECDSA_P256,
                    RappSignatureAlgorithm.ECDSA_SHA256,
                    digests,
                    NOW,
                    LIFETIME_MS,
                )
            val inspect = custodian.receiveFrame(checkNotNull(request.frame), NOW)
            assertEquals(RappBridgeActionKind.INSPECT_PREREQUISITES, inspect.kind)
            val consent = custodian.prerequisitesComplete(operationId)
            val descriptor = checkNotNull(consent.operation)
            assertEquals(RappOperationKind.BATCH_SIGN_DOCUMENTS, descriptor.kind)
            assertEquals(names, descriptor.documentNames)
            val command = custodian.approve(operationId, NOW)
            assertEquals(RappBridgeActionKind.EXECUTE_CARD_COMMAND, command.kind)
        }

        private fun signature(index: Int) = ByteArray(SIGNATURE_BYTES) { index.toByte() }

        @Test
        fun aCompletedBatchDeliversEverySignatureInOrder() {
            val (requester, custodian) = session()
            val operationId = random(OPERATION_ID_BYTES)
            approvedBatch(requester, custodian, operationId)

            val outcome =
                runBlocking {
                    RappBatchSignatureRun(
                        digests = digests,
                        sign = { digest -> RappBatchSignatureRun.Step.Signed(signature(digest.first().toInt())) },
                        record = { signature -> custodian.recordBatchSignature(operationId, signature) },
                    ).run()
                }
            assertSame(RappBatchSignatureRun.Outcome.Completed, outcome)
            val result = custodian.completeBatch(operationId)
            val delivered = requester.receiveFrame(checkNotNull(result.frame), NOW)
            assertEquals(RappBridgeActionKind.RESULT_ACKNOWLEDGMENT, delivered.kind)
            val signatures = requester.acknowledgmentReleased(operationId)
            assertEquals(RappResultKind.SIGNATURES, signatures.kind)
            assertEquals(DOCUMENT_COUNT, signatures.signatures.size)
            signatures.signatures.forEachIndexed { index, bytes -> assertArrayEquals(signature(index), bytes) }
        }

        @Test
        fun anInterruptedBatchAnswersAmbiguousWithTheSignaturesMadeSoFar() {
            val (requester, custodian) = session()
            val operationId = random(OPERATION_ID_BYTES)
            approvedBatch(requester, custodian, operationId)

            val outcome =
                runBlocking {
                    RappBatchSignatureRun(
                        digests = digests,
                        sign = { digest ->
                            if (digest.first() == SECOND_DOCUMENT) {
                                RappBatchSignatureRun.Step.Failed(null)
                            } else {
                                RappBatchSignatureRun.Step.Signed(signature(digest.first().toInt()))
                            }
                        },
                        record = { signature -> custodian.recordBatchSignature(operationId, signature) },
                    ).run()
                }
            assertTrue(outcome is RappBatchSignatureRun.Outcome.Stopped)
            assertNull((outcome as RappBatchSignatureRun.Outcome.Stopped).failure)
            val result = custodian.cardCompletionAmbiguous(operationId)
            val terminal = requester.receiveFrame(checkNotNull(result.frame), NOW)
            assertEquals(RappBridgeActionKind.TERMINAL, terminal.kind)
            assertEquals(1, terminal.batchSignatures.size)
            assertArrayEquals(signature(0), terminal.batchSignatures.single())
        }
    }

    private companion object {
        const val DOCUMENT_COUNT = 3
        const val SECOND_DOCUMENT: Byte = 1
        const val SHA256_BYTES = 32
        const val SIGNATURE_BYTES = 64
        const val SESSION_NONCE_BYTES = 32
        const val OPERATION_ID_BYTES = 16
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
