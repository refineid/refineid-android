// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappResultKind
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.RappTerminalReason
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.MessageDigest
import java.security.SecureRandom

class RappBatchSignatureRunTest {
    private companion object {
        const val DIGEST_ALGORITHM = "SHA-256"
        val DOCUMENT_NAMES = listOf("First.pdf", "Second.pdf", "Third.pdf")
        const val NOW = 1_000UL
        const val LIFETIME_MS = 120_000UL
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication", "fi.refineid.document-signing")
        val RANDOM_BYTE_COUNTS = rappRandomByteCounts()

        /** The synthetic digest of the document named [name]. */
        fun digest(name: String): ByteArray =
            MessageDigest.getInstance(DIGEST_ALGORITHM).digest(name.encodeToByteArray())

        /** A synthetic signature that names the document it signs. */
        fun signature(name: String): ByteArray = "signature of $name".encodeToByteArray()
    }

    private val digests = DOCUMENT_NAMES.map(::digest)

    private fun signatureOf(digest: ByteArray): ByteArray =
        signature(DOCUMENT_NAMES[digests.indexOfFirst { it.contentEquals(digest) }])

    @Test
    fun signsEveryDocumentInOrderAndRecordsEachBeforeTheNext() =
        runBlocking {
            val events = mutableListOf<String>()
            val outcome =
                RappBatchSignatureRun(
                    digests = digests,
                    sign = { digest ->
                        events += "sign " + signatureOf(digest).decodeToString()
                        RappBatchSignatureRun.Step.Signed(signatureOf(digest))
                    },
                    record = { signature -> events += "record " + signature.decodeToString() },
                ).run()
            assertSame(RappBatchSignatureRun.Outcome.Completed, outcome)
            assertEquals(
                DOCUMENT_NAMES.flatMap { name -> listOf("sign signature of $name", "record signature of $name") },
                events,
            )
        }

    @Test
    fun stopsAtTheFirstUnsignedDocumentAndNeverSignsAgain() =
        runBlocking {
            val signed = mutableListOf<ByteArray>()
            val stopAt = digests[DOCUMENT_NAMES.indexOf("Second.pdf")]
            val outcome =
                RappBatchSignatureRun(
                    digests = digests,
                    sign = { digest ->
                        signed += digest
                        if (digest.contentEquals(stopAt)) {
                            RappBatchSignatureRun.Step.Failed(RappCardFailure.CARD_ERROR)
                        } else {
                            RappBatchSignatureRun.Step.Signed(signatureOf(digest))
                        }
                    },
                    record = {},
                ).run()
            outcome as RappBatchSignatureRun.Outcome.Stopped
            assertEquals(DOCUMENT_NAMES.indexOf("Second.pdf"), outcome.signedCount)
            assertSame(RappCardFailure.CARD_ERROR, outcome.failure)
            assertEquals(digests.take(signed.size).map { it.toList() }, signed.map { it.toList() })
        }

    /** Host-bridge round trips through refineid-core's batch operation. */
    class Bridge {
        @Before
        fun setUp() {
            RappNativeTestLibrary.require()
        }

        private val digests = DOCUMENT_NAMES.map(::digest)
        private val random = SecureRandom()

        private fun session(): Pair<RappOperationBridge, RappOperationBridge> {
            val (requesterPair, custodianPair) = RappTestOffers.pairRecords(PROFILES, NOW)
            val requesterVault = RappMemoryVault()
            val custodianVault = RappMemoryVault()
            requesterPair.persistDeviceOnly(requesterVault)
            custodianPair.persistDeviceOnly(custodianVault)
            val requester =
                RappSessionBridge.beginRequester(
                    requesterPair,
                    requesterVault,
                    RappTestOffers.STREAM_PROFILE,
                )
            val custodian = RappSessionBridge.beginProxy(custodianPair, custodianVault, RappTestOffers.STREAM_PROFILE)
            custodian.readHandshakeFrame(requester.writeHandshakeFrame())
            requester.readHandshakeFrame(custodian.writeHandshakeFrame())
            custodian.enterAuthentication()
            requester.enterAuthentication()
            val nonce = ByteArray(RANDOM_BYTE_COUNTS.sessionReadyNonce.toInt()).also(random::nextBytes)
            assertSame(
                RappBridgeOutcome.Idle,
                RappBridgeOutcome.from(requester.receiveReady(custodian.sendReady(nonce), NOW)),
            )
            custodian.enterEstablished()
            requester.enterEstablished()
            return RappOperationBridge.beginRequester(requester, LIFETIME_MS, NOW) to
                RappOperationBridge.beginProxy(custodian, LIFETIME_MS, NOW)
        }

        /** Brings a batch request to the custodian's single card command. */
        private fun approvedBatch(
            requester: RappOperationBridge,
            custodian: RappOperationBridge,
            operationId: RappOperationId,
        ) {
            val request =
                requester.beginBatchSignDocuments(
                    operationId.toWire(),
                    DOCUMENT_NAMES,
                    RappCardKeyProfile.ECDSA_P256,
                    RappSignatureAlgorithm.ECDSA_SHA256,
                    digests,
                    NOW,
                    LIFETIME_MS,
                )
            val admitted = RappBridgeOutcome.from(custodian.receiveFrame(checkNotNull(request.frame), NOW))
            assertTrue(admitted is RappBridgeOutcome.Admitted)
            val consent =
                RappBridgeOutcome.from(custodian.prerequisitesComplete(operationId.toWire(), NOW)) as
                    RappBridgeOutcome.AwaitApproval
            val batch = consent.request as RappRequest.BatchSignDocuments
            assertEquals(DOCUMENT_NAMES, batch.documents.map { it.name })
            val command = RappBridgeOutcome.from(custodian.approve(operationId.toWire(), NOW))
            assertTrue(command is RappBridgeOutcome.ExecuteCommand)
        }

        @Test
        fun aCompletedBatchDeliversEverySignatureInOrder() {
            val (requester, custodian) = session()
            val operationId = RappOperationId.random(random)
            approvedBatch(requester, custodian, operationId)

            val outcome =
                runBlocking {
                    RappBatchSignatureRun(
                        digests = digests,
                        sign = { digest ->
                            RappBatchSignatureRun.Step.Signed(signature(DOCUMENT_NAMES[digests.indexOf(digest)]))
                        },
                        record = { signature -> custodian.recordBatchSignature(operationId.toWire(), signature) },
                    ).run()
                }
            assertSame(RappBatchSignatureRun.Outcome.Completed, outcome)
            val result = custodian.completeBatch(operationId.toWire())
            val delivered = requester.receiveFrame(checkNotNull(result.frame), NOW)
            assertEquals(RappBridgeActionKind.COMPLETED, delivered.kind)
            val signatures = checkNotNull(delivered.result)
            assertEquals(RappResultKind.SIGNATURES, signatures.kind)
            DOCUMENT_NAMES.forEachIndexed { index, name ->
                assertArrayEquals(signature(name), signatures.signatures[index])
            }
        }

        @Test
        fun aStoppedBatchDeliversNoSignature() {
            val (requester, custodian) = session()
            val operationId = RappOperationId.random(random)
            approvedBatch(requester, custodian, operationId)
            custodian.recordBatchSignature(operationId.toWire(), signature(DOCUMENT_NAMES.first()))

            val result = RappBridgeOutcome.from(custodian.cardError(operationId.toWire()))
            val ended = RappBridgeOutcome.from(requester.receiveFrame((result as RappBridgeOutcome.Send).frame, NOW))
            assertEquals(RappTerminalReason.CARD_ERROR, (ended as RappBridgeOutcome.Terminal).reason)
        }
    }
}
