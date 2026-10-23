// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCardReader
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * A paired computer that withdraws (RAPP v26.10.22 section 4.5 items 8 and
 * 9): its `service_withdrawn` close reaches this phone as the computer's
 * withdrawal, never as a violation, and this phone sends no close of its
 * own; the session and its operation end, the pairing stays, and the
 * pairing's next session opens.
 */
class RappPeerWithdrawalTest {
    private companion object {
        const val NOW = 1_000UL
        const val LIFETIME_MS = 120_000UL
        const val ORIGIN = "https://login.example.fi"
        const val CHALLENGE_TEXT = "synthetic login challenge"
        const val DIGEST_ALGORITHM = "SHA-384"
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication", "fi.refineid.document-signing")
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private val random = SecureRandom()

    private class Pairing(
        val requester: RappPairRecord,
        val requesterVault: RappMemoryVault,
        val custodian: RappPairRecord,
        val custodianVault: RappMemoryVault,
    )

    private fun pairing(): Pairing {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val pairing = Pairing(requester, RappMemoryVault(), custodian, RappMemoryVault())
        requester.persistDeviceOnly(pairing.requesterVault)
        custodian.persistDeviceOnly(pairing.custodianVault)
        return pairing
    }

    /** One established session of [pairing]: requester first, then this phone. */
    private fun establish(pairing: Pairing): Pair<RappOperationBridge, RappOperationBridge> {
        val requester =
            RappSessionBridge.beginRequester(pairing.requester, pairing.requesterVault, RappTestOffers.STREAM_PROFILE)
        val custodian =
            RappSessionBridge.beginProxy(pairing.custodian, pairing.custodianVault, RappTestOffers.STREAM_PROFILE)
        custodian.readHandshakeFrame(requester.writeHandshakeFrame())
        requester.readHandshakeFrame(custodian.writeHandshakeFrame())
        custodian.enterAuthentication()
        requester.enterAuthentication()
        val nonce = ByteArray(rappRandomByteCounts().sessionReadyNonce.toInt()).also(random::nextBytes)
        val ready = custodian.sendReady(nonce)
        custodian.enterEstablished()
        assertSame(RappBridgeOutcome.Idle, RappBridgeOutcome.from(requester.receiveReady(ready, NOW)))
        requester.enterEstablished()
        return RappOperationBridge.beginRequester(requester, LIFETIME_MS, NOW) to
            RappOperationBridge.beginProxy(custodian, LIFETIME_MS, NOW)
    }

    private fun send(call: () -> uniffi.refineid_rapp.RappBridgeAction): RappBridgeOutcome =
        RappBridgeOutcome.from(call())

    private fun RappBridgeOutcome.deliverTo(peer: RappOperationBridge): RappBridgeOutcome =
        RappBridgeOutcome.from(peer.receiveFrame((this as RappBridgeOutcome.Send).frame, NOW))

    /** The computer withdraws: its close, as this phone types it on receipt. */
    private fun withdraw(
        requester: RappOperationBridge,
        custodian: RappOperationBridge,
    ): RappBridgeOutcome.Closed {
        val notice = send { requester.closeWithReason(RappCloseReason.SERVICE_WITHDRAWN) }
        assertEquals(RappCloseReason.SERVICE_WITHDRAWN, (notice as RappBridgeOutcome.Send).closesWith)
        return notice.deliverTo(custodian) as RappBridgeOutcome.Closed
    }

    @Test
    fun theComputersWithdrawalClosesTheSessionWithNoViolationAndNoReply() {
        val (requester, custodian) = establish(pairing())

        assertEquals(RappCloseReason.SERVICE_WITHDRAWN, withdraw(requester, custodian).reason)

        val afterwards = send { custodian.closeWithReason(RappCloseReason.NORMAL) } as RappBridgeOutcome.Closed
        assertNull(afterwards.reason)
    }

    @Test
    fun theComputersWithdrawalEndsItsOperation() {
        val (requester, custodian) = establish(pairing())
        val operationId = RappOperationId.random(random)
        val digest = MessageDigest.getInstance(DIGEST_ALGORITHM).digest(CHALLENGE_TEXT.encodeToByteArray())
        val request =
            send {
                requester.beginBrowserAuthentication(
                    operationId.toWire(),
                    ORIGIN,
                    RappCardKeyProfile.ECDSA_P384,
                    RappSignatureAlgorithm.ECDSA_SHA384,
                    digest,
                    NOW,
                    LIFETIME_MS,
                )
            }
        assertTrue(request.deliverTo(custodian) is RappBridgeOutcome.Admitted)

        withdraw(requester, custodian)

        assertThrows(RappBindingException::class.java) {
            custodian.prerequisitesComplete(operationId.toWire(), NOW)
        }
    }

    @Test
    fun theComputersWithdrawalKeepsThePairingAndItsNextSessionOpens() {
        val pairing = pairing()
        val pairId = pairing.custodian.pairing().id
        val (requester, custodian) = establish(pairing)

        withdraw(requester, custodian)

        assertSame(RappPairState.Active, pairing.custodian.pairing().state)
        RappPairRecord.loadFromVault(pairId.toWire(), pairing.custodianVault).use { stored ->
            assertSame(RappPairState.Active, stored.pairing().state)
        }
        val (nextRequester, nextCustodian) = establish(pairing)
        val status = send { nextCustodian.reportCardStatus(null, RappCardReader.ABSENT) }.deliverTo(nextRequester)
        assertTrue(status is RappBridgeOutcome.CardStatus)
    }
}
