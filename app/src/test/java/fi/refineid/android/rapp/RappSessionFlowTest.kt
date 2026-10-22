// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBindingException
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappForgetOutcome
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.RappTerminalReason
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One RAPP v26.10.21 session between a requester and a custodian bridge,
 * read through the app's typed binding border: the custodian's ready, card
 * status, consent, reads, the retry floor, deadlines, liveness and the
 * pairing_revoked close.
 */
class RappSessionFlowTest {
    private companion object {
        const val NOW = 1_000UL
        const val WALL_MS = 1_700_000_000_000UL
        const val LIFETIME_MS = 120_000UL
        const val SHORT_LIFETIME_MS = 1_000UL

        /** Silence after which an endpoint pings, and after which the session ends (section 8.3). */
        const val PING_AFTER_SILENCE_MS = 5_000UL
        const val SESSION_SILENCE_LIMIT_MS = 30_000UL
        const val ORIGIN = "https://login.example.fi"
        const val CHALLENGE_TEXT = "synthetic login challenge"
        const val DIGEST_ALGORITHM = "SHA-384"
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication", "fi.refineid.document-signing")
        val RANDOM_BYTE_COUNTS = rappRandomByteCounts()
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private val random = SecureRandom()

    private fun random(size: ULong) = ByteArray(size.toInt()).also(random::nextBytes)

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

    /** Both ends of one session after `Noise_KK`, authentication not yet entered. */
    private fun handshake(pairing: Pairing): Pair<RappSessionBridge, RappSessionBridge> {
        val requester =
            RappSessionBridge.beginRequester(pairing.requester, pairing.requesterVault, RappTestOffers.STREAM_PROFILE)
        val custodian =
            RappSessionBridge.beginProxy(pairing.custodian, pairing.custodianVault, RappTestOffers.STREAM_PROFILE)
        custodian.readHandshakeFrame(requester.writeHandshakeFrame())
        requester.readHandshakeFrame(custodian.writeHandshakeFrame())
        return requester to custodian
    }

    /** An established session: the custodian sent `session.ready` and the requester verified it. */
    private fun establish(pairing: Pairing = pairing()): Pair<RappOperationBridge, RappOperationBridge> {
        val (requester, custodian) = handshake(pairing)
        custodian.enterAuthentication()
        requester.enterAuthentication()
        val ready = custodian.sendReady(random(RANDOM_BYTE_COUNTS.sessionReadyNonce))
        custodian.enterEstablished()
        assertSame(RappBridgeOutcome.Idle, RappBridgeOutcome.from(requester.receiveReady(ready, NOW)))
        requester.enterEstablished()
        return RappOperationBridge.beginRequester(requester, LIFETIME_MS, NOW) to
            RappOperationBridge.beginProxy(custodian, LIFETIME_MS, NOW)
    }

    /** Hands a sent frame to [peer] and types what it makes of it. */
    private fun RappBridgeOutcome.deliverTo(
        peer: RappOperationBridge,
        now: ULong = NOW,
    ): RappBridgeOutcome = RappBridgeOutcome.from(peer.receiveFrame((this as RappBridgeOutcome.Send).frame, now))

    private fun send(call: () -> uniffi.refineid_rapp.RappBridgeAction): RappBridgeOutcome =
        RappBridgeOutcome.from(call())

    private fun challengeDigest(): ByteArray =
        MessageDigest.getInstance(DIGEST_ALGORITHM).digest(CHALLENGE_TEXT.encodeToByteArray())

    /** Brings a browser authentication to the custodian's consent. */
    private fun consent(
        requester: RappOperationBridge,
        custodian: RappOperationBridge,
        operationId: RappOperationId,
        expiresAfterMs: ULong = LIFETIME_MS,
    ): RappBridgeOutcome {
        val request =
            send {
                requester.beginBrowserAuthentication(
                    operationId.toWire(),
                    ORIGIN,
                    RappCardKeyProfile.ECDSA_P384,
                    RappSignatureAlgorithm.ECDSA_SHA384,
                    challengeDigest(),
                    NOW,
                    expiresAfterMs,
                )
            }
        val admitted = request.deliverTo(custodian) as RappBridgeOutcome.Admitted
        assertEquals(operationId, admitted.operationId)
        return admitted
    }

    @Test
    fun cardStatusNamesThePresentCardByItsCertificateFingerprint() {
        val der = RappTestCertificate.der
        assumeTrue("OpenSSL makes the synthetic certificate", der != null)
        val certificate = checkNotNull(RappCertificate.fromDer(checkNotNull(der)))
        val (requester, custodian) = establish()

        val present = send { custodian.reportCardStatus(certificate.toWire()) }.deliverTo(requester)
        val status = (present as RappBridgeOutcome.CardStatus).status as RappCardStatus.Present
        assertEquals(RappCertificateFingerprint.of(certificate), status.fingerprint)

        val absent = send { custodian.reportCardStatus(null) }.deliverTo(requester)
        assertSame(RappCardStatus.Absent, (absent as RappBridgeOutcome.CardStatus).status)
    }

    @Test
    fun aReadSkipsConsentAndAnswersWithTheCertificate() {
        val der = RappTestCertificate.der
        assumeTrue("OpenSSL makes the synthetic certificate", der != null)
        val certificate = checkNotNull(RappCertificate.fromDer(checkNotNull(der)))
        val (requester, custodian) = establish()
        val operationId = RappOperationId.random(random)

        val request =
            send {
                requester.beginReadCertificate(
                    operationId = operationId.toWire(),
                    signatureCertificate = false,
                    localStartMs = NOW,
                    expiresAfterMs = LIFETIME_MS,
                )
            }
        assertTrue(request.deliverTo(custodian) is RappBridgeOutcome.Admitted)
        val read = send { custodian.prerequisitesComplete(operationId.toWire(), NOW) } as RappBridgeOutcome.ExecuteRead
        assertSame(RappRequest.ReadAuthenticationCertificate, read.request)

        val completed =
            send { custodian.completeCertificate(operationId.toWire(), certificate.toWire()) }.deliverTo(requester)
        completed as RappBridgeOutcome.Completed
        assertEquals(operationId, completed.operationId)
        assertEquals(certificate, (completed.answer as RappAnswer.Certificate).certificate)
    }

    @Test
    fun anAuthenticationAwaitsConsentAndEndsAtTheRetryFloor() {
        val (requester, custodian) = establish()
        val operationId = RappOperationId.random(random)
        consent(requester, custodian, operationId)

        val shown =
            send {
                custodian.prerequisitesComplete(
                    operationId.toWire(),
                    NOW,
                )
            } as RappBridgeOutcome.AwaitConsent
        val asked = shown.request as RappRequest.BrowserAuthenticate
        assertEquals(ORIGIN, asked.origin)
        assertTrue(asked.digest.contentEquals(challengeDigest()))

        val command = send { custodian.approve(operationId.toWire(), NOW) } as RappBridgeOutcome.ExecuteCommand
        assertTrue(command.request is RappRequest.BrowserAuthenticate)
        val ended = send { custodian.retryFloor(operationId.toWire()) }.deliverTo(requester)
        assertEquals(RappTerminalReason.RETRY_FLOOR, (ended as RappBridgeOutcome.Terminal).reason)
    }

    @Test
    fun aDeclinedRequestEndsAsUserCancelledAndTheSessionStays() {
        val (requester, custodian) = establish()
        val first = RappOperationId.random(random)
        consent(requester, custodian, first)
        send { custodian.prerequisitesComplete(first.toWire(), NOW) }
        val ended = send { custodian.deny(first.toWire()) }.deliverTo(requester)
        assertEquals(RappTerminalReason.USER_CANCELLED, (ended as RappBridgeOutcome.Terminal).reason)

        consent(requester, custodian, RappOperationId.random(random))
    }

    @Test
    fun aRequestPastItsDeadlineIsCancelledBeforeConsent() {
        val (requester, custodian) = establish()
        val operationId = RappOperationId.random(random)
        consent(requester, custodian, operationId, expiresAfterMs = SHORT_LIFETIME_MS)

        val afterDeadline = NOW + SHORT_LIFETIME_MS + SHORT_LIFETIME_MS
        val cancelled = send { custodian.prerequisitesComplete(operationId.toWire(), afterDeadline) }
        assertTrue(cancelled is RappBridgeOutcome.Send)
        val ended = cancelled.deliverTo(requester, afterDeadline)
        assertEquals(RappTerminalReason.OPERATION_EXPIRED, (ended as RappBridgeOutcome.Terminal).reason)
    }

    @Test
    fun aForgottenPairingSendsItsCloseInPlaceOfReady() {
        val pairing = pairing()
        assertEquals(RappForgetOutcome.NOTICE_PENDING, pairing.custodian.forget(pairing.custodianVault, WALL_MS))
        assertTrue(pairing.custodian.pairing().state is RappPairState.Forgotten)
        val (requester, custodian) = handshake(pairing)
        custodian.enterAuthentication()
        assertThrows(RappBindingException::class.java) {
            custodian.sendReady(random(RANDOM_BYTE_COUNTS.sessionReadyNonce))
        }

        val notice = custodian.deliverRevocationNotice()
        requester.enterAuthentication()
        val closed = RappBridgeOutcome.from(requester.receiveReady(notice, NOW))
        assertEquals(RappCloseReason.PAIRING_REVOKED, (closed as RappBridgeOutcome.Closed).reason)
    }

    @Test
    fun forgettingDuringASessionClosesItAsRevoked() {
        val (requester, custodian) = establish()
        val close = send { custodian.closeWithReason(RappCloseReason.PAIRING_REVOKED) }
        assertEquals(RappCloseReason.PAIRING_REVOKED, (close as RappBridgeOutcome.Send).closesWith)
        val closed = close.deliverTo(requester)
        assertEquals(RappCloseReason.PAIRING_REVOKED, (closed as RappBridgeOutcome.Closed).reason)
    }

    @Test
    fun silenceIsPingedAndThenEndsTheSession() {
        val (_, custodian) = establish()
        val ping =
            send { custodian.pollLiveness(NOW + PING_AFTER_SILENCE_MS, random(RANDOM_BYTE_COUNTS.livenessChallenge)) }
        assertTrue(ping is RappBridgeOutcome.Send)
        val ended =
            send {
                custodian.pollLiveness(
                    NOW + SESSION_SILENCE_LIMIT_MS,
                    random(RANDOM_BYTE_COUNTS.livenessChallenge),
                )
            }
        assertTrue(ended is RappBridgeOutcome.Closed)
    }
}
