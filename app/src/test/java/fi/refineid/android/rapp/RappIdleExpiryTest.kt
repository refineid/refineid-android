// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappPairMetadata
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappVaultException
import uniffi.refineid_rapp.rappPairingIdleExpiryMs
import uniffi.refineid_rapp.rappRandomByteCounts
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/**
 * Idle expiry of the pairings this phone serves (RAPP v26.10.29 section 4.6
 * item 5; core STPA CC-103): a session is recorded when it is established
 * and when it ends, a pairing with no established session for 30 days is
 * forgotten silently and owes its computer only the `pairing_revoked`
 * close, a pairing in session never expires, a sweep whose store failed
 * changes nothing and the next repeats it, and a record the core refuses is
 * removed once.
 */
class RappIdleExpiryTest {
    private companion object {
        const val NOW = 1_000UL
        const val DISPLAY_NAME = "Workstation"
        const val PLATFORM = "Windows"
        val PROFILES = listOf("fi.refineid.card-status", "fi.refineid.authentication")
        val IDLE_EXPIRY_MS = rappPairingIdleExpiryMs()

        /** How long before a limit the pairing is still kept. */
        const val MARGIN_MINUTES = 1L
        val MARGIN_MS = TimeUnit.MINUTES.toMillis(MARGIN_MINUTES).toULong()

        /** When, after the pairing's creation, its one session is established. */
        const val SESSION_AFTER_DAYS = 10L
        val SESSION_AFTER_MS = TimeUnit.DAYS.toMillis(SESSION_AFTER_DAYS).toULong()

        /** How long that session stays established. */
        const val SESSION_HOURS = 2L
        val SESSION_LENGTH_MS = TimeUnit.HOURS.toMillis(SESSION_HOURS).toULong()

        /** How many idle limits a session held open outlasts. */
        const val HELD_OPEN_LIMITS = 2UL

        const val UNDECODABLE_RECORD = "synthetic record in a format the core refuses"
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    /**
     * A vault that refuses the next [refusals] record replacements and
     * otherwise keeps records as [RappMemoryVault] does.
     */
    private class RefusingVault(
        var refusals: Int,
        private val memory: RappMemoryVault = RappMemoryVault(),
    ) : RappPairVault by memory {
        override fun replaceDeviceOnly(
            pairId: ByteArray,
            record: ByteArray,
        ) {
            if (refusals > 0) {
                refusals -= 1
                throw RappVaultException.Unavailable()
            }
            memory.replaceDeviceOnly(pairId, record)
        }
    }

    /** One pairing as this phone stores and catalogues it, with the computer's side beside it. */
    private class Served(
        val requester: RappPairRecord,
        val requesterVault: RappMemoryVault,
        val custodian: RappPairRecord,
        val vault: RappPairVault,
        val catalog: RappPairCatalog,
        val pairId: RappPairId,
        val createdAtMs: ULong,
    )

    private fun served(vault: RappPairVault = RappMemoryVault()): Served {
        val (requester, custodian) = RappTestOffers.pairRecords(PROFILES, NOW)
        val requesterVault = RappMemoryVault()
        requester.persistDeviceOnly(requesterVault)
        custodian.persistDeviceOnly(vault)
        val pairId = custodian.pairing().id
        val createdAtMs = custodian.metadata().createdAtMs
        val catalog = RappPairCatalog(FakeSharedPreferences())
        catalog.savePair(pairId.toWire(), DISPLAY_NAME, PLATFORM, createdAtMs.toLong())
        return Served(requester, requesterVault, custodian, vault, catalog, pairId, createdAtMs)
    }

    private fun Served.sweep(
        nowMs: ULong,
        session: RappServedSession? = null,
    ): List<RappPairId> = RappIdleExpiry.sweep(catalog, vault, nowMs, session)

    /** The pairing's record as the vault holds it now. */
    private fun Served.stored(): RappPairMetadata =
        RappPairRecord.loadFromVault(pairId.toWire(), vault).use { it.metadata() }

    /** Both ends of one session after `Noise_KK`, this phone on [record]. */
    private fun Served.handshake(record: RappPairRecord): Pair<RappSessionBridge, RappSessionBridge> {
        val computer = RappSessionBridge.beginRequester(requester, requesterVault, RappTestOffers.STREAM_PROFILE)
        val phone = RappSessionBridge.beginProxy(record, vault, RappTestOffers.STREAM_PROFILE)
        phone.readHandshakeFrame(computer.writeHandshakeFrame())
        computer.readHandshakeFrame(phone.writeHandshakeFrame())
        phone.enterAuthentication()
        computer.enterAuthentication()
        return computer to phone
    }

    @Test
    fun aSessionIsRecordedWhenEstablishedAndWhenItEnds() {
        val served = served()
        val (computer, phone) = served.handshake(served.custodian)
        val nonce = ByteArray(rappRandomByteCounts().sessionReadyNonce.toInt()).also(SecureRandom()::nextBytes)
        computer.receiveReady(phone.sendReady(nonce), NOW)
        phone.enterEstablished()

        val startMs = served.createdAtMs + SESSION_AFTER_MS
        RappIdleExpiry.recordSession(served.custodian, served.vault, startMs)
        assertEquals(startMs, served.stored().lastSessionAtMs)
        val endMs = startMs + SESSION_LENGTH_MS
        RappIdleExpiry.recordSession(served.custodian, served.vault, endMs)
        assertEquals(endMs, served.stored().lastSessionAtMs)
        phone.close()
        computer.close()
        served.custodian.close()

        assertTrue(served.sweep(startMs + IDLE_EXPIRY_MS).isEmpty())
        assertEquals(listOf(served.pairId), served.sweep(endMs + IDLE_EXPIRY_MS))
    }

    @Test
    fun aPairingIdleForThirtyDaysIsForgottenAndOwesOnlyItsClose() {
        val served = served()
        served.custodian.close()
        val limitMs = served.createdAtMs + IDLE_EXPIRY_MS

        assertTrue(served.sweep(limitMs - MARGIN_MS).isEmpty())
        assertEquals(
            served.pairId.key,
            served.catalog
                .listPairs()
                .single()
                .pairIdHex,
        )

        assertEquals(listOf(served.pairId), served.sweep(limitMs))
        assertTrue(served.catalog.listPairs().isEmpty())
        assertEquals(
            limitMs.toLong(),
            served.catalog
                .forgottenPairs()
                .single()
                .forgottenAtMs,
        )
        assertEquals(limitMs, served.stored().forgottenAtMs)
        assertTrue(served.sweep(limitMs + MARGIN_MS).isEmpty())

        val forgotten = RappStoredPairs.served(served.catalog, served.vault) { limitMs }.single()
        assertTrue(forgotten.pairing.state is RappPairState.Forgotten)
        val (computer, phone) = served.handshake(forgotten.record)
        val closed = RappBridgeOutcome.from(computer.receiveReady(phone.deliverRevocationNotice(), NOW))
        assertEquals(RappCloseReason.PAIRING_REVOKED, (closed as RappBridgeOutcome.Closed).reason)
    }

    @Test
    fun aPairingWithAnEstablishedSessionNeverExpires() {
        val served = served()
        served.custodian.close()
        val heldMs = served.createdAtMs + IDLE_EXPIRY_MS * HELD_OPEN_LIMITS

        assertTrue(served.sweep(heldMs, RappServedSession(served.pairId, established = true)).isEmpty())
        assertEquals(heldMs, served.stored().lastSessionAtMs)
        assertEquals(
            served.pairId.key,
            served.catalog
                .listPairs()
                .single()
                .pairIdHex,
        )

        assertTrue(served.sweep(heldMs + IDLE_EXPIRY_MS - MARGIN_MS).isEmpty())
        assertEquals(listOf(served.pairId), served.sweep(heldMs + IDLE_EXPIRY_MS))
    }

    @Test
    fun aPairingWhoseSessionIsComingUpIsLeftForTheNextSweep() {
        val served = served()
        served.custodian.close()
        val limitMs = served.createdAtMs + IDLE_EXPIRY_MS

        assertTrue(served.sweep(limitMs, RappServedSession(served.pairId, established = false)).isEmpty())
        assertNull(served.stored().lastSessionAtMs)
        assertNull(served.stored().forgottenAtMs)

        assertEquals(listOf(served.pairId), served.sweep(limitMs))
    }

    @Test
    fun aSweepWhoseStoreFailedChangesNothingAndTheNextRepeatsIt() {
        val vault = RefusingVault(refusals = 1)
        val served = served(vault)
        val limitMs = served.createdAtMs + IDLE_EXPIRY_MS

        assertTrue(served.sweep(limitMs).isEmpty())
        assertEquals(
            served.pairId.key,
            served.catalog
                .listPairs()
                .single()
                .pairIdHex,
        )
        assertNull(served.stored().forgottenAtMs)

        assertEquals(listOf(served.pairId), served.sweep(limitMs))
        assertEquals(limitMs, served.stored().forgottenAtMs)
        served.custodian.close()

        val sessionMs = served.createdAtMs + SESSION_AFTER_MS
        val again = served(RefusingVault(refusals = 1))
        RappIdleExpiry.recordSession(again.custodian, again.vault, sessionMs)
        assertNull(again.custodian.metadata().lastSessionAtMs)
        assertNull(again.stored().lastSessionAtMs)
        RappIdleExpiry.recordSession(again.custodian, again.vault, sessionMs)
        assertEquals(sessionMs, again.stored().lastSessionAtMs)
        again.custodian.close()
    }

    @Test
    fun aRecordTheCoreRefusesIsRemovedOnce() {
        val served = served()
        served.custodian.close()
        served.vault.replaceDeviceOnly(served.pairId.toWire(), UNDECODABLE_RECORD.encodeToByteArray())

        assertTrue(served.sweep(served.createdAtMs).isEmpty())
        assertTrue(served.catalog.allPairs().isEmpty())
        assertTrue(served.vault.isRevoked(served.pairId.toWire()))

        assertTrue(RappStoredPairs.served(served.catalog, served.vault).isEmpty())
    }
}
