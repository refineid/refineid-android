// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_rapp.RappEndpointRole
import uniffi.refineid_rapp.RappPairMetadata

/** A stored pairing is read once, at the metadata border, into its identifier, role and state. */
class RappPairingTest {
    private companion object {
        /** Sixteen ASCII bytes, a pair identifier's size. */
        const val PAIR_ID_TEXT = "pair-identifier!"
        const val SHORT_TEXT = "short"
        const val NOT_HEX = "not hexadecimal"
        const val CREATED_AT_MS = 1_700_000_000_000UL
        const val FORGOTTEN_AT_MS = 1_700_000_100_000UL
        val PROFILES = listOf("fi.refineid.authentication")
    }

    private val wire = PAIR_ID_TEXT.encodeToByteArray()

    private fun metadata(
        confirmed: Boolean,
        forgottenAtMs: ULong?,
        pairId: ByteArray = wire,
    ) = RappPairMetadata(
        pairId = pairId,
        role = RappEndpointRole.PROXY,
        profiles = PROFILES,
        createdAtMs = CREATED_AT_MS,
        storageConfirmed = confirmed,
        forgottenAtMs = forgottenAtMs,
        lastSessionAtMs = null,
    )

    @Test
    fun aPairIdentifierRoundTripsThroughItsCatalogKey() {
        assertEquals(RappPairId.SIZE, wire.size)
        val pairId = checkNotNull(RappPairId.fromWire(wire))
        assertEquals(pairId, RappPairId.fromKey(pairId.key))
        assertTrue(pairId.toWire().contentEquals(wire))
        assertEquals(pairId, RappPairId.fromKey(pairId.key.uppercase()))
    }

    @Test
    fun aKeyOrWireValueOfAnotherSizeOrAlphabetIsNoPairIdentifier() {
        assertNull(RappPairId.fromWire(SHORT_TEXT.encodeToByteArray()))
        assertNull(RappPairId.fromKey(""))
        assertNull(RappPairId.fromKey(NOT_HEX))
        assertNull(RappPairId.fromKey(checkNotNull(RappPairId.fromWire(wire)).key.drop(PAIR_ID_TEXT.length)))
    }

    @Test
    fun theMetadataNamesOneState() {
        assertSame(RappPairState.Active, RappPairing.of(metadata(confirmed = true, forgottenAtMs = null)).state)
        assertSame(RappPairState.Unconfirmed, RappPairing.of(metadata(confirmed = false, forgottenAtMs = null)).state)
        val forgotten = RappPairing.of(metadata(confirmed = true, forgottenAtMs = FORGOTTEN_AT_MS)).state
        assertEquals(FORGOTTEN_AT_MS.toLong(), (forgotten as RappPairState.Forgotten).atMs)
    }

    @Test
    fun metadataTheCoreNeverProducesIsRefused() {
        assertThrows(IllegalStateException::class.java) {
            RappPairing.of(metadata(confirmed = false, forgottenAtMs = FORGOTTEN_AT_MS))
        }
        assertThrows(IllegalStateException::class.java) {
            RappPairing.of(metadata(confirmed = true, forgottenAtMs = null, pairId = SHORT_TEXT.encodeToByteArray()))
        }
    }
}
