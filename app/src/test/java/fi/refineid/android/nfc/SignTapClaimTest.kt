// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import fi.refineid.android.core.NativeCardAccessFailure
import fi.refineid.android.core.NfcCardKind
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.FIRST_TAP
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.answering
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.failing
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignTapClaimTest {
    private val tag = ScriptedTag(FIRST_TAP)

    @Test
    fun aHeldSessionTakesTheTagAndServesAtOnce() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), held = true)
        val claim = SignTapClaimer.claim(card, tag) { error("a held session needs no access number") }
        assertEquals(SignTapClaim.Ready(opened = false), claim)
        assertEquals(listOf(tag), card.adopted)
        assertTrue(card.probed.isEmpty())
    }

    @Test
    fun aReadOrganisationCardOpensWithNoAccessNumber() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), read = true)
        val claim = SignTapClaimer.claim(card, tag) { error("an organisation card has no access number") }
        assertEquals(SignTapClaim.Ready(opened = true), claim)
        assertTrue(card.organizationOpened)
        assertNull(card.citizenAccessNumber)
    }

    @Test
    fun anOrganisationCardThisPhoneHasNotReadSaysSo() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION))
        val claim = SignTapClaimer.claim(card, tag) { error("an organisation card has no access number") }
        assertEquals(SignTapClaim.Refused(SignTapFailure.ORGANIZATION_CARD_NOT_READ), claim)
        assertFalse(card.held)
    }

    @Test
    fun aCitizenCardOpensWithItsAccessNumber() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.PERSONAL))
        val claim = SignTapClaimer.claim(card, tag) { SYNTHETIC_ACCESS_NUMBER.toByteArray(Charsets.US_ASCII) }
        assertEquals(SignTapClaim.Ready(opened = true), claim)
        assertEquals(SYNTHETIC_ACCESS_NUMBER, card.citizenAccessNumber)
        assertFalse(card.organizationOpened)
    }

    @Test
    fun aCitizenCardWithNoAccessNumberSaysSo() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.PERSONAL))
        val claim = SignTapClaimer.claim(card, tag) { null }
        assertEquals(SignTapClaim.Refused(SignTapFailure.ACCESS_NUMBER_REQUIRED), claim)
        assertFalse(card.held)
    }

    @Test
    fun aCardOfNoKnownKindSaysSo() {
        val card = ScriptedSignTapCard(answering(null))
        assertEquals(
            SignTapClaim.Refused(SignTapFailure.NO_KNOWN_KIND),
            SignTapClaimer.claim(card, tag) { error("no kind, no access number") },
        )
    }

    @Test
    fun aCardThatLeavesBeforeItAnswersKeepsTheWait() {
        val gone = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), inField = false)
        assertEquals(SignTapClaim.CardLeft, SignTapClaimer.claim(gone, tag) { null })
        assertTrue(gone.probed.isEmpty())
        val midProbe = ScriptedSignTapCard(failing(NativeCardAccessFailure.CARD_UNAVAILABLE))
        assertEquals(SignTapClaim.CardLeft, SignTapClaimer.claim(midProbe, tag) { null })
    }

    @Test
    fun aRefusedAccessFileReadGivesItsReason() {
        val expected =
            mapOf(
                NativeCardAccessFailure.REJECTED to SignTapFailure.ACCESS_FILE_REFUSED,
                NativeCardAccessFailure.INVALID_CARD_ACCESS to SignTapFailure.ACCESS_FILE_MALFORMED,
                NativeCardAccessFailure.TRANSPORT_ERROR to SignTapFailure.READ_FAILED,
                NativeCardAccessFailure.BRIDGE_ERROR to SignTapFailure.READ_FAILED,
            )
        expected.forEach { (failure, reason) ->
            val card = ScriptedSignTapCard(failing(failure))
            assertEquals(SignTapClaim.Refused(reason), SignTapClaimer.claim(card, tag) { null })
        }
    }

    private companion object {
        const val SYNTHETIC_ACCESS_NUMBER = "SYNTHETIC"
    }
}
