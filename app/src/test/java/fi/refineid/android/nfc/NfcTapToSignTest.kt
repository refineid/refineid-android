// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import fi.refineid.android.core.NfcCardKind
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.FIRST_TAP
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.SECOND_TAP
import fi.refineid.android.nfc.ScriptedSignTapCard.Companion.answering
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NfcTapToSignTest {
    private val mainThread = QueuedMainThread()
    private val outcomes = mutableListOf<String>()

    private fun tap(
        card: ScriptedSignTapCard,
        resting: ScriptedTag?,
    ): NfcTapToSign<ScriptedTag> =
        NfcTapToSign(
            worker = { it.run() },
            mainThread = mainThread,
            latestTag = { resting },
            card = card,
            accessNumber = { null },
            closeSession = card::close,
        )

    private fun NfcTapToSign<ScriptedTag>.start() =
        begin(
            canBytes = null,
            onReady = { outcomes += READY },
            onFailure = { outcomes += it.name },
        )

    @Test
    fun theOrganisationSessionTheReaderHoldsSignsForTheRestingTag() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), held = true)
        val tap = tap(card, resting = ScriptedTag(FIRST_TAP))
        tap.start()
        mainThread.runPosted()
        assertEquals(listOf(READY), outcomes)
        assertEquals(listOf(ScriptedTag(FIRST_TAP)), card.adopted)
        assertTrue(card.probed.isEmpty())
    }

    @Test
    fun aReTapIsAdoptedWithoutAnotherReady() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), held = true)
        val tap = tap(card, resting = null)
        tap.start()
        mainThread.runPosted()
        assertTrue(outcomes.isEmpty())
        tap.onTag(ScriptedTag(FIRST_TAP))
        tap.onTag(ScriptedTag(SECOND_TAP))
        mainThread.runPosted()
        assertEquals(listOf(READY), outcomes)
        assertEquals(listOf(ScriptedTag(FIRST_TAP), ScriptedTag(SECOND_TAP)), card.adopted)
    }

    @Test
    fun theReadersSessionOutlivesTheSignature() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), held = true)
        val tap = tap(card, resting = ScriptedTag(FIRST_TAP))
        tap.start()
        mainThread.runPosted()
        tap.end()
        assertFalse(card.closed)
        assertTrue(card.held)
    }

    @Test
    fun aSessionTheTapOpenedClosesWithIt() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), read = true)
        val tap = tap(card, resting = ScriptedTag(FIRST_TAP))
        tap.start()
        mainThread.runPosted()
        assertEquals(listOf(READY), outcomes)
        assertTrue(card.organizationOpened)
        tap.end()
        assertTrue(card.closed)
    }

    @Test
    fun aCardThatCannotSignEndsTheWaitWithItsReason() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION))
        val tap = tap(card, resting = ScriptedTag(FIRST_TAP))
        tap.start()
        mainThread.runPosted()
        assertEquals(listOf(SignTapFailure.ORGANIZATION_CARD_NOT_READ.name), outcomes)
        assertFalse(tap.inProgress)
        assertTrue(mainThread.delayed.isEmpty())
    }

    @Test
    fun noCardInTimeIsNoCard() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), held = true)
        val tap = tap(card, resting = null)
        tap.start()
        mainThread.runDelayed()
        assertEquals(listOf(SignTapFailure.NO_CARD.name), outcomes)
        assertFalse(tap.inProgress)
    }

    @Test
    fun aCardThatLeftIsNotCalledMissing() {
        val card = ScriptedSignTapCard(answering(NfcCardKind.ORGANIZATION), inField = false)
        val tap = tap(card, resting = ScriptedTag(FIRST_TAP))
        tap.start()
        mainThread.runDelayed()
        assertEquals(listOf(SignTapFailure.CARD_LEFT.name), outcomes)
    }

    /** The main thread as a queue the test drains; every caller is on it. */
    private class QueuedMainThread : SignTapMainThread {
        private val posted = ArrayDeque<Runnable>()
        val delayed = mutableListOf<Runnable>()

        override fun post(action: Runnable) {
            posted.addLast(action)
        }

        override fun postDelayed(
            action: Runnable,
            delayMillis: Long,
        ) {
            delayed += action
        }

        override fun remove(action: Runnable) {
            posted.remove(action)
            delayed.remove(action)
        }

        override fun isCurrent(): Boolean = true

        fun runPosted() {
            while (posted.isNotEmpty()) posted.removeFirst().run()
        }

        fun runDelayed() {
            runPosted()
            delayed.toList().forEach { action ->
                delayed.remove(action)
                action.run()
            }
            runPosted()
        }
    }

    private companion object {
        const val READY = "READY"
    }
}
