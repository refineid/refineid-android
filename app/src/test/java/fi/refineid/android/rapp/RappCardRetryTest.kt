// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A PIN command the card did not answer runs again only when the PIN's
 * attempts, read before and after, show the card did not count it
 * (credential custody; RAPP v26.10.22 section 10.2).
 */
class RappCardRetryTest {
    private enum class Answer { SIGNED, CARD_LEFT }

    private companion object {
        /** The attempts a scripted card allows before any command. */
        const val ATTEMPTS = 5

        /** The attempts after the card counted one wrong PIN. */
        const val ONE_COUNTED = 4
    }

    /** A scripted card: the answers its commands give, and the attempts each read reports. */
    private class ScriptedCard(
        answers: List<Answer>,
        attempts: List<Int?>,
    ) {
        private val answers = ArrayDeque(answers)
        private val attempts = ArrayDeque(attempts)

        /** The answers the commands sent so far gave, in order. */
        val commands = mutableListOf<Answer>()

        /** Whether the card came back, for each wait so far. */
        val waits = mutableListOf<Boolean>()

        fun command(): Answer = answers.removeFirst().also(commands::add)

        fun attemptsLeft(): Int? = attempts.removeFirst()

        fun awaitCard(present: Boolean): Boolean = present.also(waits::add)
    }

    private suspend fun ScriptedCard.run(cardComesBack: Boolean = true): RappCardRetry.Run<Answer> =
        RappCardRetry.run(
            before = attemptsLeft(),
            attemptsLeft = { attemptsLeft() },
            command = { command() },
            cardLeft = { it == Answer.CARD_LEFT },
            awaitCard = { awaitCard(cardComesBack) },
        )

    @Test
    fun aCardThatAnswersIsNeverWaitedFor() =
        runBlocking {
            val card = ScriptedCard(listOf(Answer.SIGNED), listOf(ATTEMPTS))
            val run = card.run()
            assertSame(Answer.SIGNED, (run as RappCardRetry.Run.Answered).result)
            assertTrue(card.waits.isEmpty())
        }

    @Test
    fun anUnchangedCountSendsThePinAgain() =
        runBlocking {
            val card = ScriptedCard(listOf(Answer.CARD_LEFT, Answer.SIGNED), listOf(ATTEMPTS, ATTEMPTS))
            val run = card.run()
            assertSame(Answer.SIGNED, (run as RappCardRetry.Run.Answered).result)
            assertEquals(listOf(Answer.CARD_LEFT, Answer.SIGNED), card.commands)
        }

    @Test
    fun aFallenCountMeansTheCardCountedThePinAndItIsNotSentAgain() =
        runBlocking {
            val card = ScriptedCard(listOf(Answer.CARD_LEFT), listOf(ATTEMPTS, ONE_COUNTED))
            val run = card.run()
            assertEquals(ONE_COUNTED, (run as RappCardRetry.Run.Counted).attemptsLeft)
            assertEquals(listOf(Answer.CARD_LEFT), card.commands)
        }

    @Test
    fun withoutBothCountsThePinIsNotSentAgain() =
        runBlocking {
            for (counts in listOf(listOf(null, ATTEMPTS), listOf(ATTEMPTS, null))) {
                val card = ScriptedCard(listOf(Answer.CARD_LEFT), counts)
                assertSame(RappCardRetry.Run.Unproven, card.run())
                assertEquals(listOf(Answer.CARD_LEFT), card.commands)
            }
        }

    @Test
    fun aWaitThatEndsWithoutACardEndsTheRequest() =
        runBlocking {
            val card = ScriptedCard(listOf(Answer.CARD_LEFT), listOf(ATTEMPTS))
            assertSame(RappCardRetry.Run.CardMissing, card.run(cardComesBack = false))
            assertEquals(listOf(false), card.waits)
            assertEquals(listOf(Answer.CARD_LEFT), card.commands)
        }
}
