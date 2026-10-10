// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** A remote card command waits for a card that left the field and runs again. */
class RappCardRetryTest {
    private enum class Outcome { SIGNED, CARD_LEFT }

    @Test
    fun aRequestWhoseCardLeftCompletesOnceTheCardIsPresented() =
        runBlocking {
            val outcomes = ArrayDeque(listOf(Outcome.CARD_LEFT, Outcome.SIGNED))
            var waited = 0
            val result =
                RappCardRetry.run(
                    command = { outcomes.removeFirst() },
                    cardLeft = { it == Outcome.CARD_LEFT },
                    awaitCard = {
                        waited += 1
                        true
                    },
                )
            assertEquals(Outcome.SIGNED, result)
            assertEquals(1, waited)
        }

    @Test
    fun aCardInTheFieldNeverWaits() =
        runBlocking {
            var waited = false
            val result =
                RappCardRetry.run(
                    command = { Outcome.SIGNED },
                    cardLeft = { it == Outcome.CARD_LEFT },
                    awaitCard = {
                        waited = true
                        true
                    },
                )
            assertEquals(Outcome.SIGNED, result)
            assertEquals(false, waited)
        }

    @Test
    fun aWaitThatEndsWithoutACardEndsTheRequest() =
        runBlocking {
            var runs = 0
            val result =
                RappCardRetry.run(
                    command = {
                        runs += 1
                        Outcome.CARD_LEFT
                    },
                    cardLeft = { it == Outcome.CARD_LEFT },
                    awaitCard = { false },
                )
            assertNull(result)
            assertEquals(1, runs)
        }

    @Test
    fun aSecondMissIsTheAnswer() =
        runBlocking {
            var runs = 0
            val result =
                RappCardRetry.run(
                    command = {
                        runs += 1
                        Outcome.CARD_LEFT
                    },
                    cardLeft = { it == Outcome.CARD_LEFT },
                    awaitCard = { true },
                )
            assertEquals(Outcome.CARD_LEFT, result)
            assertEquals(2, runs)
        }
}
