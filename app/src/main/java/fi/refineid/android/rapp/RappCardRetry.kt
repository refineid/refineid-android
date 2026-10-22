// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * A card command that presents a PIN, tried again once the card is back.
 *
 * A card reported ready when the request arrived can have left the field
 * since, and the command then fails without an answer: before the card saw
 * it, or after the card counted it. The request waits for the card as any
 * other request does and reads the PIN's attempts again; it runs the command
 * once more only when the count it read before the first run shows the card
 * did not count it (credential custody, RAPP v26.10.22 section 10.2). A
 * second miss is the answer.
 */
internal object RappCardRetry {
    /** What a PIN-presenting command came to. */
    sealed interface Run<out T> {
        /** The card answered with [result]. */
        class Answered<T>(
            val result: T,
        ) : Run<T>

        /** The card did not come back within the wait. */
        data object CardMissing : Run<Nothing>

        /** The card counted the PIN: its attempts fell to [attemptsLeft]. The PIN is not sent again. */
        class Counted(
            val attemptsLeft: Int,
        ) : Run<Nothing>

        /** No count shows that the card did not count the PIN, so it is not sent again. */
        data object Unproven : Run<Nothing>
    }

    /**
     * The result of [command]; when [cardLeft] says the first run went
     * unanswered, waits through [awaitCard] and runs it again only when
     * [attemptsLeft] reads [before], the count read before the first run.
     */
    suspend fun <T> run(
        before: Int?,
        attemptsLeft: suspend () -> Int?,
        command: suspend () -> T,
        cardLeft: (T) -> Boolean,
        awaitCard: suspend () -> Boolean,
    ): Run<T> {
        val first = command()
        if (!cardLeft(first)) return Run.Answered(first)
        if (!awaitCard()) return Run.CardMissing
        val after = attemptsLeft()
        return when {
            before == null || after == null -> Run.Unproven
            after < before -> Run.Counted(after)
            else -> Run.Answered(command())
        }
    }
}
