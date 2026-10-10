// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * One card command for a remote request, tried again once the card is back.
 *
 * A card reported ready when the request arrived can have left the field
 * since, and the first command then fails before it reaches the card. The
 * request waits for the card as any other request does, and runs the
 * command once more; a second miss is the answer.
 */
internal object RappCardRetry {
    /**
     * The result of [command], or of a second run after [awaitCard]
     * reported the card back when [cardLeft] says the first run missed it;
     * null when the wait ended without a card.
     */
    suspend fun <T> run(
        command: () -> T,
        cardLeft: (T) -> Boolean,
        awaitCard: suspend () -> Boolean,
    ): T? {
        val first = command()
        if (!cardLeft(first)) return first
        if (!awaitCard()) return null
        return command()
    }
}
