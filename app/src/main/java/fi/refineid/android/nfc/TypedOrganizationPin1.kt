// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.nfc

import fi.refineid.android.core.Pin1Submission
import java.util.concurrent.atomic.AtomicReference

/**
 * The PIN 1 the holder typed for an organization card that was not in the
 * field to take it. It waits for the card's next tap, at most as long as a
 * wait for a card lasts ([NfcCardWait.LIMIT_MILLISECONDS]), and opens the
 * card once it is recognized; whatever else ends the wait zeroes it. Only
 * one PIN waits: a newer one replaces it.
 */
internal class TypedOrganizationPin1(
    private val now: () -> Long,
) {
    private class Held(
        val pin1: Pin1Submission,
        val heldAt: Long,
    )

    private val held = AtomicReference<Held?>(null)

    /** Keeps [pin1], which this takes ownership of, for the next tap. */
    fun hold(pin1: Pin1Submission) {
        held.getAndSet(Held(pin1, now()))?.pin1?.close()
    }

    /** The PIN that waits, handed over to the caller; null when none waits or its wait ended. */
    fun take(): Pin1Submission? {
        val taken = held.getAndSet(null) ?: return null
        if (now() - taken.heldAt > NfcCardWait.LIMIT_MILLISECONDS) {
            taken.pin1.close()
            return null
        }
        return taken.pin1
    }

    /** Zeroes the PIN that waits, if any. */
    fun drop() {
        held.getAndSet(null)?.pin1?.close()
    }
}
