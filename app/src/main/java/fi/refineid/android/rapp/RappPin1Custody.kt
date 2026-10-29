// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.Pin1Retention
import fi.refineid.android.core.Pin1Submission

/**
 * The custodian's PIN 1 for browser authentications (RAPP v26.10.29 section
 * 11 item 2): asked at the first authentication that needs it, held only in
 * [cache]'s memory for the card that accepted it, and spent with no prompt
 * on every later authentication of that card.
 *
 * The hold ends when the card refuses the PIN, when another card is served,
 * when the card's PIN 1 counter reads below its try limit or cannot be read
 * before the PIN would go to it, and when the owner of [cache] clears it:
 * the card leaving the reader or the phone, the holder forgetting the card
 * or changing the PIN, the process ending.
 */
internal class RappPin1Custody(
    private val cache: AuthenticationPinCache?,
) {
    /**
     * The PIN 1 held for [card], the card this phone holds now, as a fresh
     * submission; null when none is held for it or the card already refused
     * it. A PIN held for another card ends here.
     */
    fun held(card: AuthenticationCardIdentity): Pin1Submission? {
        val custody = cache ?: return null
        val held = custody.take(card) ?: return null
        if (custody.isRejected(held)) {
            held.close()
            return null
        }
        return held
    }

    /**
     * Whether the PIN in hand may go to [card]: one held for [heldFor], or
     * one the holder entered for this operation when [heldFor] is null.
     * [retention] is the leave [card]'s counter gave before the command;
     * without it, or for a PIN held for another card, nothing stays held,
     * and a held PIN goes nowhere.
     */
    fun admits(
        card: AuthenticationCardIdentity,
        heldFor: AuthenticationCardIdentity?,
        retention: Pin1Retention?,
    ): Boolean {
        val heldElsewhere = heldFor != null && heldFor != card
        if (retention == null || heldElsewhere) cache?.clear()
        return heldFor == null || (!heldElsewhere && retention != null)
    }

    /** Whether [pin] is the PIN 1 already held for [card], so the card needs no separate VERIFY for it. */
    fun holds(
        pin: Pin1Submission,
        card: AuthenticationCardIdentity,
    ): Boolean = cache?.isVerified(pin, card) == true

    /** Whether the card already refused [pin] in this process; such a PIN is never sent again. */
    fun refused(pin: Pin1Submission): Boolean = cache?.isRejected(pin) == true

    /** Remembers that the card refused [pin], ending a hold of the same digits. */
    fun refuse(pin: Pin1Submission) {
        cache?.recordRejected(pin.copyBytes())
    }

    /**
     * Holds [pin], which the card [retention] names has just accepted;
     * false, holding nothing, when the custody changed since [generation].
     */
    fun hold(
        pin: Pin1Submission,
        retention: Pin1Retention,
        generation: Long?,
    ): Boolean = cache?.recordVerified(pin.copyBytes(), retention, generation) == true

    /** The custody generation an accepted PIN is held under; a clear in between refuses the hold. */
    val generation: Long?
        get() = cache?.generation
}
