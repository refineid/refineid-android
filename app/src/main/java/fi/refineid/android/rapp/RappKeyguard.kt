// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * This phone's keyguard as the custodian reads it (ADR 0040).
 *
 * Locked means the keyguard is showing, whatever secures it: a secure lock,
 * a swipe, or a lock a trust agent would let through. That is the state in
 * which no activity of this app can reach the holder, so a request that
 * needs the holder at the phone waits until the keyguard is dismissed.
 */
internal interface RappKeyguard {
    /** Whether the keyguard is showing now. */
    val isLocked: Boolean

    /** Returns once the keyguard is dismissed; at once when it is not showing. */
    suspend fun awaitUnlocked()
}

/**
 * The held PIN 1 serves a browser authentication without a prompt, but
 * never on a locked phone (ADR 0040): the holder unlocks first, and the
 * request then proceeds with no PIN prompt. The wait is on the holder, like
 * a wait for consent, and ends the same way when the operation's deadline
 * passes first: the engine answers the requester and the operation's
 * coroutine is cancelled, so nothing is signed.
 */
internal object RappUnlockGate {
    /**
     * Returns once [keyguard] is unlocked: at once, with nothing told, while
     * it is not showing; otherwise after [tell] has told the holder a
     * request waits on the unlock and the holder dismissed the keyguard.
     * [withdraw] takes the telling back once the wait ends, by the unlock or
     * by cancellation. True when the holder had to unlock.
     */
    suspend fun awaitUnlocked(
        keyguard: RappKeyguard,
        tell: suspend () -> Unit,
        withdraw: suspend () -> Unit,
    ): Boolean {
        if (!keyguard.isLocked) return false
        tell()
        try {
            keyguard.awaitUnlocked()
        } finally {
            withdraw()
        }
        return true
    }
}
