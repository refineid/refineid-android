// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory retention of the Card Access Number (CAN) for the lifetime of
 * the running application process. CAN is non-secret card metadata (printed
 * on the front of the identity card) needed to establish PACE.
 *
 * If the card rejects the CAN during PACE authentication (WRONG_CAN / WRONG_ACCESS_NUMBER),
 * the stored CAN is immediately dropped and placed on a short-term blocklist (cooldown)
 * to prevent rapid retries of the invalid access number.
 */
internal object CanSessionStore {
    const val BLOCKLIST_DURATION_MS = 5 * 1000L // 5 seconds
    private const val MILLIS_CEILING_ROUNDING = 999L
    private const val MILLIS_PER_SECOND = 1000L

    @Volatile
    private var rememberedCan: String? = null

    @Volatile
    private var lastRejectedCan: String? = null

    private val blockedCans = ConcurrentHashMap<String, Long>()

    val currentCan: String?
        get() {
            val can = rememberedCan ?: return null
            if (isBlocked(can)) {
                rememberedCan = null
                return null
            }
            return can
        }

    val hasCan: Boolean
        get() = currentCan != null

    val mostRecentRejectedCan: String?
        get() = lastRejectedCan

    fun remember(
        canText: CharSequence,
        now: Long = System.currentTimeMillis(),
    ) {
        val digits = canText.toString().trim()
        if (CanSubmission.isComplete(digits) && !isBlocked(digits, now)) {
            rememberedCan = digits
        }
    }

    fun remember(submission: CanSubmission) {
        submission.peekDigits()?.let { digits ->
            val clean = digits.trim()
            if (CanSubmission.isComplete(clean)) {
                blockedCans.remove(clean)
                rememberedCan = clean
            }
        }
    }

    fun canBytes(): ByteArray? {
        val digits = currentCan ?: return null
        return CanSubmission.from(digits).transfer()
    }

    fun drop() {
        rememberedCan = null
    }

    /**
     * Mark a CAN as rejected by the card and place it on a short-term blocklist.
     */
    fun recordRejected(
        canText: CharSequence? = null,
        now: Long = System.currentTimeMillis(),
    ) {
        val digits = canText?.toString()?.trim() ?: rememberedCan
        if (digits != null && CanSubmission.isComplete(digits)) {
            blockedCans[digits] = now + BLOCKLIST_DURATION_MS
            lastRejectedCan = digits
        }
        val current = rememberedCan
        if (digits == current || (current != null && isBlocked(current, now))) {
            rememberedCan = null
        }
    }

    fun isBlocked(
        canText: CharSequence,
        now: Long = System.currentTimeMillis(),
    ): Boolean {
        val digits = canText.toString().trim()
        val expiry = blockedCans[digits] ?: return false
        if (now >= expiry) {
            blockedCans.remove(digits)
            return false
        }
        return true
    }

    /**
     * Remaining seconds on cooldown for the given CAN, or 0 if not blocked.
     */
    fun remainingCooldownSeconds(
        canText: CharSequence,
        now: Long = System.currentTimeMillis(),
    ): Int {
        val digits = canText.toString().trim()
        val expiry = blockedCans[digits] ?: return 0
        val remainingMs = expiry - now
        return if (remainingMs > 0) {
            ((remainingMs + MILLIS_CEILING_ROUNDING) / MILLIS_PER_SECOND).toInt()
        } else {
            blockedCans.remove(digits)
            0
        }
    }

    fun clearForTesting() {
        rememberedCan = null
        lastRejectedCan = null
        blockedCans.clear()
    }
}
