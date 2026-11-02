// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.core

/**
 * In-memory retention of the Card Access Number (CAN) for the lifetime of
 * the running application process. The CAN, six digits printed on the front
 * of a personal card and needed to establish PACE, is a secret like the
 * PINs: it is never written back into an entry field or shown.
 *
 * A CAN the card rejected during PACE is dropped at once and nothing about it
 * is kept: the next entry starts from an empty field.
 */
internal object CanSessionStore {
    @Volatile
    private var rememberedCan: String? = null

    val currentCan: String?
        get() = rememberedCan

    val hasCan: Boolean
        get() = currentCan != null

    fun remember(canText: CharSequence) {
        val digits = canText.toString().trim()
        if (CanSubmission.isComplete(digits)) {
            rememberedCan = digits
        }
    }

    fun remember(submission: CanSubmission) {
        submission.peekDigits()?.let { digits ->
            val clean = digits.trim()
            if (CanSubmission.isComplete(clean)) {
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

    fun clearForTesting() {
        rememberedCan = null
    }
}
