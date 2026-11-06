// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

/**
 * Text a paired peer chose, made inert for display. RAPP admits any UTF-8
 * of 1 to 256 bytes as a display name, document name or contained file
 * name (RAPP v26.11.2 sections 4.3, 9.3), so such a name can carry line
 * breaks that rewrite the sentence around it and bidirectional controls
 * that reorder what the holder reads, for example turning a name ending in
 * `fdp.exe` behind a right-to-left override into one that reads `exe.pdf`.
 *
 * Every code point that is a control character (C0, DEL, C1), a line or
 * paragraph separator, a format character (the bidirectional marks,
 * embeddings, overrides and isolates, zero-width space, soft hyphen, tag
 * characters) or a lone surrogate is replaced by [REPLACEMENT], so the
 * holder sees that the name held something it cannot show, and a name of
 * nothing else still shows as something. Replacing rather than removing
 * keeps the name's length and its separate words visible. Zero-width
 * non-joiner and joiner stay: they only choose letter joining, which
 * Persian, Indic scripts and emoji sequences need, and cannot reorder or
 * break a line. Everything else, letters of every script, right-to-left
 * ones included, digits, punctuation and spaces, passes unchanged.
 *
 * Only what is displayed passes through here; the values the protocol
 * carries and signs stay as the peer sent them.
 */
internal object RappDisplayText {
    /** U+FFFD REPLACEMENT CHARACTER, shown in place of each inert code point. */
    const val REPLACEMENT: Char = '\uFFFD'

    /** U+200C ZERO WIDTH NON-JOINER. */
    private const val ZERO_WIDTH_NON_JOINER = 0x200C

    /** U+200D ZERO WIDTH JOINER. */
    private const val ZERO_WIDTH_JOINER = 0x200D

    fun inert(text: String): String {
        val shown = StringBuilder(text.length)
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isInert(codePoint)) shown.append(REPLACEMENT) else shown.appendCodePoint(codePoint)
            index += Character.charCount(codePoint)
        }
        return shown.toString()
    }

    private fun isInert(codePoint: Int): Boolean =
        when (Character.getType(codePoint).toByte()) {
            Character.CONTROL,
            Character.LINE_SEPARATOR,
            Character.PARAGRAPH_SEPARATOR,
            Character.SURROGATE,
            -> true

            Character.FORMAT -> codePoint != ZERO_WIDTH_NON_JOINER && codePoint != ZERO_WIDTH_JOINER

            else -> false
        }
}
