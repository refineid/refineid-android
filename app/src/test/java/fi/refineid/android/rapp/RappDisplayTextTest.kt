// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A peer-chosen name shows without anything that could rewrite or reorder the text around it. */
class RappDisplayTextTest {
    @Test
    fun cleanNamesPassUnchanged() {
        for (name in listOf(ASCII_NAME, FINNISH_NAME, SWEDISH_NAME, HEBREW_NAME, ARABIC_NAME, PERSIAN_NAME, CJK_NAME)) {
            assertEquals(name, RappDisplayText.inert(name))
        }
    }

    @Test
    fun controlCharactersAreReplaced() {
        for (control in listOf(NUL, TAB, LINE_FEED, CARRIAGE_RETURN, ESCAPE, DELETE, NEXT_LINE, C1_CSI)) {
            assertEquals(shown(REPLACED), RappDisplayText.inert("a${control}b"))
        }
    }

    @Test
    fun lineAndParagraphSeparatorsAreReplaced() {
        for (separator in listOf(LINE_SEPARATOR, PARAGRAPH_SEPARATOR)) {
            assertEquals(shown(REPLACED), RappDisplayText.inert("a${separator}b"))
        }
    }

    @Test
    fun bidirectionalControlsAreReplaced() {
        val controls =
            listOf(
                LEFT_TO_RIGHT_MARK,
                RIGHT_TO_LEFT_MARK,
                ARABIC_LETTER_MARK,
                LEFT_TO_RIGHT_EMBEDDING,
                RIGHT_TO_LEFT_EMBEDDING,
                POP_DIRECTIONAL_FORMATTING,
                LEFT_TO_RIGHT_OVERRIDE,
                RIGHT_TO_LEFT_OVERRIDE,
                LEFT_TO_RIGHT_ISOLATE,
                RIGHT_TO_LEFT_ISOLATE,
                FIRST_STRONG_ISOLATE,
                POP_DIRECTIONAL_ISOLATE,
            )
        for (control in controls) {
            assertEquals(shown(REPLACED), RappDisplayText.inert("a${control}b"))
        }
    }

    @Test
    fun otherFormatCharactersAreReplaced() {
        for (format in listOf(ZERO_WIDTH_SPACE, SOFT_HYPHEN, WORD_JOINER, BYTE_ORDER_MARK, TAG_LATIN_SMALL_A)) {
            assertEquals(shown(REPLACED), RappDisplayText.inert("a${format}b"))
        }
    }

    @Test
    fun joinerAndNonJoinerStayForTheScriptsThatNeedThem() {
        for (joiner in listOf(ZERO_WIDTH_NON_JOINER, ZERO_WIDTH_JOINER)) {
            assertEquals("a${joiner}b", RappDisplayText.inert("a${joiner}b"))
        }
    }

    @Test
    fun aLoneSurrogateIsReplaced() {
        assertEquals(shown(REPLACED), RappDisplayText.inert("a${LONE_HIGH_SURROGATE}b"))
    }

    @Test
    fun aReversedExtensionShowsItsOverrideInsteadOfHidingIt() {
        val shown = RappDisplayText.inert("${FINNISH_NAME}${RIGHT_TO_LEFT_OVERRIDE}fdp.exe")

        assertEquals("$FINNISH_NAME${RappDisplayText.REPLACEMENT}fdp.exe", shown)
    }

    @Test
    fun mixedTextKeepsEveryOrdinaryCharacter() {
        val mixed = "$SWEDISH_NAME${LINE_FEED}$HEBREW_NAME${POP_DIRECTIONAL_ISOLATE} 2026, $ARABIC_NAME."

        assertEquals(
            "$SWEDISH_NAME${RappDisplayText.REPLACEMENT}$HEBREW_NAME${RappDisplayText.REPLACEMENT} 2026, $ARABIC_NAME.",
            RappDisplayText.inert(mixed),
        )
    }

    @Test
    fun aNameOfNothingButControlsStillShowsSomething() {
        val shown = RappDisplayText.inert("$RIGHT_TO_LEFT_OVERRIDE$LINE_FEED$ZERO_WIDTH_SPACE")

        assertEquals(CONTROL_ONLY_LENGTH, shown.length)
        assertTrue(shown.all { it == RappDisplayText.REPLACEMENT })
        assertTrue(shown.isNotBlank())
    }

    private fun shown(between: String) = "a${between}b"

    private companion object {
        const val ASCII_NAME = "Workstation-7 (office)"
        const val FINNISH_NAME = "J\u00E4rvenp\u00E4\u00E4n ty\u00F6asema \u00C4\u00D6"
        const val SWEDISH_NAME = "\u00C5sas dator \u00E5"
        const val HEBREW_NAME = "\u05DE\u05D7\u05E9\u05D1"
        const val ARABIC_NAME = "\u062D\u0627\u0633\u0648\u0628"
        const val PERSIAN_NAME = "\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645"
        const val CJK_NAME = "\u96FB\u8166"

        const val NUL = "\u0000"
        const val TAB = "\u0009"
        const val LINE_FEED = "\u000A"
        const val CARRIAGE_RETURN = "\u000D"
        const val ESCAPE = "\u001B"
        const val DELETE = "\u007F"
        const val NEXT_LINE = "\u0085"
        const val C1_CSI = "\u009B"
        const val LINE_SEPARATOR = "\u2028"
        const val PARAGRAPH_SEPARATOR = "\u2029"
        const val LEFT_TO_RIGHT_MARK = "\u200E"
        const val RIGHT_TO_LEFT_MARK = "\u200F"
        const val ARABIC_LETTER_MARK = "\u061C"
        const val LEFT_TO_RIGHT_EMBEDDING = "\u202A"
        const val RIGHT_TO_LEFT_EMBEDDING = "\u202B"
        const val POP_DIRECTIONAL_FORMATTING = "\u202C"
        const val LEFT_TO_RIGHT_OVERRIDE = "\u202D"
        const val RIGHT_TO_LEFT_OVERRIDE = "\u202E"
        const val LEFT_TO_RIGHT_ISOLATE = "\u2066"
        const val RIGHT_TO_LEFT_ISOLATE = "\u2067"
        const val FIRST_STRONG_ISOLATE = "\u2068"
        const val POP_DIRECTIONAL_ISOLATE = "\u2069"
        const val ZERO_WIDTH_SPACE = "\u200B"
        const val SOFT_HYPHEN = "\u00AD"
        const val WORD_JOINER = "\u2060"
        const val BYTE_ORDER_MARK = "\uFEFF"

        /** U+E0061 TAG LATIN SMALL LETTER A, one code point in two UTF-16 units. */
        const val TAG_LATIN_SMALL_A = "\uDB40\uDC61"
        const val ZERO_WIDTH_NON_JOINER = "\u200C"
        const val ZERO_WIDTH_JOINER = "\u200D"
        const val LONE_HIGH_SURROGATE = "\uD800"

        /** One replacement for each inert code point. */
        const val REPLACED = "\uFFFD"

        /** The three code points of the control-only name. */
        const val CONTROL_ONLY_LENGTH = 3
    }
}
