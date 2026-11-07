// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The native bridge's encoding of a CA certificate read: `step * 0x10000 + status word`. */
internal class CardCaReadAnswerTest {
    @Test
    fun anAnswerNamesTheStepTheCardStoppedAtAndItsWord() {
        val read = CardCaReadAnswer.decode(CardCaFile.ISSUING_CA, encoded(CardCaReadStep.READ, SUCCESS))
        assertTrue(read.isRead)
        assertEquals(SUCCESS, read.statusWord)

        val refused = CardCaReadAnswer.decode(CardCaFile.ROOT_CA, encoded(CardCaReadStep.SELECT_FILE, FILE_NOT_FOUND))
        assertEquals(CardCaReadAnswer(CardCaFile.ROOT_CA, CardCaReadStep.SELECT_FILE, FILE_NOT_FOUND), refused)
        assertFalse(refused.isRead)

        val unusable = CardCaReadAnswer.decode(CardCaFile.ROOT_CA, encoded(CardCaReadStep.CERTIFICATE, NO_STATUS))
        assertEquals(CardCaReadAnswer(CardCaFile.ROOT_CA, CardCaReadStep.CERTIFICATE, null), unusable)
    }

    @Test
    fun anUnknownOrMissingAnswerIsNotAsked() {
        for (value in listOf(CardCaReadAnswer.NOT_ASKED_ENCODING, UNKNOWN_STEP_ENCODING, NEGATIVE_ENCODING)) {
            assertEquals(
                CardCaReadAnswer(CardCaFile.ROOT_CA, CardCaReadStep.NOT_ASKED, null),
                CardCaReadAnswer.decode(CardCaFile.ROOT_CA, value),
            )
        }
    }

    private fun encoded(
        step: CardCaReadStep,
        status: Int,
    ): Int = step.code * STEP_FACTOR + status

    private companion object {
        const val STEP_FACTOR = 0x1_0000
        const val NO_STATUS = 0

        /** SW1-SW2 `90 00` and `6A 82` (ISO/IEC 7816-4 section 5.6). */
        const val SUCCESS = 0x9000
        const val FILE_NOT_FOUND = 0x6A82
        const val UNKNOWN_STEP_ENCODING = 0x7F_0000
        const val NEGATIVE_ENCODING = -1
    }
}
