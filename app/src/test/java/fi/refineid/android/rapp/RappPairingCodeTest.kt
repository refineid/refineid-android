package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ITERATIONS = 50

class RappPairingCodeTest {
    @Test
    fun testGenerateAndValidate() {
        for (i in 0 until ITERATIONS) {
            val code = RappPairingCode.generate()
            assertEquals(RappPairingCode.CODE_LENGTH, code.length)
            assertTrue(RappPairingCode.isValid(code))
            // Ensure excluded characters are never generated
            assertFalse(code.contains('I'))
            assertFalse(code.contains('L'))
            assertFalse(code.contains('O'))
            assertFalse(code.contains('U'))
        }
    }

    @Test
    fun testNormalizeAndFormat() {
        val raw = "7k-x4-m9"
        val normalized = RappPairingCode.normalize(raw)
        assertEquals("7KX4M9", normalized)
        assertTrue(RappPairingCode.isValid(normalized))
        assertEquals("7K X4 M9", RappPairingCode.formatted(normalized))
    }

    @Test
    fun testRejectsExcludedLetters() {
        for (excluded in listOf("7KX4MI", "7KX4Mi", "7KX4ML", "7KX4Ml", "7KX4MO", "7KX4Mo", "7KX4MU", "7KX4Mu")) {
            assertEquals(excluded, "", RappPairingCode.normalize(excluded))
            assertFalse(excluded, RappPairingCode.isValid(excluded))
        }
        assertTrue(RappPairingCode.isValid("7KX4M0"))
        assertTrue(RappPairingCode.isValid("7KX4M1"))
    }

    @Test
    fun testRejectsInvalidCharacters() {
        // U is explicitly rejected
        assertEquals("", RappPairingCode.normalize("7KU4M9"))
        assertFalse(RappPairingCode.isValid("7KU4M9"))

        // Length checks
        assertFalse(RappPairingCode.isValid("7KX4M"))
        assertFalse(RappPairingCode.isValid(""))

        // Punctuation and invalid symbols
        assertEquals("", RappPairingCode.normalize("7K#4M9"))
        assertFalse(RappPairingCode.isValid("7K#4M9"))
    }

    @Test
    fun testRejectsOverlongCodeInsteadOfTruncating() {
        assertEquals("7KX4M9AB", RappPairingCode.normalize("7KX4M9AB"))
        assertFalse(RappPairingCode.isValid("7KX4M9AB"))
        assertFalse(RappPairingCode.isValid("7K X4 M9 A"))
    }

    @Test
    fun testUppercasesAsciiOnly() {
        // Dotless i uppercases to I under full Unicode rules; the pipeline rejects it.
        assertEquals("", RappPairingCode.normalize("7KX4M\u0131"))
        assertFalse(RappPairingCode.isValid("7KX4M\u0131"))
    }

    @Test
    fun testIgnoresSpacesAndHyphensOnly() {
        assertTrue(RappPairingCode.isValid("7K X4-M9"))
        assertFalse(RappPairingCode.isValid("7K\tX4\nM9"))
        assertFalse(RappPairingCode.isValid("7K\u1680X4M9"))
        // A fullwidth digit is not folded to its ASCII form.
        assertFalse(RappPairingCode.isValid("7KX4M\uFF19"))
    }
}
