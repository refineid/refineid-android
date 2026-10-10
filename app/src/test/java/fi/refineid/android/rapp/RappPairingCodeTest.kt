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
    fun testCrockfordDecodeAliases() {
        // I and L map to 1; O maps to 0
        assertEquals("1108K2", RappPairingCode.normalize("iLo8k2"))
        assertEquals("1108K2", RappPairingCode.normalize("ILO8K2"))
        assertTrue(RappPairingCode.isValid("1108K2"))
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
    fun testStripsAsciiWhitespaceOnly() {
        assertTrue(RappPairingCode.isValid("7K\tX4\nM9"))
        // Ogham space mark is Unicode whitespace that NFKC keeps and step 4 does not strip.
        assertFalse(RappPairingCode.isValid("7K\u1680X4M9"))
    }
}
