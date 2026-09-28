package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RappPairingCodeTest {
    @Test
    fun testGenerateAndValidate() {
        val code = RappPairingCode.generate()
        assertEquals(RappPairingCode.CODE_LENGTH, code.length)
        assertTrue(RappPairingCode.isValid(code))
    }

    @Test
    fun testNormalizeAndFormat() {
        val raw = "507-313"
        val normalized = RappPairingCode.normalize(raw)
        assertEquals("507313", normalized)
        assertTrue(RappPairingCode.isValid(normalized))
        assertEquals("507 313", RappPairingCode.formatted(normalized))

        assertFalse(RappPairingCode.isValid("12345"))
        assertFalse(RappPairingCode.isValid("abcdef"))
    }
}
