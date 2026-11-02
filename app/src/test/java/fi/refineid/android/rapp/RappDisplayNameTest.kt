// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The name this device gives itself and the role it takes (RAPP v26.11.2
 * section 4.3 item 3): a phone with NFC is the custodian under its device
 * name; a tablet, or a device without NFC, is a computer named
 * "Android - <name>"; every name is 1 to 256 bytes and not blank.
 */
class RappDisplayNameTest {
    private companion object {
        const val DEVICE_NAME = "Kitchen tablet"
        const val MODEL = "Synthetic Model"
        const val BLANK = "   "

        /** A character that takes two bytes in UTF-8, so a cut can fall inside it. */
        const val TWO_BYTE_CHARACTER = "ä"
        const val ONE_BYTE_CHARACTER = "a"
        const val UTF8_BYTES_OF_TWO_BYTE_CHARACTER = 2

        /** A phone's narrower side and a tablet's, in density-independent pixels. */
        const val PHONE_WIDTH_DP = 411
        val TABLET_WIDTH_DP = RappDeviceRole.TABLET_SMALLEST_WIDTH_DP
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    @Test
    fun aNameIsNotBlankAndFitsTheBound() {
        assertNull(RappDisplayName.parse(""))
        assertNull(RappDisplayName.parse(BLANK))
        assertEquals(DEVICE_NAME, RappDisplayName.parse(DEVICE_NAME)?.text)
        assertEquals(
            RappDisplayName.MAX_BYTES,
            RappDisplayName.parse(ONE_BYTE_CHARACTER.repeat(RappDisplayName.MAX_BYTES))?.text?.length,
        )
        assertNull(RappDisplayName.parse(ONE_BYTE_CHARACTER.repeat(RappDisplayName.MAX_BYTES + 1)))
    }

    @Test
    fun aLongNameIsShortenedAtACharacterBoundary() {
        val long = ONE_BYTE_CHARACTER + TWO_BYTE_CHARACTER.repeat(RappDisplayName.MAX_BYTES)
        val shortened = checkNotNull(RappDisplayName.shortened(long)).text
        val bytes = shortened.encodeToByteArray().size
        assertTrue(bytes <= RappDisplayName.MAX_BYTES)
        assertTrue(bytes > RappDisplayName.MAX_BYTES - UTF8_BYTES_OF_TWO_BYTE_CHARACTER)
        assertTrue(long.startsWith(shortened))
        assertNull(RappDisplayName.shortened(BLANK))
    }

    @Test
    fun aPhoneWithNfcIsTheCustodianAndATabletAComputer() {
        assertEquals(RappDeviceRole.CUSTODIAN, RappDeviceRole.of(true, PHONE_WIDTH_DP, foldable = false))
        assertEquals(RappDeviceRole.REQUESTER, RappDeviceRole.of(true, TABLET_WIDTH_DP, foldable = false))
        assertEquals(RappDeviceRole.REQUESTER, RappDeviceRole.of(false, PHONE_WIDTH_DP, foldable = false))
        assertEquals(RappDeviceRole.CUSTODIAN, RappDeviceRole.of(true, TABLET_WIDTH_DP, foldable = true))
    }

    @Test
    fun aPhoneIsNamedAsItsUserNamedItAndAComputerAfterItsSystemFirst() {
        assertEquals(DEVICE_NAME, RappLocalName.of(RappDeviceRole.CUSTODIAN, DEVICE_NAME, MODEL).text)
        assertEquals(MODEL, RappLocalName.of(RappDeviceRole.CUSTODIAN, BLANK, MODEL).text)
        assertEquals(MODEL, RappLocalName.of(RappDeviceRole.CUSTODIAN, null, MODEL).text)
        assertEquals(
            RappLocalName.REQUESTER_PREFIX + DEVICE_NAME,
            RappLocalName.of(RappDeviceRole.REQUESTER, DEVICE_NAME, MODEL).text,
        )
        assertEquals(RappLocalName.OPERATING_SYSTEM, RappLocalName.of(RappDeviceRole.CUSTODIAN, null, BLANK).text)
        val long = ONE_BYTE_CHARACTER.repeat(RappDisplayName.MAX_BYTES)
        val computer = RappLocalName.of(RappDeviceRole.REQUESTER, long, MODEL).text
        assertTrue(computer.startsWith(RappLocalName.REQUESTER_PREFIX))
        assertEquals(RappDisplayName.MAX_BYTES, computer.encodeToByteArray().size)
    }
}
