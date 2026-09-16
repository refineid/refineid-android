package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class PersonPageGatingTest {
    @Test
    fun closesPersonPageWhenUsbReaderLosesLastIdentity() {
        assertEquals(
            true,
            shouldClosePersonPage(
                isPersonPage = true,
                usbReaderPresent = true,
                usbReaderChecking = false,
                hasIdentity = false,
            ),
        )
    }

    @Test
    fun keepsOtherPagesOpenWithoutIdentity() {
        assertEquals(
            false,
            shouldClosePersonPage(
                isPersonPage = false,
                usbReaderPresent = true,
                usbReaderChecking = false,
                hasIdentity = false,
            ),
        )
    }

    @Test
    fun keepsPersonPageOpenDuringUsbReprobe() {
        assertEquals(
            false,
            shouldClosePersonPage(
                isPersonPage = true,
                usbReaderPresent = true,
                usbReaderChecking = true,
                hasIdentity = false,
            ),
        )
    }

    @Test
    fun keepsPersonPageOpenWithoutUsbReader() {
        assertEquals(
            false,
            shouldClosePersonPage(
                isPersonPage = true,
                usbReaderPresent = false,
                usbReaderChecking = false,
                hasIdentity = false,
            ),
        )
    }

    @Test
    fun keepsPersonPageOpenWithIdentity() {
        assertEquals(
            false,
            shouldClosePersonPage(
                isPersonPage = true,
                usbReaderPresent = true,
                usbReaderChecking = false,
                hasIdentity = true,
            ),
        )
    }

    @Test
    fun identityRowOpensPersonWithHolder() {
        assertEquals(
            IdentityRowAction.OPEN_PERSON,
            identityRowAction(
                hasHolder = true,
                usbCanRequested = true,
                hasNfc = true,
                usbReaderPresent = true,
            ),
        )
    }

    @Test
    fun identityRowRequestsUsbCanWithoutHolder() {
        assertEquals(
            IdentityRowAction.REQUEST_USB_CAN,
            identityRowAction(
                hasHolder = false,
                usbCanRequested = true,
                hasNfc = true,
                usbReaderPresent = true,
            ),
        )
    }

    @Test
    fun identityRowPairsWithoutNfc() {
        assertEquals(
            IdentityRowAction.OPEN_PAIRING,
            identityRowAction(
                hasHolder = false,
                usbCanRequested = false,
                hasNfc = false,
                usbReaderPresent = false,
            ),
        )
    }

    @Test
    fun identityRowOffersNothingWithReaderButNoCard() {
        assertEquals(
            IdentityRowAction.NOTHING,
            identityRowAction(
                hasHolder = false,
                usbCanRequested = false,
                hasNfc = true,
                usbReaderPresent = true,
            ),
        )
    }

    @Test
    fun identityRowAsksNfcReadWithoutReader() {
        assertEquals(
            IdentityRowAction.ASK_NFC_READ,
            identityRowAction(
                hasHolder = false,
                usbCanRequested = false,
                hasNfc = true,
                usbReaderPresent = false,
            ),
        )
    }
}
