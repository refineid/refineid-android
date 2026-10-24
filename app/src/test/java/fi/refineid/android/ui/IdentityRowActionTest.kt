// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class IdentityRowActionTest {
    @Test
    fun identityRowOpensActivationWhateverElseHolds() {
        assertEquals(
            IdentityRowAction.ACTIVATE_CARD,
            identityRowAction(
                hasHolder = true,
                usbCanRequested = true,
                hasNfc = true,
                usbReaderPresent = true,
                activationRequired = true,
            ),
        )
    }

    @Test
    fun identityRowOffersNoTapWithHolder() {
        assertEquals(
            IdentityRowAction.NOTHING,
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
