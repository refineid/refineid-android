// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import uniffi.refineid_rapp.RappCardReader

/** Whether `card.status` reports a card reader on the phone (RAPP v26.10.22 section 8.4 item 1). */
class RappCardReportTest {
    @Test
    fun aDetachedOrMissingReaderIsAbsent() {
        assertEquals(RappCardReader.ABSENT, RappCardReport.readerOf(UsbReaderSnapshot()))
    }

    @Test
    fun anyConnectedReaderIsAttachedWithOrWithoutACard() {
        for (status in ReaderConnectionStatus.entries - ReaderConnectionStatus.NOT_CONNECTED) {
            for (presence in listOf(null, CardPresence.PRESENT, CardPresence.NOT_PRESENT)) {
                assertEquals(
                    "$status $presence",
                    RappCardReader.ATTACHED,
                    RappCardReport.readerOf(UsbReaderSnapshot(status, presence)),
                )
            }
        }
    }

    @Test
    fun theReaderAloneChangingIsAChangeToReport() {
        assertNotEquals(
            RappCardReport(RappOfferedCard.Absent, RappCardReader.ATTACHED),
            RappCardReport(RappOfferedCard.Absent, RappCardReader.ABSENT),
        )
        assertEquals(
            RappCardReport(RappOfferedCard.Absent, RappCardReader.ABSENT),
            RappCardReport(RappOfferedCard.Absent, RappCardReader.ABSENT),
        )
    }

    @Test
    fun anAbsentCardNamesNoCertificate() {
        assertNull(RappCardReport(RappOfferedCard.Absent, RappCardReader.ATTACHED).certificateWire())
    }
}
