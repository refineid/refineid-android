// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import uniffi.refineid_rapp.RappCardReader

/**
 * What `card.status` says on a session (RAPP v26.10.22 section 8.4 item 1):
 * the card this phone holds, and whether a card reader is connected to it.
 * A session is sent one right after `session.ready` and another whenever
 * either part changes.
 */
internal data class RappCardReport(
    val card: RappOfferedCard,
    val reader: RappCardReader,
) {
    /** The authentication certificate the report names, in its wire form; null while no card is held. */
    fun certificateWire(): ByteArray? = (card as? RappOfferedCard.Present)?.certificate?.toWire()

    companion object {
        /**
         * Whether a card reader is connected to the phone, as the USB reader
         * controller last published it: any CCID reader, with or without a
         * card in it or the app's permission to use it. A phone reading
         * cards only over NFC has none.
         */
        fun readerOf(usb: UsbReaderSnapshot): RappCardReader =
            if (usb.status == ReaderConnectionStatus.NOT_CONNECTED) RappCardReader.ABSENT else RappCardReader.ATTACHED
    }
}
