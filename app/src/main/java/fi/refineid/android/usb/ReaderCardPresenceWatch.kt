// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.usb

/**
 * Notices when the card that sat in the USB reader is gone.
 *
 * The card's presence ends when the reader reports it removed or when
 * the reader itself disconnects. Snapshots that say nothing about the
 * card, such as a probe in progress, leave the record as it was, so a
 * card that stays in the reader never ends its own presence.
 */
internal class ReaderCardPresenceWatch {
    private var cardPresent = false

    /** True exactly once for each card presence that ends. */
    fun presenceEnded(snapshot: UsbReaderSnapshot): Boolean {
        if (snapshot.cardPresence == CardPresence.PRESENT) {
            cardPresent = true
            return false
        }
        val gone =
            snapshot.cardPresence == CardPresence.NOT_PRESENT ||
                snapshot.status == ReaderConnectionStatus.NOT_CONNECTED
        if (!gone || !cardPresent) return false
        cardPresent = false
        return true
    }
}
