// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.usb

/**
 * Whether a foreground refresh keeps the open session instead of
 * reopening it. A healthy session on the same permitted device
 * survives activity returns; detach, permission loss, device change,
 * errors, and empty readers all reopen as before. Removal and silent
 * death stay covered by the removal listener and the presence poll,
 * which publish snapshots that fail this check on their own.
 */
internal fun shouldKeepSessionOnRefresh(
    previousDeviceId: Int?,
    deviceId: Int,
    status: ReaderConnectionStatus,
    cardPresence: CardPresence?,
    hasSession: Boolean,
): Boolean =
    hasSession &&
        previousDeviceId != null &&
        previousDeviceId == deviceId &&
        cardPresence == CardPresence.PRESENT &&
        (
            status == ReaderConnectionStatus.READY ||
                status == ReaderConnectionStatus.ACTIVATION_REQUIRED ||
                status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
        )
