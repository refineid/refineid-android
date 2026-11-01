// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

/**
 * Whether a tag handle still reaches the card, as [isConnected] reports it.
 * A handle the stack replaced after the tag re-polled throws
 * [SecurityException] ("Tag ... is out of date"), and a stopped tag service
 * throws [IllegalStateException]; either way the tag is gone.
 */
internal inline fun tagReachable(isConnected: () -> Boolean): Boolean =
    try {
        isConnected()
    } catch (_: SecurityException) {
        false
    } catch (_: IllegalStateException) {
        false
    }
