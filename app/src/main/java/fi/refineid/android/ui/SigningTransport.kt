// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

/**
 * Which card transport a signing visit uses. Latched on entry so a
 * transient readiness loss never reroutes the holder's signing; only
 * a genuinely gone transport releases the latch.
 */
internal enum class SigningTransport {
    USB,
    NFC,
}

/**
 * Next latch state. An empty latch takes the first present transport,
 * preferring USB; a held latch survives transient unreadiness and is
 * released only when its transport is gone, falling back to the other
 * transport when present.
 */
internal fun nextSigningTransport(
    current: SigningTransport?,
    usbPresent: Boolean,
    nfcPresent: Boolean,
): SigningTransport? =
    when {
        current == SigningTransport.USB && usbPresent -> SigningTransport.USB
        current == SigningTransport.NFC && nfcPresent -> SigningTransport.NFC
        usbPresent -> SigningTransport.USB
        nfcPresent -> SigningTransport.NFC
        else -> null
    }
