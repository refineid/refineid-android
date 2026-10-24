// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

internal enum class IdentityRowAction {
    REQUEST_USB_CAN,
    OPEN_PAIRING,
    ASK_NFC_READ,

    /** The card awaits activation: the row opens the activation form. */
    ACTIVATE_CARD,
    NOTHING,
}

/**
 * What tapping the identity row does. A card awaiting activation opens the
 * activation form whoever holds it. A known holder offers no tap: the
 * row only shows the identity. An NFC read is only offered when no USB
 * reader is attached: with a reader present but no card, there is nothing
 * to ask for.
 */
internal fun identityRowAction(
    hasHolder: Boolean,
    usbCanRequested: Boolean,
    hasNfc: Boolean,
    usbReaderPresent: Boolean,
    activationRequired: Boolean = false,
): IdentityRowAction =
    when {
        activationRequired -> IdentityRowAction.ACTIVATE_CARD
        hasHolder -> IdentityRowAction.NOTHING
        usbCanRequested -> IdentityRowAction.REQUEST_USB_CAN
        !hasNfc -> IdentityRowAction.OPEN_PAIRING
        usbReaderPresent -> IdentityRowAction.NOTHING
        else -> IdentityRowAction.ASK_NFC_READ
    }
