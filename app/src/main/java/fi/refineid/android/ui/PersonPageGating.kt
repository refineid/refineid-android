package fi.refineid.android.ui

/**
 * The Person page shows a live identity. With a USB reader attached, losing
 * the last identity (card removed, nothing held) sends the viewer back to
 * the front page instead of an empty person. Re-probes and readerless NFC
 * flows never close the page.
 */
internal fun shouldClosePersonPage(
    isPersonPage: Boolean,
    usbReaderPresent: Boolean,
    usbReaderChecking: Boolean,
    hasIdentity: Boolean,
): Boolean = isPersonPage && usbReaderPresent && !usbReaderChecking && !hasIdentity

internal enum class IdentityRowAction {
    OPEN_PERSON,
    REQUEST_USB_CAN,
    OPEN_PAIRING,
    ASK_NFC_READ,
    NOTHING,
}

/**
 * What the identity row offers. An NFC read is only offered when no USB
 * reader is attached: with a reader present but no card, there is nothing
 * to open and nothing to ask for.
 */
internal fun identityRowAction(
    hasHolder: Boolean,
    usbCanRequested: Boolean,
    hasNfc: Boolean,
    usbReaderPresent: Boolean,
): IdentityRowAction =
    when {
        hasHolder -> IdentityRowAction.OPEN_PERSON
        usbCanRequested -> IdentityRowAction.REQUEST_USB_CAN
        !hasNfc -> IdentityRowAction.OPEN_PAIRING
        usbReaderPresent -> IdentityRowAction.NOTHING
        else -> IdentityRowAction.ASK_NFC_READ
    }
