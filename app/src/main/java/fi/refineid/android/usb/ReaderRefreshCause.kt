// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.usb

/**
 * What made the reader controller look at the attached readers again, and
 * whether that moment may put the app's own USB permission request on
 * screen.
 *
 * The manifest associates the main activity with CCID readers, so an
 * attach already shows the system's dialog that grants access to the app
 * (Android USB host guide: an app the holder lets handle the attach
 * intent has permission). The app's own request is for a reader the
 * holder brought it to without that grant: when the holder opens the app,
 * picks another reader, or starts a card operation. A start in the
 * background, a broadcast, or the holder's answer to a request never asks
 * again on its own.
 */
internal enum class ReaderRefreshCause(
    val mayAskHolder: Boolean,
) {
    /** The controller started with the process, which may be in the background. */
    CONTROLLER_STARTED(mayAskHolder = false),

    /** A USB device arrived; the system's association dialog is its prompt. */
    DEVICE_ATTACHED(mayAskHolder = false),

    /** A USB device left. */
    DEVICE_DETACHED(mayAskHolder = false),

    /** The holder answered the app's permission request. */
    PERMISSION_ANSWERED(mayAskHolder = false),

    /** The system delivered an intent to the open activity, such as the accepted association. */
    ACTIVITY_INTENT(mayAskHolder = false),

    /** The holder brought the app to the foreground. */
    APP_FOREGROUND(mayAskHolder = true),

    /** The holder picked another reader. */
    READER_SELECTED(mayAskHolder = true),

    /** A card operation the holder started waits for the reader's card. */
    CARD_WANTED(mayAskHolder = true),
}

/**
 * Whether a refresh for [cause] asks the holder for access to a reader the
 * app may not use yet: only at a moment the holder drove, and never while
 * the app's earlier request for the same reader is still on screen.
 */
internal fun shouldRequestReaderPermission(
    cause: ReaderRefreshCause,
    requestOutstanding: Boolean,
): Boolean = cause.mayAskHolder && !requestOutstanding
