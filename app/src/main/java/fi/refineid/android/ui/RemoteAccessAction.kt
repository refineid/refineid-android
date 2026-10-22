// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.core.AuthenticationPurpose

/** What the holder did on Remote Access. */
internal enum class RemoteAccessAction {
    /** Opened the Remote Access page. */
    OPEN_PAGE,

    /** Turned Remote Access on. */
    TURN_ON,
}

/**
 * The card preparation [action] starts before the phone serves, or null when
 * it starts none.
 *
 * Opening the page asks nothing: it shows the switch, the pairing code and
 * the paired computers. Turning Remote Access on readies the card the phone
 * will serve when a reader can reach one, which asks for the card access
 * number only when that card needs it and has none stored. Neither asks for
 * PIN 1; the first authentication a computer requests does (RAPP v26.10.22
 * section 11 item 2).
 */
internal fun remoteAccessPreparation(
    action: RemoteAccessAction,
    cardReachable: Boolean,
): AuthenticationPurpose? =
    when (action) {
        RemoteAccessAction.OPEN_PAGE -> null
        RemoteAccessAction.TURN_ON -> AuthenticationPurpose.REMOTE_ACCESS.takeIf { cardReachable }
    }
