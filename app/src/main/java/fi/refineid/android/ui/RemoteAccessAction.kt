// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import android.Manifest
import android.os.Build
import fi.refineid.android.core.AuthenticationPurpose
import fi.refineid.android.rapp.LocalNetworkPermission

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
 * PIN 1; the first authentication a computer requests does (RAPP v26.10.29
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

/**
 * The runtime permissions Remote Access serves with on every Android:
 * notifications for the holder's prompts while RefineID is not in front, and
 * nearby devices (`BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`) for serving
 * over Bluetooth. Android 17 adds the local network ([LocalNetworkPermission])
 * for serving and pairing over the stream.
 */
internal val REMOTE_ACCESS_PERMISSIONS: List<String> =
    listOf(
        Manifest.permission.POST_NOTIFICATIONS,
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.BLUETOOTH_CONNECT,
    )

/** The runtime permissions Remote Access serves with on an Android of [sdk]. */
internal fun remoteAccessPermissions(sdk: Int): List<String> =
    if (LocalNetworkPermission.isAsked(sdk)) {
        REMOTE_ACCESS_PERMISSIONS + LocalNetworkPermission.NAME
    } else {
        REMOTE_ACCESS_PERMISSIONS
    }

/**
 * The permissions [action] asks the holder for on an Android of [sdk], of
 * those [isGranted] does not hold yet.
 *
 * Only turning Remote Access on asks, beside the card access number rule of
 * [remoteAccessPreparation]; opening the page and the app's start never ask
 * for nearby devices or the local network (notifications keep the rule of
 * ADR 0040). A permission the holder declines leaves the phone serving
 * without it: without nearby devices, over the stream alone; without the
 * local network, over Bluetooth alone, and the Remote Access page says so
 * where the pairing code would be, with a retry that asks again.
 */
internal fun remoteAccessPermissions(
    action: RemoteAccessAction,
    sdk: Int = Build.VERSION.SDK_INT,
    isGranted: (String) -> Boolean,
): List<String> =
    when (action) {
        RemoteAccessAction.OPEN_PAGE -> emptyList()
        RemoteAccessAction.TURN_ON -> remoteAccessPermissions(sdk).filterNot(isGranted)
    }
