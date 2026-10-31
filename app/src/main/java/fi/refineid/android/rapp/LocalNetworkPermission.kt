// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.rapp

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

/**
 * The local network permission of Android 17 (ADR 0041 section 2.3).
 *
 * Android 17 gates the local network behind the runtime
 * `ACCESS_LOCAL_NETWORK` permission for apps that target it: without it the
 * system refuses the stream's mDNS registration and blocks its connections.
 * Earlier Androids grant the local network with `INTERNET` and have no such
 * permission to ask for.
 */
internal object LocalNetworkPermission {
    /** The first Android that asks for the permission. */
    const val FIRST_SDK: Int = Build.VERSION_CODES.CINNAMON_BUN

    /**
     * The permission's name. The string is inlined at compile time; an
     * earlier Android is never asked for it ([isAsked]).
     */
    @SuppressLint("InlinedApi")
    const val NAME: String = Manifest.permission.ACCESS_LOCAL_NETWORK

    /** Whether an Android of [sdk] asks for the permission. */
    fun isAsked(sdk: Int = Build.VERSION.SDK_INT): Boolean = sdk >= FIRST_SDK

    /**
     * Whether the local network is open to this app: always on an Android
     * that does not ask, otherwise when the holder granted the permission.
     */
    fun isGranted(
        context: Context,
        sdk: Int = Build.VERSION.SDK_INT,
    ): Boolean = !isAsked(sdk) || ContextCompat.checkSelfPermission(context, NAME) == PackageManager.PERMISSION_GRANTED
}
