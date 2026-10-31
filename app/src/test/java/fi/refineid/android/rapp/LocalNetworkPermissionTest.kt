// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.rapp

import android.content.ContextWrapper
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Android 17 asks for the local network; earlier Androids have nothing to ask (ADR 0041 section 2.3). */
class LocalNetworkPermissionTest {
    /** A context that answers no permission check: consulting it fails the test. */
    private val unconsulted = ContextWrapper(null)

    @Test
    fun android17AsksForTheLocalNetwork() {
        assertTrue(LocalNetworkPermission.isAsked(LocalNetworkPermission.FIRST_SDK))
        assertTrue(LocalNetworkPermission.isAsked(LocalNetworkPermission.FIRST_SDK + 1))
    }

    @Test
    fun earlierAndroidsHaveNothingToAsk() {
        assertFalse(LocalNetworkPermission.isAsked(LocalNetworkPermission.FIRST_SDK - 1))
    }

    @Test
    fun anAndroidThatDoesNotAskHasTheLocalNetworkOpen() {
        assertTrue(LocalNetworkPermission.isGranted(unconsulted, LocalNetworkPermission.FIRST_SDK - 1))
    }
}
