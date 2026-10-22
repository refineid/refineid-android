// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import android.Manifest
import fi.refineid.android.core.AuthenticationPurpose
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteAccessActionTest {
    @Test
    fun openingThePageAsksNothing() {
        for (cardReachable in listOf(true, false)) {
            assertNull(remoteAccessPreparation(RemoteAccessAction.OPEN_PAGE, cardReachable))
        }
    }

    @Test
    fun turningRemoteAccessOnReadiesTheCardAReaderCanReach() {
        assertEquals(
            AuthenticationPurpose.REMOTE_ACCESS,
            remoteAccessPreparation(RemoteAccessAction.TURN_ON, cardReachable = true),
        )
    }

    @Test
    fun turningRemoteAccessOnWithNoReaderServesAtOnce() {
        assertNull(remoteAccessPreparation(RemoteAccessAction.TURN_ON, cardReachable = false))
    }

    @Test
    fun theRemoteAccessPreparationNeverAsksPin1() {
        assertFalse(AuthenticationPurpose.REMOTE_ACCESS.needsPin1)
    }

    @Test
    fun openingThePageAsksForNoPermission() {
        assertTrue(remoteAccessPermissions(RemoteAccessAction.OPEN_PAGE) { false }.isEmpty())
        assertTrue(remoteAccessPermissions(RemoteAccessAction.OPEN_PAGE) { true }.isEmpty())
    }

    @Test
    fun turningRemoteAccessOnAsksForNearbyDevicesAndNotifications() {
        assertEquals(
            listOf(
                Manifest.permission.POST_NOTIFICATIONS,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            ),
            remoteAccessPermissions(RemoteAccessAction.TURN_ON) { false },
        )
    }

    @Test
    fun turningRemoteAccessOnAsksOnlyForWhatIsMissing() {
        assertEquals(
            listOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT),
            remoteAccessPermissions(RemoteAccessAction.TURN_ON) { it == Manifest.permission.POST_NOTIFICATIONS },
        )
        assertTrue(remoteAccessPermissions(RemoteAccessAction.TURN_ON) { true }.isEmpty())
    }
}
