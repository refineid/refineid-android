// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.core.AuthenticationPurpose
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
}
