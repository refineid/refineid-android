// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NfcTagReachTest {
    @Test
    fun aConnectedHandleReachesTheCard() {
        assertTrue(tagReachable { true })
        assertFalse(tagReachable { false })
    }

    @Test
    fun anOutOfDateHandleMeansTheTagIsGone() {
        assertFalse(tagReachable { throw SecurityException("synthetic out-of-date tag") })
    }

    @Test
    fun aStoppedTagServiceMeansTheTagIsGone() {
        assertFalse(tagReachable { throw IllegalStateException("synthetic stopped tag service") })
    }
}
