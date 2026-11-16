// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserOriginAuthorityTest {
    private companion object {
        const val TRUSTED_HOST = "tunnistus.suomi.fi"
        const val OTHER_HOST = "attacker.example.test"
    }

    @Test
    fun isApprovedReturnsFalseForNullBlankOrUnknownHost() {
        val authority = BrowserOriginAuthority()
        assertFalse(authority.isApproved(null))
        assertFalse(authority.isApproved(""))
        assertFalse(authority.isApproved("   "))
        assertFalse(authority.isApproved(TRUSTED_HOST))
    }

    @Test
    fun approveAddsHostToApprovedSet() {
        val authority = BrowserOriginAuthority()
        authority.approve(TRUSTED_HOST)
        assertTrue(authority.isApproved(TRUSTED_HOST))
        assertFalse(authority.isApproved(OTHER_HOST))
    }

    @Test
    fun initialApprovedHostsAreRespected() {
        val authority = BrowserOriginAuthority(setOf(TRUSTED_HOST))
        assertTrue(authority.isApproved(TRUSTED_HOST))
        assertFalse(authority.isApproved(OTHER_HOST))
    }

    @Test
    fun enqueueReturnsTrueForFirstRequestAndFalseForSubsequent() {
        val authority = BrowserOriginAuthority()
        val first = authority.enqueue(TRUSTED_HOST, {}, {})
        val second = authority.enqueue(TRUSTED_HOST, {}, {})
        val other = authority.enqueue(OTHER_HOST, {}, {})

        assertTrue(first)
        assertFalse(second)
        assertTrue(other)
    }

    @Test
    fun completeWithApprovedRunsAllProceedCallbacksAndMarksHostApproved() {
        val authority = BrowserOriginAuthority()
        var proceedCount = 0
        var cancelCount = 0

        authority.enqueue(
            TRUSTED_HOST,
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )
        authority.enqueue(
            TRUSTED_HOST,
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )

        authority.complete(TRUSTED_HOST, approved = true)

        assertEquals(2, proceedCount)
        assertEquals(0, cancelCount)
        assertTrue(authority.isApproved(TRUSTED_HOST))
    }

    @Test
    fun completeWithRejectedRunsAllCancelCallbacksAndDoesNotApproveHost() {
        val authority = BrowserOriginAuthority()
        var proceedCount = 0
        var cancelCount = 0

        authority.enqueue(
            TRUSTED_HOST,
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )
        authority.enqueue(
            TRUSTED_HOST,
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )

        authority.complete(TRUSTED_HOST, approved = false)

        assertEquals(0, proceedCount)
        assertEquals(2, cancelCount)
        assertFalse(authority.isApproved(TRUSTED_HOST))
    }

    @Test
    fun cancelAllCancelsPendingAcrossAllHosts() {
        val authority = BrowserOriginAuthority()
        var cancels = 0

        authority.enqueue(TRUSTED_HOST, {}, { cancels++ })
        authority.enqueue(OTHER_HOST, {}, { cancels++ })

        authority.cancelAll()

        assertEquals(2, cancels)
        assertFalse(authority.isApproved(TRUSTED_HOST))
        assertFalse(authority.isApproved(OTHER_HOST))
    }

    @Test
    fun clearCancelsPendingAndRevokesApproved() {
        val authority = BrowserOriginAuthority()
        authority.approve(TRUSTED_HOST)
        var cancels = 0
        authority.enqueue(OTHER_HOST, {}, { cancels++ })

        authority.clear()

        assertEquals(1, cancels)
        assertFalse(authority.isApproved(TRUSTED_HOST))
        assertFalse(authority.isApproved(OTHER_HOST))
    }
}
