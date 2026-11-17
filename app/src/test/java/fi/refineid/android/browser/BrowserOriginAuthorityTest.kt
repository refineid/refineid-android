// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BrowserOriginAuthorityTest {
    private companion object {
        const val TRUSTED_HOST = "tunnistus.suomi.fi"
        const val OTHER_HOST = "attacker.example.test"
        const val HTTPS_PORT = 443
        const val ALTERNATE_PORT = 8443
        const val LOWEST_PORT = 1
        const val HIGHEST_PORT = 65535

        fun origin(
            host: String = TRUSTED_HOST,
            port: Int = HTTPS_PORT,
        ): BrowserOrigin = requireNotNull(BrowserOrigin.of(host, port))
    }

    @Test
    fun originCanonicalisesHostCaseAndRootDot() {
        assertEquals(origin(), BrowserOrigin.of("Tunnistus.Suomi.FI.", HTTPS_PORT))
        assertEquals(TRUSTED_HOST, origin().host)
    }

    @Test
    fun originDistinguishesPorts() {
        assertNotEquals(origin(), origin(port = ALTERNATE_PORT))
        assertEquals(ALTERNATE_PORT, origin(port = ALTERNATE_PORT).port)
    }

    @Test
    fun originRejectsBlankHostAndPortsOutsideTheTcpRange() {
        assertNull(BrowserOrigin.of(null, HTTPS_PORT))
        assertNull(BrowserOrigin.of("", HTTPS_PORT))
        assertNull(BrowserOrigin.of("   ", HTTPS_PORT))
        assertNull(BrowserOrigin.of(".", HTTPS_PORT))
        assertNull(BrowserOrigin.of(TRUSTED_HOST, LOWEST_PORT - 1))
        assertNull(BrowserOrigin.of(TRUSTED_HOST, HIGHEST_PORT + 1))
    }

    @Test
    fun originAcceptsTheTcpRangeEnds() {
        assertEquals(LOWEST_PORT, origin(port = LOWEST_PORT).port)
        assertEquals(HIGHEST_PORT, origin(port = HIGHEST_PORT).port)
    }

    @Test
    fun displayNameOmitsTheHttpsPortAndShowsAnyOther() {
        assertEquals(TRUSTED_HOST, origin().displayName)
        assertEquals("$TRUSTED_HOST:$ALTERNATE_PORT", origin(port = ALTERNATE_PORT).displayName)
    }

    @Test
    fun isApprovedIsFalseForAnOriginNeverApproved() {
        val authority = BrowserOriginAuthority()
        assertFalse(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(port = ALTERNATE_PORT)))
    }

    @Test
    fun approveCoversThatOriginOnly() {
        val authority = BrowserOriginAuthority()
        authority.approve(origin())

        assertTrue(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(port = ALTERNATE_PORT)))
        assertFalse(authority.isApproved(origin(host = OTHER_HOST)))
    }

    @Test
    fun initialApprovedOriginsAreRespected() {
        val authority = BrowserOriginAuthority(setOf(origin()))

        assertTrue(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(port = ALTERNATE_PORT)))
        assertFalse(authority.isApproved(origin(host = OTHER_HOST)))
    }

    @Test
    fun enqueueIsFirstPerOriginOnly() {
        val authority = BrowserOriginAuthority()
        val first = authority.enqueue(origin(), {}, {})
        val second = authority.enqueue(origin(), {}, {})
        val otherPort = authority.enqueue(origin(port = ALTERNATE_PORT), {}, {})
        val otherHost = authority.enqueue(origin(host = OTHER_HOST), {}, {})

        assertTrue(first)
        assertFalse(second)
        assertTrue(otherPort)
        assertTrue(otherHost)
    }

    @Test
    fun completeWithApprovedRunsAllProceedCallbacksAndMarksThatOriginApproved() {
        val authority = BrowserOriginAuthority()
        var proceedCount = 0
        var cancelCount = 0

        authority.enqueue(
            origin(),
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )
        authority.enqueue(
            origin(),
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )

        authority.complete(origin(), approved = true)

        assertEquals(2, proceedCount)
        assertEquals(0, cancelCount)
        assertTrue(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(port = ALTERNATE_PORT)))
    }

    @Test
    fun completeWithRejectedRunsAllCancelCallbacksAndDoesNotApproveOrigin() {
        val authority = BrowserOriginAuthority()
        var proceedCount = 0
        var cancelCount = 0

        authority.enqueue(
            origin(),
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )
        authority.enqueue(
            origin(),
            onProceed = { proceedCount++ },
            onCancel = { cancelCount++ },
        )

        authority.complete(origin(), approved = false)

        assertEquals(0, proceedCount)
        assertEquals(2, cancelCount)
        assertFalse(authority.isApproved(origin()))
    }

    @Test
    fun completeLeavesAnotherOriginsQueuePending() {
        val authority = BrowserOriginAuthority()
        var otherProceeds = 0

        authority.enqueue(origin(), {}, {})
        authority.enqueue(origin(port = ALTERNATE_PORT), onProceed = { otherProceeds++ }, {})

        authority.complete(origin(), approved = true)

        assertEquals(0, otherProceeds)
        assertFalse(authority.isApproved(origin(port = ALTERNATE_PORT)))
        assertTrue(authority.enqueue(origin(port = ALTERNATE_PORT), {}, {}).not())
    }

    @Test
    fun cancelAllCancelsPendingAcrossAllOrigins() {
        val authority = BrowserOriginAuthority()
        var cancels = 0

        authority.enqueue(origin(), {}, { cancels++ })
        authority.enqueue(origin(host = OTHER_HOST), {}, { cancels++ })

        authority.cancelAll()

        assertEquals(2, cancels)
        assertFalse(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(host = OTHER_HOST)))
    }

    @Test
    fun clearCancelsPendingAndRevokesApproved() {
        val authority = BrowserOriginAuthority()
        authority.approve(origin())
        var cancels = 0
        authority.enqueue(origin(host = OTHER_HOST), {}, { cancels++ })

        authority.clear()

        assertEquals(1, cancels)
        assertFalse(authority.isApproved(origin()))
        assertFalse(authority.isApproved(origin(host = OTHER_HOST)))
    }
}
