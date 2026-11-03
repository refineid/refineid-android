// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * The custodian's identity the requester offers to local consumers (RAPP
 * v26.11.2 section 8.4 item 3): confirmed while a session stands, kept
 * through the grace after a report of absence or a lost session, and
 * withdrawn at once on forgetting, revocation and withdrawal.
 */
class RappIdentityOfferTest {
    private companion object {
        const val NOW_MS = 10_000L

        /** The offer grace of section 8.4 item 3, in milliseconds. */
        const val SPEC_GRACE_MS = 120_000L

        /** A millisecond inside or outside the grace. */
        const val GRACE_MARGIN_MS = 1L
        const val WITHIN_GRACE_MS = NOW_MS + SPEC_GRACE_MS - GRACE_MARGIN_MS
        const val GRACE_END_MS = NOW_MS + SPEC_GRACE_MS
        const val AFTER_GRACE_MS = NOW_MS + SPEC_GRACE_MS + GRACE_MARGIN_MS
        const val PAST_TWO_GRACES_MS = NOW_MS + SPEC_GRACE_MS + SPEC_GRACE_MS
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private fun certificate(): RappCertificate {
        val der = RappTestCertificate.der
        assumeTrue("OpenSSL makes the synthetic certificate", der != null)
        return checkNotNull(RappCertificate.fromDer(checkNotNull(der)))
    }

    @Test
    fun theGraceIsTheSpecBound() {
        assertEquals(SPEC_GRACE_MS, RappIdentityOffer.GRACE_MS)
    }

    @Test
    fun aConfirmedCardIsOfferedWithNothingWithheld() {
        val offer = RappIdentityOffer()
        assertNull(offer.offered(NOW_MS))
        val certificate = certificate()
        offer.confirmCard(certificate)
        assertSame(certificate, offer.offered(NOW_MS))
        assertSame(certificate, offer.offered(GRACE_END_MS))
    }

    @Test
    fun aReportOfAbsenceKeepsTheOfferThroughTheGrace() {
        val offer = RappIdentityOffer()
        val certificate = certificate()
        offer.confirmCard(certificate)
        offer.startGrace(NOW_MS)
        assertSame(certificate, offer.offered(WITHIN_GRACE_MS))
        assertNull(offer.offered(GRACE_END_MS))
        assertNull(offer.offered(AFTER_GRACE_MS))
    }

    @Test
    fun aLostSessionKeepsTheOfferThroughTheGrace() {
        val offer = RappIdentityOffer()
        val certificate = certificate()
        offer.confirmCard(certificate)
        offer.startGrace(NOW_MS)
        assertSame(certificate, offer.offered(NOW_MS))
        assertNull(offer.offered(GRACE_END_MS))
    }

    @Test
    fun theGraceIsNotExtendedByAnotherReport() {
        val offer = RappIdentityOffer()
        val certificate = certificate()
        offer.confirmCard(certificate)
        offer.startGrace(NOW_MS)
        offer.startGrace(WITHIN_GRACE_MS)
        assertNull(offer.offered(GRACE_END_MS))
    }

    @Test
    fun aCardConfirmedAgainIsOfferedAnew() {
        val offer = RappIdentityOffer()
        val certificate = certificate()
        offer.confirmCard(certificate)
        offer.startGrace(NOW_MS)
        offer.confirmCard(certificate)
        assertSame(certificate, offer.offered(GRACE_END_MS))
        assertSame(certificate, offer.offered(PAST_TWO_GRACES_MS))
    }

    @Test
    fun withdrawingDropsTheOfferAtOnce() {
        val offer = RappIdentityOffer()
        offer.confirmCard(certificate())
        offer.withdraw()
        assertNull(offer.offered(NOW_MS))
    }

    @Test
    fun aGraceWithNothingOfferedOffersNothing() {
        val offer = RappIdentityOffer()
        offer.startGrace(NOW_MS)
        assertNull(offer.offered(NOW_MS))
    }
}
