// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import javax.security.auth.x500.X500Principal

class CertificateHolderNameTest {
    @Test
    fun anOrganisationCardNamesTheOrganisationAfterTheHolder() {
        val subject = X500Principal(ORGANISATION_SUBJECT)

        assertEquals("Juutilainen Denis, Testiorganisaatio Oy", CertificateHolderName.lineFromSubject(subject))
        assertEquals("Juutilainen Denis", CertificateHolderName.nameFromSubject(subject))
        assertEquals("Testiorganisaatio Oy", CertificateHolderName.organizationName(subject))
    }

    @Test
    fun aCitizenCardShowsTheHolderAlone() {
        val subject = X500Principal(CITIZEN_SUBJECT)

        assertEquals("MEIKALAINEN MATTI", CertificateHolderName.lineFromSubject(subject))
        assertNull(CertificateHolderName.organizationName(subject))
    }

    @Test
    fun theOrganisationIsShownVerbatimWithItsComma() {
        val subject = X500Principal("O=Testi\\, Esimerkki Oy,CN=Juutilainen Denis 99905322A")

        assertEquals("Juutilainen Denis, Testi, Esimerkki Oy", CertificateHolderName.lineFromSubject(subject))
    }

    @Test
    fun anEmptyOrganisationIsNotShown() {
        val subject = X500Principal("O=,CN=Juutilainen Denis 99905322A")

        assertEquals("Juutilainen Denis", CertificateHolderName.lineFromSubject(subject))
    }

    private companion object {
        const val ORGANISATION_SUBJECT =
            "C=FI,O=Testiorganisaatio Oy,2.5.4.5=99905322A,2.5.4.42=Denis,2.5.4.4=Juutilainen," +
                "CN=Juutilainen Denis 99905322A"
        const val CITIZEN_SUBJECT =
            "C=FI,2.5.4.5=12345678A,2.5.4.42=MATTI,2.5.4.4=MEIKALAINEN,CN=MEIKALAINEN MATTI 12345678A"
    }
}
