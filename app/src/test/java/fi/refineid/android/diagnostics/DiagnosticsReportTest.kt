package fi.refineid.android.diagnostics

import fi.refineid.android.core.PersonCardDetails
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticsReportTest {
    @Test
    fun generationCutoverBoundaries() {
        assertEquals(
            "Older (PUK activation code, issued before 13.1.2026)",
            cardGenerationLabel("12.1.2026"),
        )
        assertEquals(
            "Newer (preset activation PIN, issued on/after 13.1.2026)",
            cardGenerationLabel("13.1.2026"),
        )
        assertEquals(
            "Newer (preset activation PIN, issued on/after 13.1.2026)",
            cardGenerationLabel("14.1.2026"),
        )
    }

    @Test
    fun generationMissingOrUnparseable() {
        assertEquals(
            "unknown (no issue date)",
            cardGenerationLabel(null),
        )
        assertEquals(
            "unknown (unparseable issue date)",
            cardGenerationLabel("2026-01-14"),
        )
        assertEquals(
            "unknown (unparseable issue date)",
            cardGenerationLabel("not a date"),
        )
    }

    @Test
    fun cardStatusOmitsHolderIdentity() {
        val details =
            PersonCardDetails(
                holderName = "Test Holder 010280-123A",
                fullName = "Test Holder",
                issuedDate = "14.1.2026",
                expiryDate = "14.1.2031",
                issuer = "Test Issuer",
                signatureAlgorithm = "SHA384withECDSA",
                isTamperProofVerified = false,
                documentNumber = "ABC123456",
            )

        val status = cardStatusText(details)

        assertFalse(status.contains("Holder:"))
        assertFalse(status.contains("Document Number:"))
        assertFalse(status.contains("Valid:"))
        assertFalse(status.contains("Test Holder"))
        assertFalse(status.contains("ABC123456"))
        assertFalse(status.contains("14.1.2026"))
        assertFalse(status.contains("14.1.2031"))
        assertTrue(status.contains("Newer (preset activation PIN, issued on/after 13.1.2026)"))
        assertTrue(status.contains("Issuer: Test Issuer"))
    }

    @Test
    fun cardStatusWithoutDetailsOmitsIdentity() {
        val status = cardStatusText(null)

        assertFalse(status.contains("Holder:"))
        assertFalse(status.contains("Document Number:"))
        assertFalse(status.contains("Valid:"))
        assertTrue(status.contains("unknown (no issue date)"))
    }
}
