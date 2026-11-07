package fi.refineid.android.document

import org.junit.Assert.assertEquals
import org.junit.Test
import java.time.Instant

internal class SignedDocumentNameTest {
    @Test
    fun stampsTheInstantInEngineeringIsoWithSafeColons() {
        assertEquals(
            "2026-08-17T15-04-05Z",
            SignedDocumentName.instantStamp(Instant.parse("2026-08-17T15:04:05Z")),
        )
    }

    @Test
    fun truncatesSubSecondPrecisionFromTheStamp() {
        assertEquals(
            "2026-08-17T15-04-05Z",
            SignedDocumentName.instantStamp(Instant.parse("2026-08-17T15:04:05.987654321Z")),
        )
    }

    @Test
    fun marksADevelopmentDocumentBelowLongTermBeforeItsExtension() {
        assertEquals(
            "Agreement - signed at 2026-08-17T15-04-05Z-dev-B-T.pdf",
            SignedDocumentName.belowLongTerm(
                name = "Agreement - signed at 2026-08-17T15-04-05Z.pdf",
                level = PadesBaselineLevel.B_T,
            ),
        )
        assertEquals("scan-dev-B-B", SignedDocumentName.belowLongTerm("scan", PadesBaselineLevel.B_B))
        assertEquals("-dev-B-T", SignedDocumentName.developmentSuffix(PadesBaselineLevel.B_T))
    }

    @Test
    fun keepsTheOriginalBaseAndExtensionAroundTheSignedPhrase() {
        assertEquals(
            "Agreement - signed at 2026-08-17T15-04-05Z.pdf",
            SignedDocumentName.suggested(
                originalName = "Agreement.pdf",
                signedAtPhrase = "signed at 2026-08-17T15-04-05Z",
            ),
        )
    }

    @Test
    fun defaultsToPdfWhenTheOriginalCarriesNoExtension() {
        assertEquals(
            "scan - signed at 2026-08-17T15-04-05Z.pdf",
            SignedDocumentName.suggested(
                originalName = "scan",
                signedAtPhrase = "signed at 2026-08-17T15-04-05Z",
            ),
        )
    }

    @Test
    fun honorsAContainerExtensionOverride() {
        assertEquals(
            "Agreement - signed at 2026-08-17T15-04-05Z.asice",
            SignedDocumentName.suggested(
                originalName = "Agreement.pdf",
                signedAtPhrase = "signed at 2026-08-17T15-04-05Z",
                extensionOverride = "asice",
            ),
        )
    }

    @Test
    fun preservesADottedBaseNameExceptTheFinalExtension() {
        assertEquals(
            "report.final - signed at 2026-08-17T15-04-05Z.pdf",
            SignedDocumentName.suggested(
                originalName = "report.final.pdf",
                signedAtPhrase = "signed at 2026-08-17T15-04-05Z",
            ),
        )
    }
}
