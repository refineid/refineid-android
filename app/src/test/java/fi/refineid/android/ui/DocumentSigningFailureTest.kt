// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.asic.AsicSigningFailure
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.document.PadesBaselineLevel
import fi.refineid.android.document.PdfSigningFailure
import fi.refineid.android.document.QualifiedDocumentCmsFailure
import fi.refineid.android.document.QualifiedPdfArchivalFailure
import fi.refineid.android.document.QualifiedPdfSigningFailure
import fi.refineid.android.document.QualifiedPdfTimestampPhase
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationPathRole
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class DocumentSigningFailureTest {
    @Test
    fun anIssuerThatCannotBeFoundReadsAsTheHolderSentenceInEveryLanguage() {
        val failure =
            QualifiedPdfArchivalFailure
                .Validation(ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE, pathRole = null)
                .signingFailure()

        assertEquals(
            "The signature was made, but the material for long-term validation could not be collected: " +
                "the issuer of the certificate could not be found. " +
                "No signed document was made and nothing was saved. " +
                "Check the network connection and sign again.",
            ENGLISH.text(failure),
        )
        assertEquals(
            "Allekirjoitus tehtiin, mutta pitkäaikaisen validoinnin aineistoa ei saatu kerättyä: " +
                "varmenteen myöntäjää ei löytynyt. " +
                "Allekirjoitettua asiakirjaa ei syntynyt, eikä mitään tallennettu. " +
                "Tarkista verkkoyhteys ja allekirjoita uudelleen.",
            FINNISH.text(failure),
        )
        assertEquals(
            "Signaturen skapades, men materialet för långtidsvalidering kunde inte samlas in: " +
                "certifikatets utfärdare hittades inte. " +
                "Inget signerat dokument skapades och ingenting sparades. " +
                "Kontrollera nätverksanslutningen och signera igen.",
            SWEDISH.text(failure),
        )
    }

    @Test
    fun aDevelopmentDocumentBelowLongTermNamesItsLevelMarkAndCause() {
        val notice =
            BelowLongTermNotice(
                level = PadesBaselineLevel.B_T,
                failure =
                    QualifiedPdfArchivalFailure
                        .Validation(ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE, pathRole = null)
                        .signingFailure(),
            )

        assertEquals(
            "Development build: saved as PAdES B-T without long-term validation material; " +
                "the file name ends in -dev-B-T. Reason: the material for long-term validation " +
                "could not be collected: the issuer of the certificate could not be found.",
            notice.text(ENGLISH::string, ENGLISH::formatList),
        )
    }

    @Test
    fun everyValidationKindAndPathHasItsOwnCauseAndDiscardsTheSignature() {
        val failures = validationCases().map { (kind, role) -> validationFailure(kind, role) }

        failures.forEach { failure ->
            assertEquals(SigningFailureOutcome.SIGNATURE_DISCARDED, failure.outcome)
            assertEquals(R.string.signing_frame_validation_material, failure.frame)
        }
        val revoked = ValidationMaterialCollectionFailure.REVOKED
        val causes = failures.map { it.cause }
        val expectedDistinct =
            ValidationMaterialCollectionFailure.entries.size - 1 + ValidationPathRole.entries.size + 1
        assertEquals(expectedDistinct, causes.toSet().size)
        assertEquals(
            R.string.signing_cause_signer_revoked,
            validationFailure(revoked, ValidationPathRole.DOCUMENT_SIGNER).cause,
        )
        assertEquals(
            R.string.signing_cause_timestamp_authority_revoked,
            validationFailure(revoked, ValidationPathRole.TIMESTAMP_AUTHORITY).cause,
        )
    }

    @Test
    fun everyArchivalFailureSaysTheSignatureWasMadeAndDiscarded() {
        val pdf = pdfArchivalFailures().map { it.signingFailure() }
        val container =
            listOf(
                AsicSigningFailure.Timestamp,
                AsicSigningFailure.ValidationUnavailable,
                AsicSigningFailure.ContainerOverflow,
                AsicSigningFailure.InternalError,
            ) +
                validationCases().map { (kind, role) -> AsicSigningFailure.Validation(kind, role) }

        pdf.forEach { failure ->
            assertEquals(SigningFailureOutcome.SIGNATURE_DISCARDED, failure.outcome)
            assertReadableEverywhere(failure)
        }
        container.forEach { reason ->
            val failure = (reason.signingStop() as DocumentSigningStop.Failed).failure
            assertEquals(reason.toString(), SigningFailureOutcome.SIGNATURE_DISCARDED, failure.outcome)
            assertReadableEverywhere(failure)
        }
        assertEquals(
            R.string.signing_cause_signature_timestamp_failed,
            QualifiedPdfArchivalFailure.Timestamp(QualifiedPdfTimestampPhase.SIGNATURE).signingFailure().cause,
        )
        assertEquals(
            R.string.signing_cause_archive_timestamp_failed,
            QualifiedPdfArchivalFailure.Timestamp(QualifiedPdfTimestampPhase.ARCHIVE).signingFailure().cause,
        )
    }

    @Test
    fun aFailureBeforeTheSignatureSaysNoSignedDocumentWasMade() {
        val stops =
            QualifiedSignFailure.entries.map { QualifiedPdfSigningFailure.Card(it).signingStop() } +
                NativeCertificateReadFailure.entries.map { QualifiedPdfSigningFailure.Certificate(it).signingStop() } +
                PdfSigningFailure.entries.map { QualifiedPdfSigningFailure.Document(it).signingStop() } +
                QualifiedDocumentCmsFailure.entries.map { QualifiedPdfSigningFailure.Cms(it).signingStop() } +
                listOf(
                    QualifiedPdfSigningFailure.KeyProfileUnsupported.signingStop(),
                    QualifiedPdfSigningFailure.InternalError.signingStop(),
                    AsicSigningFailure.UnusableNames.signingStop(),
                    AsicSigningFailure.KeyProfileUnsupported.signingStop(),
                ) +
                QualifiedSignFailure.entries.map { AsicSigningFailure.Card(it).signingStop() } +
                NativeCertificateReadFailure.entries.map { AsicSigningFailure.Certificate(it).signingStop() }

        stops.filterIsInstance<DocumentSigningStop.Failed>().forEach { stop ->
            assertEquals(SigningFailureOutcome.NOT_SIGNED, stop.failure.outcome)
            assertReadableEverywhere(stop.failure)
        }
        assertEquals(
            DocumentSigningStop.Status(DocumentSigningStatus.WRONG_PIN),
            QualifiedSignFailure.WRONG_PIN.signingStop(),
        )
        assertEquals(
            DocumentSigningStop.Status(DocumentSigningStatus.PIN_LOCKED),
            QualifiedSignFailure.PIN_LOCKED.signingStop(),
        )
        val statusStops = stops.filterIsInstance<DocumentSigningStop.Status>()
        assertEquals(WRONG_AND_LOCKED_PER_FAILURE_SOURCE, statusStops.size)
    }

    @Test
    fun theSessionFailuresReadInEveryLanguage() {
        listOf(
            CardNotReadyFailure,
            FileUnreadableFailure,
            TimestampSettingsFailure,
            internalFailure(SigningFailureOutcome.NOT_SIGNED),
            internalFailure(SigningFailureOutcome.SIGNATURE_DISCARDED),
            saveFailure(partly = false),
            saveFailure(partly = true),
        ).forEach(::assertReadableEverywhere)
        assertEquals(SigningFailureOutcome.PARTLY_SAVED, saveFailure(partly = true).outcome)
        assertEquals(SigningFailureOutcome.NOT_SAVED, saveFailure(partly = false).outcome)
    }

    @Test
    fun noStringSplitsAPinNameFromItsNumber() {
        LOCALES.forEach { locale ->
            locale.texts.forEach { (name, text) ->
                assertFalse(locale.directory + "/" + name, SPLIT_PIN_NAME.containsMatchIn(text))
            }
        }
        assertTrue(ENGLISH.texts.getValue("pin2").contains(NO_BREAK_SPACE))
        assertEquals("Allekirjoitustunnusluku" + NO_BREAK_SPACE + "2", FINNISH.texts.getValue("pin2"))
        assertEquals("Signaturkod" + NO_BREAK_SPACE + "2", SWEDISH.texts.getValue("pin2"))
    }

    private fun assertReadableEverywhere(failure: DocumentSigningFailure) {
        LOCALES.forEach { locale ->
            val text = locale.text(failure)
            assertFalse(locale.directory + ": " + text, text.contains(FORMAT_MARK))
            assertTrue(locale.directory + ": " + text, text.endsWith(SENTENCE_END))
        }
    }

    private fun validationCases(): List<Pair<ValidationMaterialCollectionFailure, ValidationPathRole?>> =
        ValidationMaterialCollectionFailure.entries.flatMap { kind ->
            if (kind == ValidationMaterialCollectionFailure.REVOKED) {
                (ValidationPathRole.entries + listOf(null)).map { role -> kind to role }
            } else {
                listOf(kind to null)
            }
        }

    private fun pdfArchivalFailures(): List<QualifiedPdfArchivalFailure> =
        QualifiedPdfTimestampPhase.entries.map { QualifiedPdfArchivalFailure.Timestamp(it) } +
            validationCases().map { (kind, role) -> QualifiedPdfArchivalFailure.Validation(kind, role) } +
            QualifiedDocumentCmsFailure.entries.map { QualifiedPdfArchivalFailure.Cms(it) } +
            PdfSigningFailure.entries.map { QualifiedPdfArchivalFailure.Document(it) } +
            listOf(
                QualifiedPdfArchivalFailure.ValidationUnavailable,
                QualifiedPdfArchivalFailure.InternalError,
            )

    /** One resource directory's strings, resolved the way Android resolves them. */
    private class Locale(
        val directory: String,
    ) {
        val texts: Map<String, String> =
            File(RESOURCE_ROOT, directory)
                .listFiles { file -> file.name.endsWith(XML_SUFFIX) }
                .orEmpty()
                .flatMap { file -> strings(file) }
                .toMap()

        fun string(id: Int): String {
            val name = STRING_NAMES.getValue(id)
            val text = texts[name] ?: ENGLISH_TEXTS[name]
            assertNotNull(directory + " lacks " + name, text)
            return checkNotNull(text)
        }

        fun format(
            id: Int,
            argument: String,
        ): String = formatList(id, listOf(argument))

        fun formatList(
            id: Int,
            arguments: List<String>,
        ): String = String.format(string(id), *arguments.toTypedArray())

        fun text(failure: DocumentSigningFailure): String = failure.text(::string, ::format)
    }

    private companion object {
        const val RESOURCE_ROOT = "src/main/res"
        const val XML_SUFFIX = ".xml"
        const val FORMAT_MARK = "%"
        const val SENTENCE_END = "."
        const val NO_BREAK_SPACE = " "

        /** WRONG_PIN and PIN_LOCKED keep their status, once for PDF and once for ASiC card failures. */
        const val WRONG_AND_LOCKED_PER_FAILURE_SOURCE = 4
        val SPLIT_PIN_NAME = Regex("(PIN|kod|tunnuslu\\p{L}*) [12](?!\\d)")
        val STRING_NAMES: Map<Int, String> =
            R.string::class.java.fields.associate { field -> field.getInt(null) to field.name }
        val ENGLISH_TEXTS: Map<String, String> by lazy { ENGLISH.texts }
        val ENGLISH = Locale("values")
        val FINNISH = Locale("values-fi")
        val SWEDISH = Locale("values-sv")
        val LOCALES = listOf(ENGLISH, FINNISH, SWEDISH)

        fun strings(file: File): List<Pair<String, String>> {
            val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
            val nodes = document.getElementsByTagName("string")
            return (0 until nodes.length).map { index ->
                val node = nodes.item(index)
                val name = node.attributes.getNamedItem("name").nodeValue
                name to node.textContent.replace("\\'", "'").replace("\\n", "\n")
            }
        }
    }
}
