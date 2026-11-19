// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.QualifiedSignFailure
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

class DocumentSigningFailureTest {
    @Test
    fun aFailureBeforeTheSignatureSaysNoSignedDocumentWasMade() {
        val stops = QualifiedSignFailure.entries.map { it.signingStop() }

        stops.filterIsInstance<DocumentSigningStop.Failed>().forEach { stop ->
            assertEquals(SigningFailureOutcome.NOT_SIGNED, stop.failure.outcome)
            assertReadableEverywhere(stop.failure)
        }
        NativeCertificateReadFailure.entries.map { it.signingFailure() }.forEach { failure ->
            assertEquals(SigningFailureOutcome.NOT_SIGNED, failure.outcome)
            assertReadableEverywhere(failure)
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
        assertEquals(WRONG_PIN_AND_PIN_LOCKED_KEEP_STATUS, statusStops.size)
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

        /** WRONG_PIN and PIN_LOCKED keep their status instead of failing. */
        const val WRONG_PIN_AND_PIN_LOCKED_KEEP_STATUS = 2
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
