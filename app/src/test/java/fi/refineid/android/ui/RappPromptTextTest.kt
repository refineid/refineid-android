// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.rapp.RappAuthRequest
import fi.refineid.android.rapp.RappDisplayText
import fi.refineid.android.rapp.forDisplay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RappPromptTextTest {
    @Test
    fun loginNamesTheComputerAndAsksPin1() {
        val text = rappPromptText(browserAuth())

        assertEquals(R.string.authentication, text.title)
        assertEquals(R.string.rapp_prompt_authenticate, text.body)
        assertEquals(listOf(COMPUTER), text.bodyArgs)
        assertEquals(R.string.pin1, text.pinLabel)
        assertTrue(text.listedDocuments.isEmpty())
    }

    @Test
    fun signingOneDocumentNamesItInTheSentence() {
        val text = rappPromptText(documentSign(listOf(FIRST_DOCUMENT)))

        assertEquals(R.string.signature, text.title)
        assertEquals(R.string.rapp_prompt_sign_document, text.body)
        assertEquals(listOf(COMPUTER, FIRST_DOCUMENT), text.bodyArgs)
        assertEquals(R.string.pin2, text.pinLabel)
        assertTrue(text.listedDocuments.isEmpty())
    }

    @Test
    fun signingWithoutADocumentNameNamesOnlyTheComputer() {
        val text = rappPromptText(documentSign(emptyList()))

        assertEquals(R.string.signature, text.title)
        assertEquals(R.string.rapp_prompt_sign, text.body)
        assertEquals(listOf(COMPUTER), text.bodyArgs)
        assertEquals(R.string.pin2, text.pinLabel)
        assertTrue(text.listedDocuments.isEmpty())
    }

    @Test
    fun signingSeveralDocumentsListsThemInSigningOrder() {
        val names = listOf(FIRST_DOCUMENT, SECOND_DOCUMENT)
        val text = rappPromptText(documentSign(names))

        assertEquals(R.string.signature, text.title)
        assertEquals(R.string.rapp_prompt_sign, text.body)
        assertEquals(listOf(COMPUTER), text.bodyArgs)
        assertEquals(R.string.pin2, text.pinLabel)
        assertEquals(names, text.listedDocuments)
    }

    @Test
    fun signingAPackageNamesItAndListsItsFilesInContainerOrder() {
        val files = listOf(FIRST_DOCUMENT, SECOND_DOCUMENT)
        val text = rappPromptText(documentSign(listOf(PACKAGE), files))

        assertEquals(R.string.signature, text.title)
        assertEquals(R.string.rapp_prompt_sign_document, text.body)
        assertEquals(listOf(COMPUTER, PACKAGE), text.bodyArgs)
        assertEquals(R.string.pin2, text.pinLabel)
        assertEquals(files, text.listedDocuments)
    }

    @Test
    fun aBlankDocumentNameLeavesTheSentenceWithoutOne() {
        val text = rappPromptText(documentSign(listOf(BLANK_DOCUMENT)))

        assertEquals(R.string.rapp_prompt_sign, text.body)
        assertEquals(listOf(COMPUTER), text.bodyArgs)
        assertTrue(text.listedDocuments.isEmpty())
    }

    @Test
    fun theShownPromptCarriesNoPeerChosenControlsWhileTheRequestKeepsThem() {
        val raw = documentSign(listOf(SPOOFED_DOCUMENT), listOf(SPOOFED_DOCUMENT), requester = SPOOFED_COMPUTER)
        val text = rappPromptText(raw.forDisplay())

        assertEquals(R.string.rapp_prompt_sign_document, text.body)
        assertEquals(listOf(SHOWN_COMPUTER, SHOWN_DOCUMENT), text.bodyArgs)
        assertEquals(listOf(SHOWN_DOCUMENT), text.listedDocuments)
        assertEquals(listOf(SPOOFED_DOCUMENT), raw.documentNames)
    }

    @Test
    fun theShownLoginPromptCarriesNoPeerChosenControls() {
        val text = rappPromptText(browserAuth(requester = SPOOFED_COMPUTER).forDisplay())

        assertEquals(listOf(SHOWN_COMPUTER), text.bodyArgs)
    }

    private fun browserAuth(requester: String = COMPUTER) =
        RappAuthRequest.BrowserAuth(
            requestId = REQUEST_ID,
            requester = requester,
            onApproved = { it.close() },
            onDenied = {},
            onShown = {},
        )

    private fun documentSign(
        names: List<String>,
        containedFiles: List<String> = emptyList(),
        requester: String = COMPUTER,
    ) = RappAuthRequest.DocumentSign(
        requestId = REQUEST_ID,
        requester = requester,
        documentNames = names,
        containedFiles = containedFiles,
        onApproved = { it.close() },
        onDenied = {},
        onShown = {},
    )

    private companion object {
        const val REQUEST_ID = "request"
        const val COMPUTER = "Example Computer"
        const val FIRST_DOCUMENT = "contract.pdf"
        const val SECOND_DOCUMENT = "appendix.pdf"
        const val PACKAGE = "contract.asice"
        const val BLANK_DOCUMENT = " "

        /** U+202E RIGHT-TO-LEFT OVERRIDE. */
        const val RIGHT_TO_LEFT_OVERRIDE = "\u202E"

        /** U+000A LINE FEED. */
        const val LINE_FEED = "\u000A"
        const val SPOOFED_COMPUTER = "$COMPUTER${LINE_FEED}Bank"
        const val SPOOFED_DOCUMENT = "invoice${RIGHT_TO_LEFT_OVERRIDE}fdp.exe"
        const val SHOWN_COMPUTER = "$COMPUTER${RappDisplayText.REPLACEMENT}Bank"
        const val SHOWN_DOCUMENT = "invoice${RappDisplayText.REPLACEMENT}fdp.exe"
    }
}
