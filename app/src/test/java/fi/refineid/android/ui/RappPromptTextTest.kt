// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import fi.refineid.android.R
import fi.refineid.android.rapp.RappAuthRequest
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
    fun aBlankDocumentNameLeavesTheSentenceWithoutOne() {
        val text = rappPromptText(documentSign(listOf(BLANK_DOCUMENT)))

        assertEquals(R.string.rapp_prompt_sign, text.body)
        assertEquals(listOf(COMPUTER), text.bodyArgs)
        assertTrue(text.listedDocuments.isEmpty())
    }

    private fun browserAuth() =
        RappAuthRequest.BrowserAuth(
            requestId = REQUEST_ID,
            requester = COMPUTER,
            onApproved = { it.close() },
            onDenied = {},
            onShown = {},
        )

    private fun documentSign(names: List<String>) =
        RappAuthRequest.DocumentSign(
            requestId = REQUEST_ID,
            requester = COMPUTER,
            documentNames = names,
            onApproved = { it.close() },
            onDenied = {},
            onShown = {},
        )

    private companion object {
        const val REQUEST_ID = "request"
        const val COMPUTER = "Example Computer"
        const val FIRST_DOCUMENT = "contract.pdf"
        const val SECOND_DOCUMENT = "appendix.pdf"
        const val BLANK_DOCUMENT = " "
    }
}
