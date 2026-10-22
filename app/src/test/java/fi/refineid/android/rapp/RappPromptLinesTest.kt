// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Test

/** What a PIN prompt names: the computer and the program that asked, each labelled, never a site. */
class RappPromptLinesTest {
    @Test
    fun aLoginNamesTheComputerAndTheProgram() {
        assertEquals(
            listOf(
                RappPromptLine(RappPromptParty.COMPUTER, COMPUTER),
                RappPromptLine(RappPromptParty.PROGRAM, PROGRAM),
            ),
            rappPromptLines(login(PROGRAM)),
        )
    }

    @Test
    fun aLoginWithoutAProgramNamesTheComputer() {
        assertEquals(
            listOf(RappPromptLine(RappPromptParty.COMPUTER, COMPUTER)),
            rappPromptLines(login(BLANK)),
        )
    }

    @Test
    fun aSignatureNamesTheComputerAndListsItsDocumentsElsewhere() {
        val request =
            RappAuthRequest.DocumentSign(
                requestId = REQUEST_ID,
                requester = COMPUTER,
                documentNames = listOf(DOCUMENT),
                onApproved = { it.close() },
                onDenied = {},
                onShown = {},
            )
        assertEquals(listOf(RappPromptLine(RappPromptParty.COMPUTER, COMPUTER)), rappPromptLines(request))
    }

    private fun login(program: String): RappAuthRequest.BrowserAuth =
        RappAuthRequest.BrowserAuth(
            requestId = REQUEST_ID,
            requester = COMPUTER,
            program = program,
            onApproved = { it.close() },
            onDenied = {},
            onShown = {},
        )

    private companion object {
        const val REQUEST_ID = "synthetic request"
        const val COMPUTER = "synthetic computer"
        const val PROGRAM = "synthetic program on synthetic computer"
        const val DOCUMENT = "synthetic document.pdf"
        const val BLANK = " "
    }
}
