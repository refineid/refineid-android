// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_doc_sign_android.VerifyFailure
import java.nio.file.Files

class CoreDocumentsTest {
    @Test
    fun stagedNamesKeepTheLastSegmentAndSeparateRepeats() {
        assertEquals(
            listOf("letter.pdf", "0-annex.pdf", "1-annex.pdf", "document"),
            CoreDocuments.stagedNames(listOf("dir/letter.pdf", "annex.pdf", "other/annex.pdf", "")),
        )
    }

    @Test
    fun aPlainTextInputIsNoSignedDocumentAndItsStagingIsRemoved() {
        val work = Files.createTempDirectory(WORK_PREFIX).toFile()
        try {
            assertThrows(VerifyFailure.NotASignedDocument::class.java) {
                CoreDocuments.verify(NamedInput(PLAIN_NAME) { PLAIN_TEXT.byteInputStream() }, work)
            }
            assertTrue(checkNotNull(work.listFiles()).isEmpty())
        } finally {
            work.deleteRecursively()
        }
    }

    private companion object {
        const val WORK_PREFIX = "core-documents-test"
        const val PLAIN_NAME = "note.txt"
        const val PLAIN_TEXT = "plain text"
    }
}
