// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every secret entry field is [SecretField], the one field that reports
 * only bullets to accessibility and stays out of autofill: no other
 * production source builds a password field of its own.
 */
internal class SecretFieldSourceTest {
    @Test
    fun onlySecretFieldBuildsAPasswordField() {
        val sources =
            File(SOURCE_ROOT)
                .walkTopDown()
                .filter { file -> file.isFile && file.extension == KOTLIN_EXTENSION }
                .toList()
        assertTrue("production sources found", sources.isNotEmpty())

        val offenders =
            sources
                .filter { file -> file.name != SECRET_FIELD_FILE }
                .flatMap { file ->
                    val text = file.readText()
                    PASSWORD_FIELD_MARKERS
                        .filter { marker -> marker.containsMatchIn(text) }
                        .map { marker -> "${file.name}: ${marker.pattern}" }
                }
        assertEquals(emptyList<String>(), offenders)
    }

    private companion object {
        const val SOURCE_ROOT = "src/main/java"
        const val KOTLIN_EXTENSION = "kt"
        const val SECRET_FIELD_FILE = "SecretField.kt"
        val PASSWORD_FIELD_MARKERS =
            listOf(
                Regex("""\bSecureTextField\b"""),
                Regex("""\bBasicSecureTextField\b"""),
                Regex("""\bOutlinedSecureTextField\b"""),
                Regex("""\bPasswordVisualTransformation\b"""),
                Regex("""\bTextObfuscationMode\b"""),
                Regex("""\bKeyboardType\.NumberPassword\b"""),
                Regex("""\bPasswordTransformationMethod\b"""),
            )
    }
}
