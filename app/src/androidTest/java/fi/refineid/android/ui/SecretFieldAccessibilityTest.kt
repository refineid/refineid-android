// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.remember
import androidx.compose.ui.autofill.ContentDataType
import androidx.compose.ui.autofill.FillableData
import androidx.compose.ui.semantics.SemanticsConfiguration
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.CanSessionStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Reads the semantics tree, which is what accessibility services, autofill
 * and content capture see, after synthetic secrets are typed into the
 * app's secret fields: every field reports one bullet per typed digit and
 * no digit anywhere, hidden or revealed.
 */
@RunWith(AndroidJUnit4::class)
internal class SecretFieldAccessibilityTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Before
    fun setUp() {
        CanSessionStore.drop()
    }

    @Test
    fun signingScreenReportsOnlyBulletsForPin2AndCan() {
        composeRule.setContent {
            RefineIdTheme {
                DocumentSigningCard(
                    hasDocument = true,
                    documentNames = listOf(SYNTHETIC_DOCUMENT_NAME),
                    canSignPdf = true,
                    canRequired = true,
                    canSign = true,
                    status = DocumentSigningStatus.IDLE,
                    onChooseDocuments = {},
                    onAddDocument = {},
                    onSign = { _, pin2, can ->
                        pin2.close()
                        can?.close()
                    },
                )
            }
        }
        val typed =
            mapOf(
                UiAutomationIds.PIN2_FIELD to SYNTHETIC_PIN2,
                UiAutomationIds.DOCUMENT_CAN_FIELD to SYNTHETIC_CAN,
            )
        typeInto(typed)
        assertOnlyBullets(typed)

        composeRule.onNodeWithTag(secretRevealTestTag(UiAutomationIds.DOCUMENT_CAN_FIELD)).performClick()
        assertOnlyBullets(typed)
    }

    @Test
    fun organisationPin1EntryReportsOnlyBullets() {
        composeRule.setContent {
            RefineIdTheme {
                OrganizationPin1Entry(
                    attemptsLeft = null,
                    answer = null,
                    isOpening = false,
                    onSubmit = { submission -> submission.close() },
                )
            }
        }
        val typed = mapOf(UiAutomationIds.NFC_ORGANIZATION_PIN1_FIELD to SYNTHETIC_PIN1)
        typeInto(typed)
        assertOnlyBullets(typed)
    }

    @Test
    fun revealedAndPasswordFieldsReportOnlyBullets() {
        composeRule.setContent {
            RefineIdTheme {
                Column {
                    SecretField(
                        state = remember { TextFieldState() },
                        testTag = REVEALABLE_TAG,
                        label = SYNTHETIC_LABEL,
                        revealNames = PinRevealNames,
                    )
                    SecretField(
                        state = remember { TextFieldState() },
                        testTag = PASSWORD_TAG,
                        label = SYNTHETIC_LABEL,
                        keyboardType = KeyboardType.Password,
                    )
                }
            }
        }
        val typed = mapOf(REVEALABLE_TAG to SYNTHETIC_PUK, PASSWORD_TAG to SYNTHETIC_PASSWORD)
        typeInto(typed)
        assertOnlyBullets(typed)

        composeRule.onNodeWithTag(secretRevealTestTag(REVEALABLE_TAG)).performClick()
        assertOnlyBullets(typed)
    }

    private fun typeInto(typed: Map<String, String>) {
        typed.forEach { (tag, secret) -> composeRule.onNodeWithTag(tag).performTextInput(secret) }
        composeRule.waitForIdle()
    }

    private fun assertOnlyBullets(typed: Map<String, String>) {
        composeRule.waitForIdle()
        typed.forEach { (tag, secret) ->
            val config = composeRule.onNodeWithTag(tag).fetchSemanticsNode().config
            val masked = maskedSecret(secret.length)
            assertTrue("$tag carries password semantics", config.contains(SemanticsProperties.Password))
            assertEquals("$tag editable text", masked, config.getOrNull(SemanticsProperties.EditableText)?.text)
            assertEquals("$tag input text", masked, config.getOrNull(SemanticsProperties.InputText)?.text)
            assertEquals(
                "$tag autofill value",
                masked,
                config.getOrNull(SemanticsProperties.FillableData)?.textValue?.toString(),
            )
            assertEquals(
                "$tag is not autofillable",
                ContentDataType.None,
                config.getOrNull(SemanticsProperties.ContentDataType),
            )
            assertFalse("$tag reports a digit", secretFieldTexts(config).any { text -> text.any(Char::isDigit) })
        }
        listOf(MERGED_TREE, UNMERGED_TREE).forEach { unmerged ->
            val root = composeRule.onRoot(useUnmergedTree = unmerged).fetchSemanticsNode()
            allNodes(root).forEach { node ->
                val texts = textsOf(node.config)
                typed.values.forEach { secret ->
                    assertFalse(
                        "semantics node ${node.id} reports a typed secret",
                        texts.any { text -> text.contains(secret) },
                    )
                }
            }
        }
    }

    /** The values a secret field reports as its own content, as opposed to its label. */
    private fun secretFieldTexts(config: SemanticsConfiguration): List<String> =
        listOfNotNull(
            config.getOrNull(SemanticsProperties.EditableText)?.text,
            config.getOrNull(SemanticsProperties.InputText)?.text,
            config.getOrNull(SemanticsProperties.FillableData)?.textValue?.toString(),
            config.getOrNull(SemanticsProperties.StateDescription),
        )

    /** Every text-bearing value a semantics node carries. */
    private fun textsOf(config: SemanticsConfiguration): List<String> =
        config.flatMap { (_, value) ->
            when (value) {
                is AnnotatedString -> {
                    listOf(value.text)
                }

                is CharSequence -> {
                    listOf(value.toString())
                }

                is FillableData -> {
                    listOfNotNull(value.textValue?.toString())
                }

                is List<*> -> {
                    value.mapNotNull { item ->
                        when (item) {
                            is AnnotatedString -> item.text
                            is CharSequence -> item.toString()
                            else -> null
                        }
                    }
                }

                else -> {
                    emptyList()
                }
            }
        }

    private fun allNodes(node: SemanticsNode): List<SemanticsNode> = listOf(node) + node.children.flatMap(::allNodes)

    private companion object {
        const val MERGED_TREE = false
        const val UNMERGED_TREE = true
        const val REVEALABLE_TAG = "revealableSecretField"
        const val PASSWORD_TAG = "passwordSecretField"
        const val SYNTHETIC_LABEL = "Synthetic secret"
        const val SYNTHETIC_DOCUMENT_NAME = "test_document.pdf"
        const val SYNTHETIC_PIN1 = "8642"
        const val SYNTHETIC_PIN2 = "246810"
        const val SYNTHETIC_CAN = "135790"
        const val SYNTHETIC_PUK = "97531864"
        const val SYNTHETIC_PASSWORD = "synthetic-password-7"
    }
}
