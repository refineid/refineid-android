package fi.refineid.android.ui

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.R
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.PIN2_MAXIMUM_LENGTH
import fi.refineid.android.core.Pin2Submission
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class DocumentSigningCardTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Before
    fun setUp() {
        fi.refineid.android.core.CanSessionStore
            .drop()
    }

    @Test
    fun emptyCardOffersOnlyPdfSelection() {
        var chooseCount = NO_ACTIONS
        show(onChooseDocuments = { chooseCount += ACTION_COUNT_STEP })

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION)
            .assertIsDisplayed()
            .assertIsEnabled()
            .performClick()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertDoesNotExist()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD).assertDoesNotExist()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertDoesNotExist()
        composeRule.runOnIdle {
            assertEquals(SINGLE_ACTION, chooseCount)
        }
    }

    @Test
    fun selectedPdfPromptsForPin2WithoutAccessNumberWhenPrimed() {
        show(hasDocument = true)

        composeRule
            .onNodeWithTag(
                UiAutomationIds.DOCUMENT_SELECTED_STATUS,
                useUnmergedTree = true,
            ).assertIsDisplayed()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertIsDisplayed()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD).assertDoesNotExist()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertIsNotEnabled()
    }

    @Test
    fun selectedPdfPromptsForPin2WithoutAccessNumberWhenCanIsRememberedInSession() {
        fi.refineid.android.core.CanSessionStore
            .remember(SYNTHETIC_CAN)
        try {
            show(hasDocument = true, canRequired = true)

            composeRule
                .onNodeWithTag(
                    UiAutomationIds.DOCUMENT_SELECTED_STATUS,
                    useUnmergedTree = true,
                ).assertIsDisplayed()
            composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertIsDisplayed()
            // The field stays visible for verification, but the
            // remembered access number already satisfies readiness: PIN2
            // alone enables signing.
            composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD).assertIsDisplayed()
            composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).performTextInput(SYNTHETIC_PIN2)
            composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertIsEnabled()
        } finally {
            fi.refineid.android.core.CanSessionStore
                .clearForTesting()
        }
    }

    @Test
    fun anUnprimedCardAlsoPromptsForTheAccessNumber() {
        show(hasDocument = true, canRequired = true)

        val canField = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD)
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)

        canField.assertIsDisplayed()
        pinField.performTextInput(SYNTHETIC_PIN2)
        signAction.assertIsNotEnabled()
        canField.performTextInput(SYNTHETIC_CAN)
        signAction.assertIsEnabled()
    }

    @Test
    fun securePin2SubmitsOnceAndClearsImmediately() {
        var submissionCount = NO_ACTIONS
        var submittedBytes: ByteArray? = null
        var submittedCan: CanSubmission? = null
        show(
            hasDocument = true,
            onSign = { _, submission, can ->
                submissionCount += ACTION_COUNT_STEP
                submittedBytes = submission.consume { bytes -> bytes.copyOf() }
                submittedCan = can
            },
        )
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)

        assertTrue(
            "PIN2 field must carry password semantics",
            pinField.fetchSemanticsNode().config.contains(SemanticsProperties.Password),
        )
        signAction.assertIsNotEnabled()
        pinField.performTextInput(SYNTHETIC_PIN2)
        signAction.assertIsEnabled().performClick()

        val expected = SYNTHETIC_PIN2.encodeToByteArray()
        try {
            composeRule.runOnIdle {
                assertEquals(SINGLE_ACTION, submissionCount)
                assertArrayEquals(expected, checkNotNull(submittedBytes))
                // A primed card supplies no access number from the card.
                assertNull(submittedCan)
            }
            signAction.assertIsNotEnabled()
        } finally {
            expected.fill(CLEARED_BYTE)
            submittedBytes?.fill(CLEARED_BYTE)
            submittedCan?.close()
        }
    }

    @Test
    fun unavailableCardKeepsSignDisabledWithCompleteCredentials() {
        var submissionCount = NO_ACTIONS
        show(
            hasDocument = true,
            canSign = false,
            onSign = { _, pin2, can ->
                submissionCount += ACTION_COUNT_STEP
                pin2.close()
                can?.close()
            },
        )
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)
        val containerAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_FORMAT_CONTAINER)

        pinField.performTextInput(SYNTHETIC_PIN2)
        signAction.assertIsNotEnabled()
        containerAction.assertIsNotEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION)
            .assertIsEnabled()
        composeRule.runOnIdle {
            assertEquals(NO_ACTIONS, submissionCount)
        }
    }

    @Test
    fun pin2InputRejectsNonDecimalAndOverlengthValues() {
        show(hasDocument = true)
        val pinField = composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD)
        val signAction = composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)

        pinField.performTextInput(NON_DECIMAL_PIN2)
        signAction.assertIsNotEnabled()
        pinField.performTextInput(OVERLENGTH_PIN2)
        signAction.assertIsNotEnabled()
    }

    @Test
    fun signingDisablesEveryMutableControlAndShowsTerseStatus() {
        show(
            hasDocument = true,
            status = DocumentSigningStatus.SIGNING,
        )

        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION).assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.PIN2_FIELD).assertIsNotEnabled()
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertIsNotEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS)
            .assertTextEquals(
                InstrumentationRegistry
                    .getInstrumentation()
                    .targetContext
                    .getString(R.string.signing),
            )
    }

    @Test
    fun holdingForTheCardShowsTheTapPrompt() {
        show(
            hasDocument = true,
            status = DocumentSigningStatus.HOLD_CARD,
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS)
            .assertTextEquals(
                InstrumentationRegistry
                    .getInstrumentation()
                    .targetContext
                    .getString(R.string.hold_card),
            )
        composeRule.onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION).assertIsNotEnabled()
    }

    private fun show(
        hasDocument: Boolean = false,
        canRequired: Boolean = false,
        canSign: Boolean = true,
        status: DocumentSigningStatus = DocumentSigningStatus.IDLE,
        onChooseDocuments: () -> Unit = {},
        onAddDocument: () -> Unit = {},
        onSign: (SignatureFormat, Pin2Submission, CanSubmission?) -> Unit = { _, pin2, can ->
            pin2.close()
            can?.close()
        },
    ) {
        composeRule.setContent {
            ReFineIdTheme {
                DocumentSigningCard(
                    hasDocument = hasDocument,
                    documentNames = if (hasDocument) listOf("test_document.pdf") else emptyList(),
                    canSignPdf = true,
                    canRequired = canRequired,
                    canSign = canSign,
                    status = status,
                    onChooseDocuments = onChooseDocuments,
                    onAddDocument = onAddDocument,
                    onSign = onSign,
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_PIN2 = "246810"
        const val SYNTHETIC_CAN = "135790"
        const val NON_DECIMAL_PIN2 = "24A810"
        const val NO_ACTIONS = 0
        const val SINGLE_ACTION = 1
        const val ACTION_COUNT_STEP = 1
        const val SINGLE_EXCESS_CHARACTER_COUNT = 1
        const val DECIMAL_FILL_CHARACTER = '0'
        const val CLEARED_BYTE: Byte = 0
        val OVERLENGTH_PIN2 =
            DECIMAL_FILL_CHARACTER
                .toString()
                .repeat(PIN2_MAXIMUM_LENGTH + SINGLE_EXCESS_CHARACTER_COUNT)
    }
}
