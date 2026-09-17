package fi.refineid.android.ui

import android.app.Activity
import android.content.ClipData
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.core.app.ActivityOptionsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.R
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.settings.TimestampAuthorityRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Document selection must survive a transient card-readiness loss.
 * The picker result and the READY to CHECKING to READY transition can
 * arrive in either order; both must keep the selection, keep signing
 * disabled while unavailable, and keep the add and save pickers
 * registered.
 */
@RunWith(AndroidJUnit4::class)
internal class DocumentSigningHarnessLifecycleTest {
    @get:Rule
    val composeRule = createComposeRule()

    private lateinit var registry: CapturingRegistry
    private lateinit var available: MutableState<Boolean>
    private lateinit var swapped: MutableState<Boolean>

    @Test
    fun pickerResultBeforeCheckingSurvivesTheTransient() {
        show(signingAvailable = true)

        chooseDocuments()
        deliverDocuments(
            requestCode = registry.launches.single().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_ONE),
        )
        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }
        composeRule
            .onNodeWithTag(UiAutomationIds.PIN2_FIELD)
            .performTextInput(SYNTHETIC_PIN2)
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)
            .assertIsEnabled()

        setAvailable(false)

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_CARD)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD)
            .assertDoesNotExist()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)
            .assertIsNotEnabled()

        setAvailable(true)

        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }
        composeRule
            .onNodeWithTag(
                UiAutomationIds.DOCUMENT_SELECTED_STATUS,
                useUnmergedTree = true,
            ).assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGN_ACTION)
            .assertIsEnabled()
    }

    @Test
    fun pickerResultDuringCheckingSurvivesTheTransient() {
        show(signingAvailable = true)

        chooseDocuments()
        setAvailable(false)
        deliverDocuments(
            requestCode = registry.launches.single().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_ONE),
        )
        setAvailable(true)

        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }
        composeRule
            .onNodeWithTag(
                UiAutomationIds.DOCUMENT_SELECTED_STATUS,
                useUnmergedTree = true,
            ).assertIsDisplayed()
    }

    @Test
    fun addingDocumentsAcrossTheTransientMergesSelection() {
        show(signingAvailable = true)

        chooseDocuments()
        deliverDocuments(
            requestCode = registry.launches.single().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_ONE),
        )
        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }

        addDocuments()
        setAvailable(false)
        deliverDocuments(
            requestCode = registry.launches.last().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_TWO),
        )
        setAvailable(true)

        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == TWO_DOCUMENTS }
    }

    @Test
    fun cancelledPickerAcrossTheTransientKeepsSelection() {
        show(signingAvailable = true)

        chooseDocuments()
        deliverDocuments(
            requestCode = registry.launches.single().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_ONE),
        )
        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }

        chooseDocuments()
        setAvailable(false)
        deliverDocuments(
            requestCode = registry.launches.last().requestCode,
            resultCode = Activity.RESULT_CANCELED,
            uris = emptyList(),
        )
        setAvailable(true)

        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS)
            .assertDoesNotExist()
    }

    @Test
    fun serviceSwapDuringSigningKeepsSelection() {
        show(signingAvailable = true)

        chooseDocuments()
        deliverDocuments(
            requestCode = registry.launches.single().requestCode,
            resultCode = Activity.RESULT_OK,
            uris = listOf(DOCUMENT_ONE),
        )
        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }

        swapService()

        composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { selectedCount() == SINGLE_DOCUMENT }
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD)
            .assertIsDisplayed()
    }

    @Test
    fun signRefusesWhileUnavailableWithoutTouchingTheService() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        val session =
            DocumentSigningHarnessSession(
                context = targetContext,
                contentResolver = targetContext.contentResolver,
                cardService = { STRICT_SERVICE },
                isAvailable = { false },
                scope = scope,
                timestampAuthorityRepository = STRICT_REPOSITORY,
                tap = { null },
            )
        try {
            session.select(listOf(DOCUMENT_ONE))
            composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { session.hasDocument }

            val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)
            session.sign(SignatureFormat.PDF, pin2, null)

            composeRule.runOnIdle {
                assertEquals(DocumentSigningStatus.UNAVAILABLE, session.status)
                assertTrue(session.hasDocument)
            }
        } finally {
            session.close()
            scope.cancel()
        }
    }

    @Test
    fun saveDestinationCancelKeepsSelection() {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        val session =
            DocumentSigningHarnessSession(
                context = targetContext,
                contentResolver = targetContext.contentResolver,
                cardService = { STRICT_SERVICE },
                isAvailable = { true },
                scope = scope,
                timestampAuthorityRepository = STRICT_REPOSITORY,
                tap = { null },
            )
        try {
            session.select(listOf(DOCUMENT_ONE))
            composeRule.waitUntil(SELECTION_TIMEOUT_MILLISECONDS) { session.hasDocument }

            session.saveTo(null)
            session.saveTo(DOCUMENT_TWO)
            session.saveAllToFolder(null)
            session.saveAllToFolder(DOCUMENT_TWO)

            composeRule.runOnIdle {
                assertTrue(session.hasDocument)
                assertEquals(DocumentSigningStatus.IDLE, session.status)
            }
        } finally {
            session.close()
            scope.cancel()
        }
    }

    private fun show(signingAvailable: Boolean) {
        registry = CapturingRegistry()
        available = mutableStateOf(signingAvailable)
        swapped = mutableStateOf(false)
        val owner = TestRegistryOwner(registry)
        composeRule.setContent {
            CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) {
                ReFineIdTheme {
                    DocumentSigningHarness(
                        signingAvailable = available.value,
                        cardService =
                            if (swapped.value) {
                                STRICT_SERVICE_NFC
                            } else {
                                STRICT_SERVICE
                            },
                        tap =
                            if (swapped.value) {
                                NFC_TAP
                            } else {
                                null
                            },
                        timestampAuthorityRepository = STRICT_REPOSITORY,
                        onComplete = {},
                    )
                }
            }
        }
    }

    private fun setAvailable(value: Boolean) {
        composeRule.runOnIdle {
            available.value = value
        }
    }

    private fun swapService() {
        composeRule.runOnIdle {
            swapped.value = true
        }
    }

    private fun chooseDocuments() {
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION)
            .performClick()
    }

    private fun addDocuments() {
        val addLabel =
            InstrumentationRegistry
                .getInstrumentation()
                .targetContext
                .getString(R.string.add_file)
        composeRule
            .onNodeWithText(addLabel)
            .performClick()
    }

    private fun selectedCount(): Int =
        composeRule
            .onAllNodesWithTag(
                UiAutomationIds.DOCUMENT_SELECTED_STATUS,
                useUnmergedTree = true,
            ).fetchSemanticsNodes()
            .size

    private fun deliverDocuments(
        requestCode: Int,
        resultCode: Int,
        uris: List<Uri>,
    ) {
        val data =
            if (resultCode == Activity.RESULT_OK && uris.isNotEmpty()) {
                Intent().apply {
                    if (uris.size == SINGLE_DOCUMENT) {
                        setData(uris.single())
                    } else {
                        val clip = ClipData.newRawUri(null, uris.first())
                        uris.drop(1).forEach { uri -> clip.addItem(ClipData.Item(uri)) }
                        setClipData(clip)
                    }
                }
            } else {
                null
            }
        composeRule.runOnIdle {
            registry.deliver(requestCode, resultCode, data)
        }
    }

    private class TestRegistryOwner(
        override val activityResultRegistry: ActivityResultRegistry,
    ) : ActivityResultRegistryOwner

    private class CapturingRegistry : ActivityResultRegistry() {
        data class Launch(
            val requestCode: Int,
        )

        val launches = mutableListOf<Launch>()

        override fun <I, O> onLaunch(
            requestCode: Int,
            contract: ActivityResultContract<I, O>,
            input: I,
            options: ActivityOptionsCompat?,
        ) {
            launches += Launch(requestCode)
        }

        fun deliver(
            requestCode: Int,
            resultCode: Int,
            data: Intent?,
        ) {
            dispatchResult(requestCode, resultCode, data)
        }
    }

    private companion object {
        const val SELECTION_TIMEOUT_MILLISECONDS = 10_000L
        const val SINGLE_DOCUMENT = 1
        const val TWO_DOCUMENTS = 2
        const val SYNTHETIC_PIN2 = "246810"

        val DOCUMENT_ONE = Uri.parse("content://fi.refineid.synthetic.test/documents/first.pdf")
        val DOCUMENT_TWO = Uri.parse("content://fi.refineid.synthetic.test/documents/second.pdf")

        val STRICT_SERVICE = strictService()
        val STRICT_SERVICE_NFC = strictService()

        val NFC_TAP =
            DocumentSignTap(
                begin = { _, _, _ -> },
                end = {},
                canRequired = true,
            )

        fun strictService(): QualifiedCardService =
            object : QualifiedCardService {
                override fun requestQualifiedCertificate(
                    onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit,
                ): Unit = error("card service must not be touched")

                override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit): Unit =
                    error("card service must not be touched")

                override fun requestQualifiedSignature(
                    algorithm: QualifiedSigningAlgorithm,
                    pin2: Pin2Submission,
                    content: ByteArray,
                    expectedCertificate: NativeQualifiedCertificate,
                    onResult: (QualifiedSignResult) -> Unit,
                ): Unit = error("card service must not be touched")

                override fun requestQualifiedDigestSignature(
                    algorithm: QualifiedSigningAlgorithm,
                    pin2: Pin2Submission,
                    digest: ByteArray,
                    expectedCertificate: NativeQualifiedCertificate,
                    onResult: (QualifiedSignResult) -> Unit,
                ): Unit = error("card service must not be touched")
            }

        val STRICT_REPOSITORY =
            object : TimestampAuthorityRepository {
                override fun load(): List<TimestampAuthorityConfiguration> =
                    error("timestamp authorities must not load")

                override fun save(authorities: List<TimestampAuthorityConfiguration>): Unit =
                    error("timestamp authorities must not save")

                override fun restoreDefaults(): Unit = error("timestamp authorities must not reset")
            }
    }
}
