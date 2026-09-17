package fi.refineid.android.ui

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class MainScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun readyReaderWithCardHidesCardSectionAndExposesBrowserAndIdentity() {
        show(
            snapshot =
                READY_WITH_CARD.copy(
                    holderName = SYNTHETIC_HOLDER_NAME,
                ),
            browserCardService = INERT_BROWSER_CARD_SERVICE,
        )

        composeRule.onNodeWithTag(UiAutomationIds.READER_CARD).assertDoesNotExist()
        composeRule
            .onNodeWithTag(UiAutomationIds.BROWSER_ACTION)
            .performScrollTo()
            .assertIsDisplayed()
            .assertIsEnabled()
        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun readyCardServiceExposesTheTerseBrowserAction() {
        show(
            snapshot = READY_WITH_CARD,
            browserCardService = INERT_BROWSER_CARD_SERVICE,
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.BROWSER_ACTION)
            .performScrollTo()
            .assertIsDisplayed()
            .assertIsEnabled()
    }

    @Test
    fun activationRequiredReaderHidesCardActionsAndShowsBanner() {
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.ACTIVATION_REQUIRED,
                    cardPresence = CardPresence.PRESENT,
                    holderName = SYNTHETIC_HOLDER_NAME,
                ),
            browserCardService = INERT_BROWSER_CARD_SERVICE,
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.ACTIVATION_BANNER)
            .assertIsDisplayed()

        composeRule
            .onNodeWithTag(UiAutomationIds.BROWSER_ACTION)
            .assertDoesNotExist()

        composeRule
            .onNodeWithTag(UiAutomationIds.SIGN_ROW)
            .assertDoesNotExist()
    }

    @Test
    fun cardRequiringCanAutomaticallyShowsCanDialog() {
        CanSessionStore.drop()
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                    cardPresence = CardPresence.PRESENT,
                ),
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_DIALOG)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_FIELD)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CONNECT_ACTION)
            .assertIsDisplayed()
            .assertIsNotEnabled()
    }

    @Test
    fun cancelingCanDialogDismissesAndCanBeReopenedFromIdentityRow() {
        CanSessionStore.drop()
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                    cardPresence = CardPresence.PRESENT,
                ),
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_DIALOG)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CANCEL_ACTION)
            .performClick()
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_DIALOG)
            .assertDoesNotExist()

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performClick()
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_DIALOG)
            .assertIsDisplayed()
    }

    @Test
    fun enteringCanAndUnlockingInvokesConnectHandler() {
        CanSessionStore.drop()
        var connectedCan: String? = null
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                    cardPresence = CardPresence.PRESENT,
                ),
            onReaderConnect = { can, _ ->
                connectedCan = can.peekDigits()
            },
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CAN_FIELD)
            .performTextInput("123456")
        composeRule
            .onNodeWithTag(UiAutomationIds.READER_CONNECT_ACTION)
            .assertIsEnabled()
            .performClick()

        assertEquals("123456", connectedCan)
    }

    @Test
    fun usbCheckingDuringSigningKeepsUsbServiceWithoutCanPrompt() {
        val snapshotState =
            mutableStateOf(
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.READY,
                    cardPresence = CardPresence.PRESENT,
                ),
            )
        showSigning(snapshotState)

        composeRule
            .onNodeWithTag(UiAutomationIds.SIGN_ROW)
            .performScrollTo()
            .performClick()
        composeRule
            .onNodeWithTag(UiAutomationIds.SIGN_SCREEN)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_CARD)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD)
            .assertDoesNotExist()

        snapshotState.value =
            snapshotState.value.copy(status = ReaderConnectionStatus.CHECKING)

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_CARD)
            .assertIsDisplayed()
        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_CAN_FIELD)
            .assertDoesNotExist()

        snapshotState.value =
            snapshotState.value.copy(status = ReaderConnectionStatus.READY)

        composeRule
            .onNodeWithTag(UiAutomationIds.DOCUMENT_SIGNING_CARD)
            .assertIsDisplayed()
    }

    @Test
    fun removingCardClosesPersonPageBackToFront() {
        var snapshot by mutableStateOf(
            READY_WITH_CARD.copy(
                holderName = SYNTHETIC_HOLDER_NAME,
                cardDetails =
                    PersonCardDetails(
                        holderName = SYNTHETIC_HOLDER_NAME,
                        fullName = SYNTHETIC_HOLDER_NAME,
                    ),
            ),
        )
        composeRule.setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = snapshot,
                    onRequestPermission = {},
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .performClick()
        composeRule
            .onNodeWithTag(PERSON_SCREEN_TAG)
            .assertIsDisplayed()

        snapshot =
            READY_WITH_CARD.copy(
                cardPresence = CardPresence.NOT_PRESENT,
                holderName = null,
                cardDetails = null,
            )

        composeRule
            .onNodeWithTag(PERSON_SCREEN_TAG)
            .assertDoesNotExist()
        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .assertIsDisplayed()
    }

    private fun show(
        snapshot: UsbReaderSnapshot,
        onRequestPermission: () -> Unit = {},
        onReaderConnect: (CanSubmission, ((ByteArray?) -> Unit)?) -> Unit = { _, _ -> },
        browserCardService: AuthenticationCardService? = null,
    ) {
        composeRule.setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = snapshot,
                    onRequestPermission = onRequestPermission,
                    onReaderConnect = onReaderConnect,
                    browserCardService = browserCardService,
                )
            }
        }
    }

    private fun showSigning(snapshotState: MutableState<UsbReaderSnapshot>) {
        composeRule.setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = snapshotState.value,
                    onRequestPermission = {},
                    qualifiedCardService = STRICT_SERVICE,
                    nfcQualifiedCardService = STRICT_SERVICE,
                    timestampAuthorityRepository = BENIGN_REPOSITORY,
                    nfcSnapshot =
                        NfcReaderSnapshot(
                            status = NfcReaderStatus.WAITING_FOR_CARD,
                        ),
                )
            }
        }
    }

    private companion object {
        const val SYNTHETIC_HOLDER_NAME = "MEIKALAINEN MATTI SAKARI"
        const val EXPECTED_PERMISSION_REQUEST_COUNT = 1
        const val PERSON_SCREEN_TAG = "PersonScreen"

        val READY_WITH_CARD =
            UsbReaderSnapshot(
                status = ReaderConnectionStatus.READY,
                cardPresence = CardPresence.PRESENT,
            )

        val STRICT_SERVICE =
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

        val BENIGN_REPOSITORY =
            object : TimestampAuthorityRepository {
                override fun load(): List<TimestampAuthorityConfiguration> = emptyList()

                override fun save(authorities: List<TimestampAuthorityConfiguration>) = Unit

                override fun restoreDefaults() = Unit
            }

        val INERT_BROWSER_CARD_SERVICE =
            object : AuthenticationCardService {
                override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
                    onResult(null)
                }

                override fun signAuthenticationMessage(
                    algorithm: AuthenticationSigningAlgorithm,
                    pin1: Pin1Submission,
                    message: ByteArray,
                ): AuthenticationSignResult {
                    pin1.close()
                    return AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.CARD_UNAVAILABLE,
                    )
                }

                override fun signAuthenticationDigest(
                    algorithm: AuthenticationSigningAlgorithm,
                    pin1: Pin1Submission,
                    digest: ByteArray,
                ): AuthenticationSignResult {
                    pin1.close()
                    return AuthenticationSignResult.Failure(
                        AuthenticationSignFailure.CARD_UNAVAILABLE,
                    )
                }
            }
    }
}
