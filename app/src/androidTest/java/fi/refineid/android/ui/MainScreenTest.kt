package fi.refineid.android.ui

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.R
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
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
    fun activationRequiredReaderOpensActivationInPlaceOfHome() {
        val management = HeldCardManagementService()
        show(
            snapshot =
                UsbReaderSnapshot(
                    status = ReaderConnectionStatus.ACTIVATION_REQUIRED,
                    cardPresence = CardPresence.PRESENT,
                    holderName = SYNTHETIC_HOLDER_NAME,
                ),
            browserCardService = INERT_BROWSER_CARD_SERVICE,
            cardManagementService = management,
        )

        composeRule
            .onNodeWithTag("CardManagementScreen")
            .assertDoesNotExist()

        composeRule.runOnIdle { management.answer(ORGANIZATION_CARD_AWAITING_ACTIVATION) }

        composeRule
            .onNodeWithTag("CardManagementScreen")
            .assertIsDisplayed()
        composeRule
            .onNodeWithText(
                InstrumentationRegistry
                    .getInstrumentation()
                    .targetContext
                    .getString(R.string.organisation_card_activation),
            ).assertIsDisplayed()

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
            onReaderConnect = { can ->
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
    fun contactlessIdentityRowRemovesIdentityAtOnce() {
        var forgotten = false
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = UsbReaderSnapshot(),
                    onRequestPermission = {},
                    hasNfc = true,
                    nfcSnapshot =
                        NfcReaderSnapshot(
                            status = NfcReaderStatus.CARD_READY,
                            holderName = SYNTHETIC_HOLDER_NAME,
                        ),
                    onForgetPrimedCard = { forgotten = true },
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .assertHasNoClickAction()
        composeRule
            .onNodeWithTag(UiAutomationIds.FORGET_IDENTITY_ACTION)
            .assertIsDisplayed()
            .performClick()

        assertEquals(true, forgotten)
    }

    @Test
    fun wiredIdentityRowShowsTheHolderOnly() {
        show(
            snapshot =
                READY_WITH_CARD.copy(
                    holderName = SYNTHETIC_HOLDER_NAME,
                    cardDetails =
                        PersonCardDetails(
                            holderName = SYNTHETIC_HOLDER_NAME,
                            fullName = SYNTHETIC_HOLDER_NAME,
                        ),
                ),
        )

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .assertIsDisplayed()
            .assertHasNoClickAction()
        composeRule
            .onNodeWithTag(UiAutomationIds.FORGET_IDENTITY_ACTION)
            .assertDoesNotExist()
    }

    @Test
    fun awaitingCardShowsNfcCardTapDialogAndCancelInvokesCallback() {
        var cancelInvoked = false
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = UsbReaderSnapshot(),
                    onRequestPermission = {},
                    nfcSnapshot =
                        NfcReaderSnapshot(
                            status = NfcReaderStatus.WAITING_FOR_CARD,
                            awaitingCard = true,
                        ),
                    onCancelAwaitingCard = { cancelInvoked = true },
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CARD_TAP_DIALOG)
            .assertIsDisplayed()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CARD_TAP_CANCEL_ACTION)
            .assertIsDisplayed()
            .performClick()

        assertEquals(true, cancelInvoked)
    }

    @Test
    fun readCardWithoutRememberedCanShowsCanDialog() {
        CanSessionStore.drop()
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = UsbReaderSnapshot(),
                    onRequestPermission = {},
                    hasNfc = true,
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .performClick()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CAN_FIELD)
            .assertIsDisplayed()
    }

    @Test
    fun readCardWithRememberedCanDirectlyConnectsWithoutCanDialog() {
        CanSessionStore.drop()
        CanSessionStore.remember("123456")
        var connectedCan: String? = null
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = UsbReaderSnapshot(),
                    onRequestPermission = {},
                    hasNfc = true,
                    onNfcConnect = { can, _ ->
                        connectedCan = can?.peekDigits()
                    },
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .performClick()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CAN_FIELD)
            .assertDoesNotExist()
        assertEquals("123456", connectedCan)
        CanSessionStore.drop()
    }

    @Test
    fun readCardAfterWrongCanAsksForCanWithEmptyField() {
        CanSessionStore.remember("123456")
        CanSessionStore.drop()
        var connectedCan: String? = null
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = UsbReaderSnapshot(),
                    onRequestPermission = {},
                    hasNfc = true,
                    nfcSnapshot =
                        NfcReaderSnapshot(
                            status = NfcReaderStatus.WRONG_CAN,
                        ),
                    onNfcConnect = { can, _ ->
                        connectedCan = can?.peekDigits()
                    },
                )
            }
        }

        composeRule
            .onNodeWithTag(UiAutomationIds.IDENTITY_ROW)
            .performScrollTo()
            .performClick()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CAN_FIELD)
            .assertIsDisplayed()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CONNECT_ACTION)
            .assertIsNotEnabled()

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CAN_FIELD)
            .performTextReplacement("654321")

        composeRule
            .onNodeWithTag(UiAutomationIds.NFC_CONNECT_ACTION)
            .assertIsEnabled()
            .performClick()

        assertEquals("654321", connectedCan)
        CanSessionStore.drop()
    }

    private fun show(
        snapshot: UsbReaderSnapshot,
        onRequestPermission: () -> Unit = {},
        onReaderConnect: (CanSubmission) -> Unit = {},
        browserCardService: AuthenticationCardService? = null,
        cardManagementService: CardManagementService? = null,
    ) {
        composeRule.setContent {
            RefineIdTheme {
                MainScreen(
                    snapshot = snapshot,
                    onRequestPermission = onRequestPermission,
                    onReaderConnect = onReaderConnect,
                    browserCardService = browserCardService,
                    cardManagementService = cardManagementService,
                )
            }
        }
    }

    private fun showSigning(snapshotState: MutableState<UsbReaderSnapshot>) {
        composeRule.setContent {
            RefineIdTheme {
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

    /** Holds each credential probe until the test answers it. */
    private class HeldCardManagementService : CardManagementService {
        private var pending: ((CardManagementResult<CredentialHealth>) -> Unit)? = null

        fun answer(health: CredentialHealth) {
            pending?.invoke(CardManagementResult.Success(health))
            pending = null
        }

        override fun probeCredentialHealth(onResult: (CardManagementResult<CredentialHealth>) -> Unit) {
            pending = onResult
        }

        override fun changePin1(
            currentPin: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun changePin2(
            currentPin: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun unblockPin1(
            puk: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun unblockPin2(
            puk: ByteArray,
            newPin: ByteArray,
            onResult: (CardManagementResult<ManageOutcome>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))

        override fun activateCard(
            scheme: CardManagementScheme,
            code: ByteArray,
            newPin1: ByteArray?,
            newPin2: ByteArray?,
            onResult: (CardManagementResult<ActivationReport>) -> Unit,
        ) = onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
    }

    private companion object {
        val ORGANIZATION_CARD_AWAITING_ACTIVATION =
            CredentialHealth(
                pin1State = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
                pin2State = NativePin2State.Remaining(FINEID_PIN_TRY_LIMIT),
                pukState = NativePin1State.Remaining(FINEID_PIN_TRY_LIMIT),
                scheme = NativePinReferenceScheme.ORGANIZATIONAL,
                activationScheme = CardManagementScheme.PUK,
                activationNeeds = CardActivationNeeds(pin1 = true, pin2 = true),
            )

        const val SYNTHETIC_HOLDER_NAME = "MEIKALAINEN MATTI SAKARI"
        const val EXPECTED_PERMISSION_REQUEST_COUNT = 1

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
