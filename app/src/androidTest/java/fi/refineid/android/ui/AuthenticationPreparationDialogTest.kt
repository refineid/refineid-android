package fi.refineid.android.ui

import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.AuthenticationPreparation
import fi.refineid.android.core.AuthenticationPreparationBackend
import fi.refineid.android.core.AuthenticationReadiness
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class AuthenticationPreparationDialogTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Before
    @After
    fun clearTransientAccessNumber() {
        CanSessionStore.drop()
    }

    @Test
    fun browserWithoutIdentityStartsPreparationWithBothMissingFields() {
        val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
        val preparation = AuthenticationPreparation(scope, Backend(), AuthenticationPinCache())
        try {
            composeRule.setContent {
                ReFineIdTheme {
                    MainScreen(
                        snapshot = UsbReaderSnapshot(),
                        authenticationPreparation = preparation,
                        onRequestPermission = {},
                        hasNfc = true,
                        nfcSnapshot = NfcReaderSnapshot(status = NfcReaderStatus.WAITING_FOR_CARD),
                        nfcCardService = InertCardService,
                    )
                }
            }
            composeRule.onNodeWithTag(UiAutomationIds.BROWSER_ACTION).performScrollTo().performClick()
            composeRule.onNodeWithTag("AuthenticationPreparationCan").assertIsDisplayed()
            composeRule.onNodeWithTag("AuthenticationPreparationPin1").assertIsDisplayed()
            composeRule.onNodeWithTag("AuthenticationPreparationSubmit").assertIsNotEnabled()
        } finally {
            scope.cancel()
        }
    }

    @Test
    fun presentUsbCardCanStartBrowserPreparationWithoutNfc() {
        val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
        val preparation = AuthenticationPreparation(scope, Backend(), AuthenticationPinCache())
        try {
            composeRule.setContent {
                ReFineIdTheme {
                    MainScreen(
                        snapshot =
                            UsbReaderSnapshot(
                                status = ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED,
                                cardPresence = CardPresence.PRESENT,
                            ),
                        authenticationPreparation = preparation,
                        onRequestPermission = {},
                        hasNfc = false,
                        browserCardService = InertCardService,
                    )
                }
            }
            composeRule.onNodeWithTag(UiAutomationIds.READER_CANCEL_ACTION).performClick()
            composeRule.onNodeWithTag(UiAutomationIds.BROWSER_ACTION).performScrollTo().performClick()
            composeRule.onNodeWithTag("AuthenticationPreparationCan").assertIsDisplayed()
            composeRule.onNodeWithTag("AuthenticationPreparationPin1").assertIsDisplayed()
        } finally {
            scope.cancel()
        }
    }

    @Test
    fun primedCardShowsOnlyMissingPin() {
        val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
        val preparation = AuthenticationPreparation(scope, Backend(primed = true), AuthenticationPinCache())
        try {
            composeRule.setContent {
                val state by preparation.state.collectAsState()
                ReFineIdTheme { AuthenticationPreparationDialog(preparation, state) }
            }
            composeRule.runOnIdle { preparation.start {} }
            composeRule.onNodeWithTag("AuthenticationPreparationCan").assertDoesNotExist()
            composeRule.onNodeWithTag("AuthenticationPreparationPin1").assertIsDisplayed()
        } finally {
            scope.cancel()
        }
    }

    private object InertCardService : AuthenticationCardService {
        override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) =
            error("no certificate request expected before preparation")

        override fun signAuthenticationMessage(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            message: ByteArray,
        ): AuthenticationSignResult = error("no signature expected")

        override fun signAuthenticationDigest(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            digest: ByteArray,
        ): AuthenticationSignResult = error("no signature expected")
    }

    private class Backend(
        private val primed: Boolean = false,
    ) : AuthenticationPreparationBackend {
        override fun readiness(): AuthenticationReadiness = AuthenticationReadiness(primed, !primed, true)

        override suspend fun connect(can: CanSubmission?): Boolean = error("no card operation expected")

        override suspend fun verify(pin1: Pin1Submission): Pin1VerificationResult = error("no card operation expected")

        override suspend fun retainVerified(pin: ByteArray): Boolean = error("no card operation expected")

        override fun invalidate() = Unit
    }
}
