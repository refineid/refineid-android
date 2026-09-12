package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.uiAutomator
import fi.refineid.android.RefineIdApplication
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
internal class LiveQualifiedCertificateUiAutomatorTest {
    @Test
    fun liveCardReadsTheQualifiedCertificateWithoutASecret() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(
            "enable the opt-in live qualified-certificate read",
            InstrumentationRegistry.getArguments().getString(LIVE_TEST_ARGUMENT) ==
                LIVE_TEST_ENABLED_VALUE,
        )
        val launchIntent =
            Intent
                .makeMainActivity(
                    ComponentName(
                        instrumentation.targetContext,
                        TARGET_ACTIVITY_CLASS,
                    ),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        instrumentation.targetContext.startActivity(launchIntent)

        uiAutomator {
            waitForAppToBeVisible(TARGET_PACKAGE)
            val readerState =
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.AUTHENTICATION_CARD ||
                        viewIdResourceName == UiAutomationIds.READER_ACTION
                }
            if (readerState.resourceName == UiAutomationIds.READER_ACTION) {
                readerState.click()
                onElement(USB_PERMISSION_TIMEOUT_MILLISECONDS) {
                    packageName?.toString() == SYSTEM_UI_PACKAGE &&
                        viewIdResourceName == ANDROID_CONFIRM_BUTTON_RESOURCE
                }.click()
            }
            onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.AUTHENTICATION_CARD
            }
        }

        val completion = CountDownLatch(SINGLE_COMPLETION)
        val result =
            AtomicReference<NativeCertificateReadResult<NativeQualifiedCertificate>>()
        val application =
            instrumentation.targetContext.applicationContext as RefineIdApplication
        application.readerController.qualifiedCardService.requestQualifiedCertificate { certificateResult ->
            result.set(certificateResult)
            completion.countDown()
        }

        assertTrue(
            "qualified-certificate read timed out",
            completion.await(CERTIFICATE_TIMEOUT_SECONDS, TimeUnit.SECONDS),
        )
        when (val certificateResult = result.get()) {
            is NativeCertificateReadResult.Success -> {
                try {
                    assertTrue(
                        "qualified certificate must not be empty",
                        certificateResult.certificate.derLength > EMPTY_CERTIFICATE_LENGTH,
                    )
                } finally {
                    certificateResult.certificate.close()
                }
            }

            is NativeCertificateReadResult.Failure -> {
                fail("qualified-certificate read failed: " + certificateResult.kind)
            }

            null -> {
                fail("qualified-certificate callback returned no result")
            }
        }
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val SYSTEM_UI_PACKAGE = "com.android.systemui"
        const val ANDROID_CONFIRM_BUTTON_RESOURCE = "android:id/button1"
        const val LIVE_TEST_ARGUMENT = "refineidLiveQualifiedCertificate"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val CARD_READY_TIMEOUT_MILLISECONDS = 15_000L
        const val USB_PERMISSION_TIMEOUT_MILLISECONDS = 10_000L
        const val CERTIFICATE_TIMEOUT_SECONDS = 30L
        const val SINGLE_COMPLETION = 1
        const val EMPTY_CERTIFICATE_LENGTH = 0
    }
}
