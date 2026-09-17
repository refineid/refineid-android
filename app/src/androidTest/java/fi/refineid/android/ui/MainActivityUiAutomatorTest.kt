package fi.refineid.android.ui

import android.content.ComponentName
import android.content.Intent
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiAutomatorTestScope
import androidx.test.uiautomator.uiAutomator
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class MainActivityUiAutomatorTest {
    @Test
    fun launchesAndExposesTheStableAutomationSurface() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
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
            dismissStartupDialogs()
            onElement(STARTUP_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.MAIN_SCREEN
            }
            onElement(STARTUP_TIMEOUT_MILLISECONDS) {
                viewIdResourceName == UiAutomationIds.VERIFY_ROW
            }
        }
    }

    /**
     * A fresh install raises the system USB grant and the notification
     * runtime prompt before the home screen settles; clear either while
     * present so the tagged surface is reachable. The permission
     * controller's resources keep the com.android namespace even where
     * Mainline installs it under the com.google package.
     */
    private fun UiAutomatorTestScope.dismissStartupDialogs() {
        val deadline = SystemClock.uptimeMillis() + DIALOG_SETTLE_TIMEOUT_MILLISECONDS
        while (SystemClock.uptimeMillis() < deadline) {
            onElementOrNull(DIALOG_POLL_TIMEOUT_MILLISECONDS) {
                packageName?.toString() == SYSTEM_UI_PACKAGE &&
                    viewIdResourceName == ANDROID_CONFIRM_BUTTON_RESOURCE
            }?.click()
            onElementOrNull(DIALOG_POLL_TIMEOUT_MILLISECONDS) {
                isPermissionController(packageName?.toString()) &&
                    (
                        viewIdResourceName == PERMISSION_DENY_BUTTON_RESOURCE ||
                            viewIdResourceName == PERMISSION_DENY_ALWAYS_BUTTON_RESOURCE
                    )
            }?.click()
            val settled =
                onElementOrNull(DIALOG_POLL_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.MAIN_SCREEN
                } != null
            if (settled) {
                return
            }
        }
    }

    private companion object {
        const val TARGET_PACKAGE = "fi.refineid.android"
        const val TARGET_ACTIVITY_CLASS = "$TARGET_PACKAGE.MainActivity"
        const val SYSTEM_UI_PACKAGE = "com.android.systemui"
        const val ANDROID_CONFIRM_BUTTON_RESOURCE = "android:id/button1"
        const val MAINLINE_PERMISSION_CONTROLLER_PACKAGE = "com.google.android.permissioncontroller"
        const val AOSP_PERMISSION_CONTROLLER_PACKAGE = "com.android.permissioncontroller"
        const val PERMISSION_DENY_BUTTON_RESOURCE =
            "com.android.permissioncontroller:id/permission_deny_button"
        const val PERMISSION_DENY_ALWAYS_BUTTON_RESOURCE =
            "com.android.permissioncontroller:id/permission_deny_and_dont_ask_again_button"
        const val DIALOG_SETTLE_TIMEOUT_MILLISECONDS = 20_000L
        const val DIALOG_POLL_TIMEOUT_MILLISECONDS = 1_500L
        const val STARTUP_TIMEOUT_MILLISECONDS = 15_000L

        fun isPermissionController(packageName: String?): Boolean =
            packageName == MAINLINE_PERMISSION_CONTROLLER_PACKAGE ||
                packageName == AOSP_PERMISSION_CONTROLLER_PACKAGE
    }
}
