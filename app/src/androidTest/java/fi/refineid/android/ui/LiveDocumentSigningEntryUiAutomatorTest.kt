package fi.refineid.android.ui

import android.content.ComponentName
import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import android.provider.MediaStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.UiAutomatorTestScope
import androidx.test.uiautomator.uiAutomator
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Live picker round trip on a real card. A freshly picked synthetic
 * document stays selected, and a cancelled pick keeps the signing
 * screen instead of falling back to the initial screen. Enters no
 * credential and submits nothing, so no retry is consumed.
 */
@RunWith(AndroidJUnit4::class)
internal class LiveDocumentSigningEntryUiAutomatorTest {
    @Test
    fun liveCardCompletesThePickerRoundTripWithSyntheticDocuments() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(
            "enable the opt-in live document entry check",
            InstrumentationRegistry.getArguments().getString(LIVE_TEST_ARGUMENT) ==
                LIVE_TEST_ENABLED_VALUE,
        )
        val targetContext = instrumentation.targetContext
        val syntheticUri = provisionSyntheticDocument(targetContext.contentResolver)
        try {
            val launchIntent =
                Intent
                    .makeMainActivity(
                        ComponentName(
                            targetContext,
                            TARGET_ACTIVITY_CLASS,
                        ),
                    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            targetContext.startActivity(launchIntent)

            uiAutomator {
                waitForAppToBeVisible(TARGET_PACKAGE)
                openSigningWithUsbGrant(targetContext, launchIntent)
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.SIGN_SCREEN
                }
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.DOCUMENT_SIGNING_CARD
                }
                onElement(CARD_READY_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.DOCUMENT_CHOOSE_ACTION
                }.click()
                onElement(PICKER_TIMEOUT_MILLISECONDS) {
                    text?.toString() == SYNTHETIC_FILE_NAME
                }.click()
                val selected =
                    onElement(PICKER_RESULT_TIMEOUT_MILLISECONDS) {
                        viewIdResourceName == UiAutomationIds.DOCUMENT_SELECTED_STATUS
                    }
                assertEquals(SYNTHETIC_FILE_NAME, selected.text)
                onElement(PICKER_RESULT_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.SIGN_SCREEN
                }
                onElement(PICKER_RESULT_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.DOCUMENT_CHOOSE_ACTION
                }.click()
                pressBack()
                onElement(PICKER_RESULT_TIMEOUT_MILLISECONDS) {
                    viewIdResourceName == UiAutomationIds.SIGN_SCREEN
                }
                val kept =
                    onElement(PICKER_RESULT_TIMEOUT_MILLISECONDS) {
                        viewIdResourceName == UiAutomationIds.DOCUMENT_SELECTED_STATUS
                    }
                assertEquals(SYNTHETIC_FILE_NAME, kept.text)
                pressBack()
            }
        } finally {
            targetContext.contentResolver.delete(syntheticUri, null, null)
        }
    }

    /**
     * Settle onto the home screen and tap the sign entry once the live
     * card enables it. A fresh install raises the system USB grant and
     * the notification runtime prompt first; a relaunch re-prompts the
     * USB grant when a previous confirmation missed, since the grant
     * only arrives through the system dialog.
     */
    private fun UiAutomatorTestScope.openSigningWithUsbGrant(
        targetContext: Context,
        launchIntent: Intent,
    ) {
        repeat(USB_GRANT_ATTEMPTS) { attempt ->
            dismissStartupDialogs()
            if (tapEnabledSignRow()) {
                return
            }
            if (attempt + 1 < USB_GRANT_ATTEMPTS) {
                targetContext.startActivity(launchIntent)
                waitForAppToBeVisible(TARGET_PACKAGE)
            }
        }
        fail("live card required: the USB grant did not take effect")
    }

    /**
     * Clear the system USB grant and the notification runtime prompt
     * until the home screen is visible. The permission controller's
     * resources keep the com.android namespace even where Mainline
     * installs it under the com.google package.
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
        fail("home screen never settled past the system dialogs")
    }

    /**
     * Tap the sign entry once the live card enables it. A dialog that
     * reappears mid-wait is cleared so the grant can still land.
     */
    private fun UiAutomatorTestScope.tapEnabledSignRow(): Boolean {
        val deadline = SystemClock.uptimeMillis() + CARD_READY_TIMEOUT_MILLISECONDS
        while (SystemClock.uptimeMillis() < deadline) {
            try {
                onElementOrNull(DIALOG_POLL_TIMEOUT_MILLISECONDS) {
                    packageName?.toString() == SYSTEM_UI_PACKAGE &&
                        viewIdResourceName == ANDROID_CONFIRM_BUTTON_RESOURCE
                }?.click()
                val signRow =
                    onElementOrNull(DIALOG_POLL_TIMEOUT_MILLISECONDS) {
                        viewIdResourceName == UiAutomationIds.SIGN_ROW
                    }
                if (signRow != null && signRow.isEnabled) {
                    signRow.click()
                    return true
                }
            } catch (_: StaleObjectException) {
                // The home recomposed between find and tap; re-find below.
            }
        }
        return false
    }

    /**
     * Stage a synthetic PDF in Downloads for the system picker. Stale
     * reruns are dropped first so the display name stays exact.
     */
    private fun provisionSyntheticDocument(resolver: ContentResolver): Uri {
        val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
        resolver
            .query(
                collection,
                arrayOf(MediaStore.Downloads._ID),
                "${MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf(SYNTHETIC_FILE_NAME),
                null,
            )?.use { cursor ->
                val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID)
                while (cursor.moveToNext()) {
                    val stale = ContentUris.withAppendedId(collection, cursor.getLong(idColumn))
                    resolver.delete(stale, null, null)
                }
            }
        val pending =
            ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, SYNTHETIC_FILE_NAME)
                put(MediaStore.Downloads.MIME_TYPE, PDF_MIME_TYPE)
                put(MediaStore.Downloads.IS_PENDING, PENDING_WRITE)
            }
        val uri = resolver.insert(collection, pending) ?: error("synthetic document insert failed")
        resolver.openOutputStream(uri)?.use { out -> out.write(SYNTHETIC_PDF_BYTES) }
            ?: error("synthetic document write failed")
        val published = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, PUBLISHED) }
        resolver.update(uri, published, null, null)
        return uri
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

        const val LIVE_TEST_ARGUMENT = "refineidLiveDocumentEntry"
        const val LIVE_TEST_ENABLED_VALUE = "true"
        const val PDF_MIME_TYPE = "application/pdf"
        const val SYNTHETIC_FILE_NAME = "refineid-live-synthetic.pdf"
        const val PENDING_WRITE = 1
        const val PUBLISHED = 0
        const val CARD_READY_TIMEOUT_MILLISECONDS = 30_000L
        const val USB_GRANT_ATTEMPTS = 2
        const val DIALOG_SETTLE_TIMEOUT_MILLISECONDS = 20_000L
        const val DIALOG_POLL_TIMEOUT_MILLISECONDS = 1_500L
        const val PICKER_TIMEOUT_MILLISECONDS = 15_000L
        const val PICKER_RESULT_TIMEOUT_MILLISECONDS = 10_000L

        fun isPermissionController(packageName: String?): Boolean =
            packageName == MAINLINE_PERMISSION_CONTROLLER_PACKAGE ||
                packageName == AOSP_PERMISSION_CONTROLLER_PACKAGE

        val SYNTHETIC_PDF_BYTES =
            (
                "%PDF-1.4\n" +
                    "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                    "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                    "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R" +
                    "/Resources<</Font<</F1 5 0 R>>>>>>endobj\n" +
                    "4 0 obj<</Length 44>>stream\n" +
                    "BT /F1 12 Tf 50 150 Td (synthetic) Tj ET\n" +
                    "endstream\nendobj\n" +
                    "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n" +
                    "trailer<</Root 1 0 R>>\n"
            ).toByteArray()
    }
}
