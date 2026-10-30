// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.ui.RefineIdTheme
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The diagnostics screen's error list sits in a screen that scrolls, as
 * every sub-screen does, and lists what was recorded.
 */
@RunWith(AndroidJUnit4::class)
internal class DevErrorSectionTest {
    private companion object {
        const val EVENT = "rapp:dial-refused"
        const val OTHER_EVENT = "nfc:session-open-failed"
    }

    @get:Rule
    val composeRule = createComposeRule()

    @After
    fun clearErrors() {
        DevErrorLog.clear()
    }

    @Test
    fun recordedErrorsAreListedInAScrollingScreen() {
        DevErrorLog.report(EVENT)
        DevErrorLog.report(OTHER_EVENT)

        composeRule.setContent {
            RefineIdTheme {
                Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                    DevErrorSection()
                }
            }
        }

        composeRule.onNodeWithText(EVENT).assertIsDisplayed()
        composeRule.onNodeWithText(OTHER_EVENT).assertIsDisplayed()
    }
}
