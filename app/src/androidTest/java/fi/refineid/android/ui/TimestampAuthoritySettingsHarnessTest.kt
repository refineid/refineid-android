// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import android.os.Looper
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import fi.refineid.android.R
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.settings.TimestampAuthorityRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
internal class TimestampAuthoritySettingsHarnessTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun savesReorderedAuthoritiesAndAnEmptySecurePasswordOffMain() {
        val repository = RecordingTimestampAuthorityRepository()
        try {
            show(repository)
            openAndAwait(repository)

            val passwordField =
                composeRule.onNodeWithTag(UiAutomationIds.timestampPasswordField(FIRST_AUTHORITY_INDEX))
            assertTrue(
                "timestamp password field must carry password semantics",
                passwordField.fetchSemanticsNode().config.contains(SemanticsProperties.Password),
            )
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampMoveDownAction(FIRST_AUTHORITY_INDEX))
                .performScrollTo()
                .performClick()
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampAddressField(FIRST_AUTHORITY_INDEX))
                .assertTextContains(SECOND_AUTHORITY_ADDRESS, substring = true)

            composeRule
                .onNodeWithTag(UiAutomationIds.timestampAddressField(SECOND_AUTHORITY_INDEX))
                .performScrollTo()
                .performTextReplacement(UPDATED_AUTHORITY_ADDRESS)
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampUsernameField(SECOND_AUTHORITY_INDEX))
                .performScrollTo()
                .performTextReplacement(UPDATED_USERNAME)
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampPasswordField(SECOND_AUTHORITY_INDEX))
                .performScrollTo()
                .performTextClearance()
            composeRule
                .onNodeWithTag(UiAutomationIds.TIMESTAMP_SAVE_ACTION)
                .performScrollTo()
                .performClick()

            composeRule.waitUntil(ASYNC_TIMEOUT_MILLISECONDS) {
                repository.saveCount.get() == EXPECTED_SAVE_COUNT
            }
            composeRule.waitForIdle()
            assertTrue(repository.saveWasOffMain.get())
            assertEquals(
                listOf(SECOND_AUTHORITY_ADDRESS, UPDATED_AUTHORITY_ADDRESS),
                repository.savedAddresses.get(),
            )
            assertEquals(UPDATED_USERNAME, repository.savedUsername.get())
            assertTrue(checkNotNull(repository.savedPassword.get()).isEmpty())
            composeRule
                .onNodeWithTag(UiAutomationIds.TIMESTAMP_SETTINGS_STATUS)
                .performScrollTo()
                .assertTextEquals(
                    InstrumentationRegistry
                        .getInstrumentation()
                        .targetContext
                        .getString(R.string.saved),
                )
        } finally {
            repository.close()
        }
    }

    @Test
    fun restoreRunsOffMainAndReloadsTheShippedAuthority() {
        val repository = RecordingTimestampAuthorityRepository()
        try {
            show(repository)
            openAndAwait(repository)

            composeRule
                .onNodeWithTag(UiAutomationIds.TIMESTAMP_RESTORE_ACTION)
                .performScrollTo()
                .performClick()
            composeRule.waitUntil(ASYNC_TIMEOUT_MILLISECONDS) {
                repository.restoreCount.get() == EXPECTED_RESTORE_COUNT &&
                    repository.loadCount.get() == EXPECTED_LOAD_COUNT_AFTER_RESTORE
            }
            composeRule.waitForIdle()

            assertTrue(repository.restoreWasOffMain.get())
            assertTrue(repository.loadWasOffMain.get())
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampAddressField(FIRST_AUTHORITY_INDEX))
                .performScrollTo()
                .assertTextContains(
                    TimestampAuthorityConfiguration.SHIPPED_AUTHORITY_ADDRESS,
                    substring = true,
                )
            composeRule
                .onNodeWithTag(UiAutomationIds.timestampDeleteAction(FIRST_AUTHORITY_INDEX))
                .assertIsNotEnabled()
        } finally {
            repository.close()
        }
    }

    private fun show(repository: TimestampAuthorityRepository) {
        composeRule.setContent {
            RefineIdTheme {
                Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                    TimestampAuthoritySettingsHarness(repository)
                }
            }
        }
    }

    private fun openAndAwait(repository: RecordingTimestampAuthorityRepository) {
        composeRule
            .onNodeWithTag(UiAutomationIds.TIMESTAMP_SETTINGS_ACTION)
            .assertIsDisplayed()
            .performClick()
        composeRule.waitUntil(ASYNC_TIMEOUT_MILLISECONDS) {
            repository.loadCount.get() == EXPECTED_INITIAL_LOAD_COUNT &&
                composeRule
                    .onAllNodesWithTag(
                        UiAutomationIds.timestampAddressField(FIRST_AUTHORITY_INDEX),
                    ).fetchSemanticsNodes()
                    .size == EXPECTED_NODE_COUNT
        }
    }

    private class RecordingTimestampAuthorityRepository :
        TimestampAuthorityRepository,
        AutoCloseable {
        val loadCount = AtomicInteger(NO_CALLS)
        val saveCount = AtomicInteger(NO_CALLS)
        val restoreCount = AtomicInteger(NO_CALLS)
        val loadWasOffMain = AtomicBoolean(false)
        val saveWasOffMain = AtomicBoolean(false)
        val restoreWasOffMain = AtomicBoolean(false)
        val savedAddresses = AtomicReference<List<String>>(emptyList())
        val savedUsername = AtomicReference<String?>(null)
        val savedPassword = AtomicReference<CharArray?>(null)
        private val isRestored = AtomicBoolean(false)

        override fun load(): List<TimestampAuthorityConfiguration> {
            loadWasOffMain.set(Looper.myLooper() != Looper.getMainLooper())
            loadCount.incrementAndGet()
            if (isRestored.get()) {
                return listOf(TimestampAuthorityConfiguration.shipped())
            }
            val password = INITIAL_PASSWORD_TEXT.toCharArray()
            return try {
                listOf(
                    TimestampAuthorityConfiguration.copyOf(
                        address = FIRST_AUTHORITY_ADDRESS,
                        username = INITIAL_USERNAME,
                        password = password,
                    ),
                    TimestampAuthorityConfiguration.copyOf(
                        address = SECOND_AUTHORITY_ADDRESS,
                        username = null,
                        password = null,
                    ),
                )
            } finally {
                password.fill(CLEARED_CHARACTER)
            }
        }

        override fun save(authorities: List<TimestampAuthorityConfiguration>) {
            saveWasOffMain.set(Looper.myLooper() != Looper.getMainLooper())
            savedAddresses.set(authorities.map(TimestampAuthorityConfiguration::address))
            val credentialed = authorities.single { authority -> authority.hasCredentials }
            savedUsername.set(credentialed.username)
            savedPassword.getAndSet(credentialed.copyPassword())?.fill(CLEARED_CHARACTER)
            saveCount.incrementAndGet()
        }

        override fun restoreDefaults() {
            restoreWasOffMain.set(Looper.myLooper() != Looper.getMainLooper())
            isRestored.set(true)
            restoreCount.incrementAndGet()
        }

        override fun close() {
            savedPassword.getAndSet(null)?.fill(CLEARED_CHARACTER)
        }
    }

    private companion object {
        const val FIRST_AUTHORITY_ADDRESS = "https://first.timestamp.example/request"
        const val SECOND_AUTHORITY_ADDRESS = "http://second.timestamp.example/request"
        const val UPDATED_AUTHORITY_ADDRESS = "https://updated.timestamp.example/request"
        const val INITIAL_USERNAME = "initial-account"
        const val UPDATED_USERNAME = "updated-account"
        const val INITIAL_PASSWORD_TEXT = "synthetic-password"
        const val FIRST_AUTHORITY_INDEX = 0
        const val SECOND_AUTHORITY_INDEX = 1
        const val NO_CALLS = 0
        const val EXPECTED_INITIAL_LOAD_COUNT = 1
        const val EXPECTED_LOAD_COUNT_AFTER_RESTORE = 2
        const val EXPECTED_SAVE_COUNT = 1
        const val EXPECTED_RESTORE_COUNT = 1
        const val EXPECTED_NODE_COUNT = 1
        const val ASYNC_TIMEOUT_MILLISECONDS = 10_000L
        const val CLEARED_CHARACTER = '\u0000'
    }
}
