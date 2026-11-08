// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import android.content.Context
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.rapp.RappPairCatalog
import fi.refineid.android.rapp.RappSettings
import fi.refineid.android.rapp.RemoteCardModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.refineid_rapp.RappPairVault

/**
 * Renders the requester's pairing screen inside the SubScreen that hosts
 * it on the home screen's navigation, as a tablet or a phone without NFC
 * shows it, and checks that it lays out.
 */
@RunWith(AndroidJUnit4::class)
internal class RappRequesterPairingScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var model: RemoteCardModel

    @Before
    fun setUp() {
        clearPreferences()
        model =
            RemoteCardModel(
                context = context,
                scope = scope,
                vault = EmptyPairVault,
                catalog = RappPairCatalog(context.getSharedPreferences(CATALOG_PREFS, Context.MODE_PRIVATE)),
                settings = RappSettings(context.getSharedPreferences(SETTINGS_PREFS, Context.MODE_PRIVATE)),
            )
    }

    @After
    fun tearDown() {
        scope.cancel()
        clearPreferences()
    }

    @Test
    fun pairingScreenLaysOutInsideItsSubScreen() {
        composeRule.setContent {
            RefineIdTheme {
                SubScreen(
                    title = SYNTHETIC_TITLE,
                    tag = UiAutomationIds.REQUESTER_PAIRING_SCREEN,
                    onBack = {},
                ) {
                    RappRequesterPairingScreen(
                        remoteCardModel = model,
                        onToggleRemoteUse = {},
                        onRequestLocalNetwork = {},
                    )
                }
            }
        }

        composeRule.onNodeWithTag(UiAutomationIds.REQUESTER_REMOTE_USE_SWITCH).assertIsDisplayed()
    }

    private fun clearPreferences() {
        listOf(CATALOG_PREFS, SETTINGS_PREFS).forEach(context::deleteSharedPreferences)
    }

    /** A vault holding no pairing, which this screen never writes to. */
    private object EmptyPairVault : RappPairVault {
        override fun insertDeviceOnly(
            pairId: ByteArray,
            record: ByteArray,
        ) = Unit

        override fun replaceDeviceOnly(
            pairId: ByteArray,
            record: ByteArray,
        ) = Unit

        override fun loadDeviceOnly(pairId: ByteArray): ByteArray? = null

        override fun revokeDeviceOnly(
            pairId: ByteArray,
            revokedAtMs: ULong,
        ) = Unit

        override fun isRevoked(pairId: ByteArray): Boolean = false
    }

    private companion object {
        const val SYNTHETIC_TITLE = "Pair"
        const val CATALOG_PREFS = "fi.refineid.test.requester-pairing.catalog"
        const val SETTINGS_PREFS = "fi.refineid.test.requester-pairing.settings"
    }
}
