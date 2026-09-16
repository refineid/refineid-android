package fi.refineid.android.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.getBoundsInRoot
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.PersonCardDetails
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
internal class PersonScreenTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun narrowScreenStacksPhotoButtonsOnOwnLines() {
        show(NARROW_CONTAINER_WIDTH)

        val copyTop = topOf(UiAutomationIds.COPY_PHOTO_ACTION)
        val shareTop = topOf(UiAutomationIds.SHARE_PHOTO_ACTION)

        assertNotEquals(copyTop, shareTop)
    }

    @Test
    fun wideScreenKeepsPhotoButtonsSideBySide() {
        show(WIDE_CONTAINER_WIDTH)

        val copyTop = topOf(UiAutomationIds.COPY_PHOTO_ACTION)
        val shareTop = topOf(UiAutomationIds.SHARE_PHOTO_ACTION)

        assertEquals(copyTop, shareTop)
    }

    private fun show(containerWidth: Dp) {
        composeRule.setContent {
            ReFineIdTheme {
                Box(modifier = Modifier.width(containerWidth)) {
                    PersonScreen(
                        details =
                            PersonCardDetails(
                                holderName = SYNTHETIC_HOLDER_NAME,
                                fullName = SYNTHETIC_HOLDER_NAME,
                            ),
                        onReadPhoto = null,
                    )
                }
            }
        }
        composeRule.onNodeWithTag(UiAutomationIds.COPY_PHOTO_ACTION).assertIsDisplayed()
        composeRule.onNodeWithTag(UiAutomationIds.SHARE_PHOTO_ACTION).assertIsDisplayed()
    }

    private fun topOf(tag: String): Dp = composeRule.onNodeWithTag(tag).getBoundsInRoot().top

    private companion object {
        val NARROW_CONTAINER_WIDTH = 200.dp
        val WIDE_CONTAINER_WIDTH = 400.dp
        const val SYNTHETIC_HOLDER_NAME = "MEIKALAINEN MATTI"
    }
}
