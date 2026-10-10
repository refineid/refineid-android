package fi.refineid.android.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.graphics.Color

private val REFINED_ID_PRIMARY = Color(0xFF0056A6)
private val REFINED_ID_PRIMARY_CONTAINER = Color(0xFFD7E9FF)
private val REFINED_ID_ON_PRIMARY_CONTAINER = Color(0xFF001C38)
private val REFINED_ID_SECONDARY = Color(0xFF35618E)
private val REFINED_ID_BACKGROUND = Color(0xFFF7F9FC)
private val REFINED_ID_ON_BACKGROUND = Color(0xFF171C22)
private val REFINED_ID_SURFACE_VARIANT = Color(0xFFE2E8F0)
private val REFINED_ID_ON_SURFACE_VARIANT = Color(0xFF424A54)
private val REFINED_ID_ERROR = Color(0xFFBA1A1A)

private val ReFineIdColors =
    lightColorScheme(
        primary = REFINED_ID_PRIMARY,
        onPrimary = Color.White,
        primaryContainer = REFINED_ID_PRIMARY_CONTAINER,
        onPrimaryContainer = REFINED_ID_ON_PRIMARY_CONTAINER,
        secondary = REFINED_ID_SECONDARY,
        onSecondary = Color.White,
        background = REFINED_ID_BACKGROUND,
        onBackground = REFINED_ID_ON_BACKGROUND,
        surface = Color.White,
        onSurface = REFINED_ID_ON_BACKGROUND,
        surfaceVariant = REFINED_ID_SURFACE_VARIANT,
        onSurfaceVariant = REFINED_ID_ON_SURFACE_VARIANT,
        error = REFINED_ID_ERROR,
    )

/**
 * Dark theme is the Android-provided Material baseline, not a second
 * hand-rolled brand palette: it tracks the platform in both themes.
 */
private val ReFineIdDarkColors = darkColorScheme()

/** Effective dark flag for status colors, following the system theme. */
internal val LocalRefineIdDarkTheme = compositionLocalOf { false }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun ReFineIdTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(LocalRefineIdDarkTheme provides darkTheme) {
        MaterialTheme(
            colorScheme = if (darkTheme) ReFineIdDarkColors else ReFineIdColors,
            typography = Typography(),
            content = content,
        )
    }
}

private val SUCCESS_GREEN_DARK = Color(0xFF75D69B)
private val SUCCESS_GREEN_LIGHT = Color(0xFF168447)
private val WARNING_AMBER_DARK = Color(0xFFFFB74D)
private val WARNING_AMBER_LIGHT = Color(0xFFE18400)

/** Status green that stays readable on both light and dark surfaces. */
@Composable
internal fun successStatusColor(): Color =
    if (LocalRefineIdDarkTheme.current) SUCCESS_GREEN_DARK else SUCCESS_GREEN_LIGHT

/** Warning amber that stays readable on both light and dark surfaces. */
@Composable
internal fun permissionStatusColor(): Color =
    if (LocalRefineIdDarkTheme.current) WARNING_AMBER_DARK else WARNING_AMBER_LIGHT

private val SUCCESS_CONTAINER_LIGHT = Color(0xFFD4F2DF)
private val ON_SUCCESS_CONTAINER_LIGHT = Color(0xFF00391B)
private val SUCCESS_CONTAINER_DARK = Color(0xFF1D4A30)
private val ON_SUCCESS_CONTAINER_DARK = Color(0xFFB7F0C8)
private val WARNING_CONTAINER_LIGHT = Color(0xFFFFE8C2)
private val ON_WARNING_CONTAINER_LIGHT = Color(0xFF3A2400)
private val WARNING_CONTAINER_DARK = Color(0xFF5A3E00)
private val ON_WARNING_CONTAINER_DARK = Color(0xFFFFDDB0)

/** Container and content colors of a status banner. */
internal data class StatusContainerColors(
    val container: Color,
    val content: Color,
)

/** Green banner colors for a completed action, readable in both themes. */
@Composable
internal fun successContainerColors(): StatusContainerColors =
    if (LocalRefineIdDarkTheme.current) {
        StatusContainerColors(SUCCESS_CONTAINER_DARK, ON_SUCCESS_CONTAINER_DARK)
    } else {
        StatusContainerColors(SUCCESS_CONTAINER_LIGHT, ON_SUCCESS_CONTAINER_LIGHT)
    }

/** Amber banner colors for a caution, readable in both themes. */
@Composable
internal fun warningContainerColors(): StatusContainerColors =
    if (LocalRefineIdDarkTheme.current) {
        StatusContainerColors(WARNING_CONTAINER_DARK, ON_WARNING_CONTAINER_DARK)
    } else {
        StatusContainerColors(WARNING_CONTAINER_LIGHT, ON_WARNING_CONTAINER_LIGHT)
    }
