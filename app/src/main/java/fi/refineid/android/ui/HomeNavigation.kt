package fi.refineid.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.KeyboardArrowRight
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import fi.refineid.android.R

/**
 * The reference app's grouped-list navigation, ported natively: a
 * rounded group holds tappable rows, each with a tinted leading icon,
 * a label, and a trailing chevron, pushing to a dedicated screen.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun NavigationGroup(content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
    ) {
        Column(content = content)
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun NavigationRow(
    icon: ImageVector,
    label: String,
    tag: String,
    enabled: Boolean = true,
    onClick: () -> Unit,
) {
    val contentColor =
        if (enabled) {
            MaterialTheme.colorScheme.onSurface
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        }
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(enabled = enabled, onClick = onClick)
                .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING)
                .testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint =
                if (enabled) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            modifier = Modifier.size(ROW_ICON_SIZE),
        )
        Text(
            text = label,
            color = contentColor,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(ROW_LABEL_WEIGHT),
        )
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun NavigationRow(
    icon: Painter,
    label: String,
    tag: String,
    enabled: Boolean = true,
    iconTint: Color? = null,
    stateDescription: String? = null,
    onClick: () -> Unit,
) {
    val rowState = stateDescription
    val contentColor =
        if (enabled) {
            MaterialTheme.colorScheme.onSurface
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        }
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(enabled = enabled, onClick = onClick)
                .semantics { rowState?.let { this.stateDescription = it } }
                .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING)
                .testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
    ) {
        Icon(
            painter = icon,
            contentDescription = null,
            tint =
                iconTint
                    ?: if (enabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
            modifier = Modifier.size(ROW_ICON_SIZE),
        )
        Text(
            text = label,
            color = contentColor,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(ROW_LABEL_WEIGHT),
            maxLines = 1,
        )
        Icon(
            imageVector = Icons.AutoMirrored.Outlined.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** One pushed detail screen: a back arrow, its title, and the content. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SubScreen(
    title: String,
    tag: String,
    onBack: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    Scaffold(
        modifier =
            Modifier
                .semantics { testTagsAsResourceId = true }
                .testTag(tag),
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testTag(UiAutomationIds.BACK_ACTION),
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back),
                        )
                    }
                },
            )
        },
    ) { contentPadding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(contentPadding)
                    .navigationBarsPadding()
                    .padding(
                        horizontal = SUBSCREEN_HORIZONTAL_PADDING,
                        vertical = SUBSCREEN_VERTICAL_PADDING,
                    ),
            verticalArrangement = Arrangement.spacedBy(SUBSCREEN_ITEM_SPACING),
            content = content,
        )
    }
}

internal val SECTION_ITEM_SPACING = 8.dp
internal val GROUP_DIVIDER_INSET = 52.dp
internal val GROUP_CORNER_RADIUS = 16.dp
internal val GROUP_ELEVATION = 0.dp
internal val ROW_HORIZONTAL_PADDING = 16.dp
internal val ROW_VERTICAL_PADDING = 14.dp
internal val ROW_ITEM_SPACING = 12.dp
internal val ROW_ICON_SIZE = 24.dp
internal const val ROW_LABEL_WEIGHT = 1f
internal val SUBSCREEN_HORIZONTAL_PADDING = 16.dp
internal val SUBSCREEN_VERTICAL_PADDING = 8.dp
internal val SUBSCREEN_ITEM_SPACING = 14.dp
internal val PAIRED_PEER_ROW_VERTICAL_PADDING = 12.dp

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun Section(
    title: String,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SECTION_ITEM_SPACING),
    ) {
        SectionHeader(title)
        content()
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun SectionHeader(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 4.dp),
    )
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun ActivationBanner(
    modifier: Modifier = Modifier,
    cardLabel: String? = null,
    isMultiple: Boolean = false,
    onActivate: (() -> Unit)? = null,
) {
    Card(
        modifier =
            modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.ACTIVATION_BANNER),
        colors =
            CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f),
            ),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(ROW_HORIZONTAL_PADDING),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(28.dp),
                )
                Column(modifier = Modifier.weight(1f)) {
                    val title =
                        when {
                            !cardLabel.isNullOrBlank() && isMultiple -> {
                                stringResource(R.string.cards_not_activated_multiple, cardLabel)
                            }

                            !cardLabel.isNullOrBlank() -> {
                                stringResource(R.string.card_not_activated_named, cardLabel)
                            }

                            else -> {
                                stringResource(R.string.card_not_activated)
                            }
                        }
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Text(
                        text = stringResource(R.string.card_activation_needed_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
            if (onActivate != null) {
                Button(
                    onClick = onActivate,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.ACTIVATION_BUTTON),
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error,
                            contentColor = MaterialTheme.colorScheme.onError,
                        ),
                ) {
                    Text(stringResource(R.string.activate_card))
                }
            }
        }
    }
}
