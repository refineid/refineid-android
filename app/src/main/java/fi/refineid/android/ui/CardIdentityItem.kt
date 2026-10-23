// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.PersonCardDetails

internal data class CardIdentityItem(
    val id: String,
    val title: String,
    val transportLabel: String,
    val isActivationRequired: Boolean = false,
    val isSelected: Boolean = true,
    val details: PersonCardDetails? = null,
    val onSelect: (() -> Unit)? = null,
    val onForget: (() -> Unit)? = null,
)

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun CardItemRow(
    card: CardIdentityItem,
    onClick: () -> Unit,
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(
                    onClickLabel = if (!card.isSelected) stringResource(R.string.card_switch_reader) else null,
                    onClick = onClick,
                ).padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING)
                .testTag(UiAutomationIds.IDENTITY_ROW),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
    ) {
        Icon(
            imageVector = Icons.Outlined.Person,
            contentDescription = null,
            tint =
                if (card.isSelected) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            modifier = Modifier.size(ROW_ICON_SIZE),
        )
        Column(modifier = Modifier.weight(ROW_LABEL_WEIGHT)) {
            Text(
                text = card.title,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = if (card.isSelected) FontWeight.SemiBold else FontWeight.Normal,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = card.transportLabel,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (card.isActivationRequired) {
            Text(
                text = stringResource(R.string.card_not_activated),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                fontWeight = FontWeight.Bold,
            )
        } else {
            card.onForget?.let { onForget -> ForgetIdentityButton(onForget = onForget) }
        }
    }
}

/**
 * The trailing control of an identity row: one tap removes the identity
 * from the phone.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun ForgetIdentityButton(onForget: () -> Unit) {
    IconButton(
        onClick = onForget,
        modifier =
            Modifier
                .size(FORGET_IDENTITY_BUTTON_SIZE)
                .testTag(UiAutomationIds.FORGET_IDENTITY_ACTION),
    ) {
        Icon(
            imageVector = MinusCircleIcon,
            contentDescription = stringResource(R.string.forget_identity),
            tint = MaterialTheme.colorScheme.error,
            modifier = Modifier.size(ROW_ICON_SIZE),
        )
    }
}

private val FORGET_IDENTITY_BUTTON_SIZE = 44.dp

private val MinusCircleIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "MinusCircle",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18" +
                            "c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-5-9h10v2H7z",
                    ).toNodes(),
            fill = SolidColor(Color.Black),
        ).build()
}
