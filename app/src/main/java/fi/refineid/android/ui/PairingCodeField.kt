package fi.refineid.android.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.rapp.RappPairingCode

/**
 * The pairing code entry: six boxes in three pairs, as the phone shows the
 * code. One hidden field owns the input, so assistive technology meets one
 * labelled field; the boxes only show it.
 *
 * [value] holds the filtered entry, [RappPairingCode.filterEntry]; a
 * complete entry calls [onComplete] once, and the caller disables the
 * field while the code is tried.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun PairingCodeField(
    value: String,
    onValueChange: (String) -> Unit,
    onComplete: (String) -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier,
) {
    val label = stringResource(R.string.pairing_code)
    var focused by remember { mutableStateOf(false) }
    Column(
        modifier = modifier,
        verticalArrangement = Arrangement.spacedBy(CODE_FIELD_SPACING_DP.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Box(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .clearAndSetSemantics { },
            ) {
                repeat(RappPairingCode.CODE_LENGTH) { index ->
                    val next = enabled && focused && index == value.length
                    val endGap =
                        when {
                            index == RappPairingCode.CODE_LENGTH - 1 -> 0
                            index % CODE_GROUP_SIZE == CODE_GROUP_SIZE - 1 -> CODE_GROUP_GAP_DP
                            else -> CODE_BOX_GAP_DP
                        }
                    Box(
                        modifier =
                            Modifier
                                .weight(CODE_BOX_WEIGHT)
                                .height(CODE_BOX_HEIGHT_DP.dp)
                                .padding(end = endGap.dp)
                                .border(
                                    width = CODE_BOX_BORDER_DP.dp,
                                    color =
                                        when {
                                            !enabled -> MaterialTheme.colorScheme.outlineVariant
                                            next -> MaterialTheme.colorScheme.primary
                                            else -> MaterialTheme.colorScheme.outline
                                        },
                                    shape = RoundedCornerShape(CODE_BOX_CORNER_DP.dp),
                                ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = value.getOrNull(index)?.toString().orEmpty(),
                            style = MaterialTheme.typography.headlineSmall,
                            textAlign = TextAlign.Center,
                            color =
                                if (enabled) {
                                    MaterialTheme.colorScheme.onSurface
                                } else {
                                    MaterialTheme.colorScheme.onSurfaceVariant
                                },
                        )
                    }
                }
            }
            BasicTextField(
                value = value,
                onValueChange = { typed ->
                    if (!enabled) return@BasicTextField
                    val filtered = RappPairingCode.filterEntry(typed)
                    val completes = !RappPairingCode.isCompleteEntry(value) && RappPairingCode.isCompleteEntry(filtered)
                    onValueChange(filtered)
                    if (completes) onComplete(filtered)
                },
                modifier =
                    Modifier
                        .matchParentSize()
                        .alpha(0f)
                        .onFocusChanged { focused = it.isFocused }
                        .testTag(UiAutomationIds.PAIRING_CODE_FIELD)
                        .semantics { contentDescription = label },
                enabled = enabled,
                textStyle = TextStyle(color = Color.Transparent),
                keyboardOptions =
                    KeyboardOptions(
                        keyboardType = KeyboardType.Ascii,
                        autoCorrectEnabled = false,
                    ),
                singleLine = true,
                cursorBrush = SolidColor(Color.Transparent),
            )
        }
    }
}

private const val CODE_FIELD_SPACING_DP = 8
private const val CODE_BOX_WEIGHT = 1f
private const val CODE_BOX_HEIGHT_DP = 56
private const val CODE_BOX_GAP_DP = 8
private const val CODE_GROUP_GAP_DP = 16
private const val CODE_GROUP_SIZE = 2
private const val CODE_BOX_BORDER_DP = 1
private const val CODE_BOX_CORNER_DP = 8
