@file:Suppress("LongMethod", "MagicNumber")

package fi.refineid.android.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.diagnostics.DiagnosticsSnapshot

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DiagnosticsScreen(
    snapshot: DiagnosticsSnapshot,
    onRefresh: () -> Unit,
    onClearLogs: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var showsClearConfirmation by remember { mutableStateOf(false) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SUBSCREEN_ITEM_SPACING),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Button(
                onClick = {
                    copyReportToClipboard(context, snapshot.toReportText())
                },
                modifier =
                    Modifier
                        .weight(1f)
                        .testTag(UiAutomationIds.COPY_REPORT_ACTION),
            ) {
                Icon(
                    imageVector = CopyIcon,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.copy_report))
            }

            OutlinedButton(
                onClick = onRefresh,
                modifier = Modifier.size(48.dp),
                contentPadding =
                    androidx.compose.foundation.layout
                        .PaddingValues(0.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Refresh,
                    contentDescription = stringResource(R.string.refresh),
                    modifier = Modifier.size(20.dp),
                )
            }
        }

        DiagnosticBlock(
            title = "Application",
            content = snapshot.appInfo,
        )

        DiagnosticBlock(
            title = "Device",
            content = snapshot.deviceInfo,
        )

        DiagnosticBlock(
            title = "NFC",
            content = snapshot.nfcStatus,
        )

        DiagnosticBlock(
            title = "USB CCID",
            content = snapshot.usbStatus,
        )

        DiagnosticBlock(
            title = "Card & Identity",
            content = snapshot.cardStatus,
        )

        val traceContent =
            if (snapshot.traceLogs.isEmpty()) {
                "(no trace events recorded)"
            } else {
                snapshot.traceLogs.joinToString("\n")
            }

        DiagnosticBlock(
            title = "Trace Log (${snapshot.traceLogs.size})",
            content = traceContent,
            isMonospace = true,
        )

        OutlinedButton(
            onClick = { showsClearConfirmation = true },
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.CLEAR_LOGS_ACTION),
            colors =
                ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error,
                ),
        ) {
            Icon(
                imageVector = Icons.Outlined.Delete,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.clear_logs))
        }
    }

    if (showsClearConfirmation) {
        AlertDialog(
            onDismissRequest = { showsClearConfirmation = false },
            title = {
                Text(
                    text = stringResource(R.string.clear_logs),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            },
            text = {
                Text(
                    text = "This clears RefineID's diagnostic trace. It does not remove your card details.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showsClearConfirmation = false
                        onClearLogs()
                        onRefresh()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                ) {
                    Text(stringResource(R.string.proceed))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showsClearConfirmation = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DiagnosticBlock(
    title: String,
    content: String,
    isMonospace: Boolean = false,
) {
    Section(title = title) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
            shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
        ) {
            Box(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(ROW_HORIZONTAL_PADDING),
            ) {
                if (isMonospace) {
                    Row(modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        Text(
                            text = content,
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                } else {
                    Text(
                        text = content,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }
        }
    }
}

private fun copyReportToClipboard(
    context: Context,
    text: String,
) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val clip = ClipData.newPlainText("RefineID Diagnostics", text)
    clipboard?.setPrimaryClip(clip)
    Toast.makeText(context, context.getString(R.string.report_copied), Toast.LENGTH_SHORT).show()
}

private val CopyIcon: ImageVector by lazy {
    ImageVector
        .Builder(
            name = "Copy",
            defaultWidth = 24.dp,
            defaultHeight = 24.dp,
            viewportWidth = 24f,
            viewportHeight = 24f,
        ).addPath(
            pathData =
                PathParser()
                    .parsePathString(
                        "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14" +
                            "c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
                    ).toNodes(),
            fill = SolidColor(Color.Black),
        ).build()
}
