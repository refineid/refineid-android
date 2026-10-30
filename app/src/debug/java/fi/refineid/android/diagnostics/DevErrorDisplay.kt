// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.diagnostics

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt

private val PILL_MARGIN = 12.dp
private val LIST_MAXIMUM_HEIGHT = 320.dp
private val LIST_MAXIMUM_WIDTH = 360.dp
private val LIST_PADDING = 12.dp
private val LIST_SPACING = 6.dp
private const val PILL_ELEVATION_DP = 6
private const val CLIP_LABEL = "RefineID errors"

/**
 * The debug build's error pill, drawn over the app inside the system bars
 * and cutouts: hidden until the first error, then a count that can be
 * dragged anywhere. It opens on each new error and on a tap, listing the
 * errors newest first in a list of bounded height that scrolls, with Copy
 * all and Clear.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DevErrorOverlay() {
    val entries by DevErrorLog.entries.collectAsState()
    var isOpen by remember { mutableStateOf(false) }
    var dragged by remember { mutableStateOf(Offset.Zero) }
    val newest = entries.firstOrNull()
    LaunchedEffect(newest?.serial, newest?.occurrences) {
        if (newest != null) isOpen = true
    }
    if (entries.isEmpty()) return
    Box(
        modifier =
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(PILL_MARGIN),
        contentAlignment = Alignment.BottomEnd,
    ) {
        Surface(
            modifier =
                Modifier
                    .offset { IntOffset(dragged.x.roundToInt(), dragged.y.roundToInt()) }
                    .pointerInput(Unit) {
                        detectDragGestures { change, amount ->
                            change.consume()
                            dragged += amount
                        }
                    },
            shape = RoundedCornerShape(PILL_MARGIN),
            color = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
            shadowElevation = PILL_ELEVATION_DP.dp,
        ) {
            if (isOpen) {
                Column(modifier = Modifier.widthIn(max = LIST_MAXIMUM_WIDTH).padding(LIST_PADDING)) {
                    DevErrorEntries(
                        entries,
                        Modifier.heightIn(max = LIST_MAXIMUM_HEIGHT).verticalScroll(rememberScrollState()),
                    )
                    DevErrorActions(entries, onClose = { isOpen = false })
                }
            } else {
                TextButton(onClick = { isOpen = true }) {
                    Text(text = "Errors " + entries.size)
                }
            }
        }
    }
}

/**
 * The error list for the diagnostics screen, newest first, with Copy all
 * and Clear; it takes the height of its entries and scrolls with the screen.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DevErrorSection() {
    val entries by DevErrorLog.entries.collectAsState()
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = "Errors (" + entries.size + ")", style = MaterialTheme.typography.titleSmall)
        if (entries.isEmpty()) {
            Text(text = "(no errors recorded)", style = MaterialTheme.typography.bodySmall)
        } else {
            DevErrorEntries(entries, Modifier)
            DevErrorActions(entries, onClose = null)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DevErrorEntries(
    entries: List<DevErrorLog.Entry>,
    modifier: Modifier,
) {
    SelectionContainer {
        Column(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(LIST_SPACING),
        ) {
            entries.forEach { entry ->
                Text(
                    text = entry.text,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DevErrorActions(
    entries: List<DevErrorLog.Entry>,
    onClose: (() -> Unit)?,
) {
    val context = LocalContext.current
    Row(horizontalArrangement = Arrangement.spacedBy(LIST_SPACING)) {
        TextButton(onClick = { copy(context, DevErrorLog.transcript(entries)) }) { Text("Copy all") }
        TextButton(onClick = DevErrorLog::clear) { Text("Clear") }
        if (onClose != null) {
            TextButton(onClick = onClose) { Text("Close") }
        }
    }
}

private fun copy(
    context: Context,
    text: String,
) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    clipboard?.setPrimaryClip(ClipData.newPlainText(CLIP_LABEL, text))
}
