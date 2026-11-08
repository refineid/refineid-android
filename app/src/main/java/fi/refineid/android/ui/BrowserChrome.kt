// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import fi.refineid.android.R
import fi.refineid.android.browser.BrowserSessionHistory
import fi.refineid.android.browser.BrowserSignatureStatus
import java.util.concurrent.atomic.AtomicReference

/** What the open page tells the browsing controls. */
@Stable
internal class BrowserPageState {
    /** The address of the page shown, as the WebView reports it. */
    var url by mutableStateOf("")
        private set

    /** Loading progress of the page, in percent; [PAGE_LOADED_PERCENT] when idle. */
    var progressPercent by mutableIntStateOf(PAGE_LOADED_PERCENT)

    var canGoBack by mutableStateOf(false)
        private set

    var canGoForward by mutableStateOf(false)
        private set

    /** The page in [view] moved to [address]; records it in the session history. */
    fun pageChanged(
        view: WebView,
        address: String,
    ) {
        url = address
        canGoBack = view.canGoBack()
        canGoForward = view.canGoForward()
        BrowserSessionHistory.process.record(address)
    }

    internal companion object {
        const val PAGE_START_PERCENT = 0
        const val PAGE_LOADED_PERCENT = 100
    }
}

/** Answers a page's file input with the files the holder chose, or none. */
internal typealias BrowserFileChooser = (WebChromeClient.FileChooserParams, (Array<Uri>?) -> Unit) -> Unit

/**
 * Reports page progress to [page] and opens the system file picker for a
 * page's file input through [chooseFiles]. The WebView keeps its default
 * single-window mode, so no other window opens.
 */
internal class BrowserChromeClient(
    private val page: BrowserPageState,
    private val chooseFiles: BrowserFileChooser,
) : WebChromeClient() {
    override fun onProgressChanged(
        view: WebView,
        newProgress: Int,
    ) {
        page.progressPercent =
            newProgress.coerceIn(BrowserPageState.PAGE_START_PERCENT, BrowserPageState.PAGE_LOADED_PERCENT)
    }

    override fun onShowFileChooser(
        webView: WebView,
        filePathCallback: ValueCallback<Array<Uri>>,
        fileChooserParams: FileChooserParams,
    ): Boolean {
        chooseFiles(fileChooserParams) { files -> filePathCallback.onReceiveValue(files) }
        return true
    }
}

/**
 * The system file picker for a page's file input. Every request is
 * answered once: with the files chosen, or with none when the holder
 * cancels, no picker exists, or a newer request replaces it.
 */
@Composable
internal fun rememberBrowserFileChooser(): BrowserFileChooser {
    val pending = remember { AtomicReference<((Array<Uri>?) -> Unit)?>(null) }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            pending
                .getAndSet(
                    null,
                )?.invoke(WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data))
        }
    return remember(launcher) {
        { params, answer ->
            pending.getAndSet(answer)?.invoke(null)
            try {
                launcher.launch(params.createIntent())
            } catch (_: ActivityNotFoundException) {
                pending.getAndSet(null)?.invoke(null)
            } catch (_: SecurityException) {
                pending.getAndSet(null)?.invoke(null)
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserControlsBar(
    page: BrowserPageState,
    signatureStatus: BrowserSignatureStatus,
    onNavigate: (String) -> Unit,
    onBack: () -> Unit,
    onForward: () -> Unit,
    onReload: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var field by remember { mutableStateOf(TextFieldValue("")) }
    var editing by remember { mutableStateOf(false) }
    val focusManager = LocalFocusManager.current
    LaunchedEffect(page.url, editing) {
        if (!editing) field = TextFieldValue(page.url)
    }
    val go = { typed: String ->
        focusManager.clearFocus()
        onNavigate(typed)
    }
    val suggestions = if (editing) BrowserSessionHistory.process.suggestions(field.text) else emptyList()
    Column(
        modifier =
            modifier
                .fillMaxWidth()
                .safeDrawingPadding()
                .padding(horizontal = FLOATING_BAR_HORIZONTAL_PADDING, vertical = FLOATING_BAR_BOTTOM_PADDING),
        verticalArrangement = Arrangement.spacedBy(BROWSER_ITEM_SPACING),
    ) {
        BrowserStatus(signatureStatus)
        if (suggestions.isNotEmpty()) {
            BrowserSuggestions(suggestions = suggestions, onPick = go)
        }
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(FLOATING_BAR_CORNER_RADIUS),
            color = MaterialTheme.colorScheme.surface.copy(alpha = FLOATING_BAR_ALPHA),
            shadowElevation = FLOATING_BAR_ELEVATION,
        ) {
            Column {
                if (page.progressPercent < BrowserPageState.PAGE_LOADED_PERCENT) {
                    LinearProgressIndicator(
                        progress = { page.progressPercent.toFloat() / BrowserPageState.PAGE_LOADED_PERCENT },
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = FLOATING_BAR_CORNER_RADIUS)
                                .testTag(UiAutomationIds.BROWSER_PROGRESS),
                    )
                }
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(FLOATING_BAR_INNER_PADDING),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(
                        onClick = onBack,
                        enabled = page.canGoBack,
                        modifier = Modifier.testTag(UiAutomationIds.BROWSER_BACK_ACTION),
                    ) {
                        Text(stringResource(R.string.browser_back))
                    }
                    IconButton(
                        onClick = onForward,
                        enabled = page.canGoForward,
                        modifier = Modifier.testTag(UiAutomationIds.BROWSER_FORWARD_ACTION),
                    ) {
                        Text(stringResource(R.string.browser_forward))
                    }
                    IconButton(
                        onClick = onReload,
                        modifier = Modifier.testTag(UiAutomationIds.BROWSER_RELOAD_ACTION),
                    ) {
                        Text(stringResource(R.string.browser_reload))
                    }
                    OutlinedTextField(
                        value = field,
                        onValueChange = { field = it },
                        modifier =
                            Modifier
                                .weight(BROWSER_FIELD_WEIGHT)
                                .onFocusChanged { state ->
                                    if (state.isFocused && !editing) {
                                        // A tap on the address selects it whole, ready to replace.
                                        field = field.copy(selection = TextRange(0, field.text.length))
                                    }
                                    editing = state.isFocused
                                }.testTag(UiAutomationIds.BROWSER_URL_FIELD),
                        singleLine = true,
                        trailingIcon = {
                            IconButton(
                                onClick = { go(field.text) },
                                modifier = Modifier.testTag(UiAutomationIds.BROWSER_GO_ACTION),
                            ) {
                                Text(stringResource(R.string.browser_go))
                            }
                        },
                        keyboardOptions =
                            KeyboardOptions(
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.Uri,
                                imeAction = ImeAction.Go,
                            ),
                        keyboardActions = KeyboardActions(onGo = { go(field.text) }),
                    )
                    BrowserMenu(url = page.url)
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserSuggestions(
    suggestions: List<String>,
    onPick: (String) -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(FLOATING_BAR_CORNER_RADIUS),
        color = MaterialTheme.colorScheme.surface.copy(alpha = FLOATING_BAR_ALPHA),
        shadowElevation = FLOATING_BAR_ELEVATION,
    ) {
        Column(modifier = Modifier.padding(vertical = SUGGESTION_LIST_PADDING)) {
            suggestions.forEach { address ->
                Text(
                    text = BrowserSessionHistory.readable(address),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .clickable(role = Role.Button) { onPick(address) }
                            .padding(horizontal = SUGGESTION_HORIZONTAL_PADDING, vertical = SUGGESTION_VERTICAL_PADDING)
                            .testTag(UiAutomationIds.BROWSER_SUGGESTION),
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserMenu(url: String) {
    val context = LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    val hasPage = url.isNotEmpty()
    IconButton(
        onClick = { expanded = true },
        enabled = hasPage,
        modifier = Modifier.testTag(UiAutomationIds.BROWSER_MENU_ACTION),
    ) {
        Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.browser_more))
    }
    DropdownMenu(
        expanded = expanded,
        onDismissRequest = { expanded = false },
        // The menu is its own window; its tags reach UI automation only when it says so.
        modifier = Modifier.semantics { testTagsAsResourceId = true },
    ) {
        DropdownMenuItem(
            text = { Text(stringResource(R.string.browser_copy_link)) },
            onClick = {
                expanded = false
                copyLink(context, url)
            },
            modifier = Modifier.testTag(UiAutomationIds.BROWSER_COPY_LINK_ACTION),
        )
        DropdownMenuItem(
            text = { Text(stringResource(R.string.browser_share)) },
            onClick = {
                expanded = false
                startOrIgnore(
                    context,
                    Intent.createChooser(
                        Intent(Intent.ACTION_SEND).setType(PLAIN_TEXT).putExtra(Intent.EXTRA_TEXT, url),
                        null,
                    ),
                )
            },
            modifier = Modifier.testTag(UiAutomationIds.BROWSER_SHARE_ACTION),
        )
        DropdownMenuItem(
            // The link alone opens there; this browser's session stays here.
            text = { Text(stringResource(R.string.browser_open_external)) },
            onClick = {
                expanded = false
                startOrIgnore(context, Intent(Intent.ACTION_VIEW, url.toUri()))
            },
            modifier = Modifier.testTag(UiAutomationIds.BROWSER_OPEN_EXTERNAL_ACTION),
        )
    }
}

private fun copyLink(
    context: Context,
    url: String,
) {
    context
        .getSystemService(ClipboardManager::class.java)
        ?.setPrimaryClip(ClipData.newPlainText(context.getString(R.string.browser_link), url))
}

private fun startOrIgnore(
    context: Context,
    intent: Intent,
) {
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        // No app takes it; the menu item then does nothing.
    } catch (_: SecurityException) {
        // The app that would take it refuses this caller; likewise nothing.
    }
}

private const val PLAIN_TEXT = "text/plain"
private const val BROWSER_FIELD_WEIGHT = 1F
private const val FLOATING_BAR_ALPHA = 0.95f
private val BROWSER_ITEM_SPACING = 12.dp
private val FLOATING_BAR_HORIZONTAL_PADDING = 12.dp
private val FLOATING_BAR_BOTTOM_PADDING = 8.dp
private val FLOATING_BAR_CORNER_RADIUS = 28.dp
private val FLOATING_BAR_INNER_PADDING = 4.dp
private val FLOATING_BAR_ELEVATION = 6.dp
private val SUGGESTION_LIST_PADDING = 8.dp
private val SUGGESTION_HORIZONTAL_PADDING = 20.dp
private val SUGGESTION_VERTICAL_PADDING = 12.dp
