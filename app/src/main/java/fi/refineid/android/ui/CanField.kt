// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import fi.refineid.android.R
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission

/**
 * Entry for a card access number. The CAN is a secret like the PINs: the
 * field starts empty and hidden, the eye reveals only what the holder is
 * typing, and a remembered CAN is never written into it.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun CanField(
    state: TextFieldState,
    testTag: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    imeAction: ImeAction = ImeAction.Done,
    onKeyboardAction: (() -> Unit)? = null,
) {
    SecretField(
        state = state,
        testTag = testTag,
        modifier = modifier,
        label = stringResource(R.string.can),
        enabled = enabled,
        inputTransformation = CanInputTransformation,
        imeAction = imeAction,
        onKeyboardAction = onKeyboardAction,
        revealNames = CanRevealNames,
    )
}

/**
 * True when [entry] can be submitted: six typed digits, or an empty field
 * while a CAN is remembered.
 */
internal fun canEntryReady(entry: CharSequence): Boolean =
    CanSubmission.isComplete(entry) || (entry.isEmpty() && CanSessionStore.hasCan)

/**
 * The CAN that [entry] submits: the typed digits, or the remembered CAN
 * when the field is empty. Null when neither is complete.
 */
internal fun canEntrySubmission(entry: CharSequence): CanSubmission? =
    when {
        CanSubmission.isComplete(entry) -> CanSubmission.from(entry)
        entry.isEmpty() -> CanSessionStore.currentCan?.let { CanSubmission.from(it) }
        else -> null
    }

internal val CanInputTransformation =
    InputTransformation {
        if (!CanSubmission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }
