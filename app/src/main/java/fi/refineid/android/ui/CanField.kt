// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
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
    var revealed by remember { mutableStateOf(false) }
    SecureTextField(
        state = state,
        modifier = modifier.testTag(testTag),
        enabled = enabled,
        label = { Text(stringResource(R.string.can)) },
        inputTransformation = CanInputTransformation,
        textObfuscationMode = if (revealed) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        keyboardOptions =
            KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.NumberPassword,
                imeAction = imeAction,
            ),
        onKeyboardAction = onKeyboardAction?.let { action -> { action() } },
        trailingIcon = {
            IconButton(
                onClick = { revealed = !revealed },
                modifier = Modifier.testTag("${testTag}Toggle"),
            ) {
                Icon(
                    painter =
                        painterResource(
                            if (revealed) R.drawable.ic_visibility_off else R.drawable.ic_visibility,
                        ),
                    contentDescription =
                        stringResource(if (revealed) R.string.hide_can else R.string.show_can),
                )
            }
        },
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
