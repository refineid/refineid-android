// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldLabelPosition
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.autofill.ContentDataType
import androidx.compose.ui.autofill.FillableData
import androidx.compose.ui.autofill.createFromText
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDataType
import androidx.compose.ui.semantics.editableText
import androidx.compose.ui.semantics.fillableData
import androidx.compose.ui.semantics.inputText
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import fi.refineid.android.R

/**
 * Where every PIN, PUK and access-number field shows its label: above
 * the field, across its full width. A label inside the field shares the
 * row with the padding and the reveal control, so a long Finnish name
 * such as "Allekirjoitustunnusluku 2" wraps there; above the field it
 * has the whole column and keeps the name with its number.
 */
internal val SecretFieldLabelPosition: TextFieldLabelPosition = TextFieldLabelPosition.Above()

/**
 * The character a secret field shows and reports to accessibility in place
 * of each typed character: U+2022 BULLET, the mask Android's View-based
 * password fields use and the mask [SecureTextField] draws.
 */
internal const val SECRET_MASK_CHARACTER: Char = '•'

/** The spoken names of a secret field's reveal control. */
internal class SecretRevealNames(
    @param:StringRes val show: Int,
    @param:StringRes val hide: Int,
)

internal val PinRevealNames = SecretRevealNames(show = R.string.show_pin, hide = R.string.hide_pin)
internal val CanRevealNames = SecretRevealNames(show = R.string.show_can, hide = R.string.hide_can)

/**
 * Entry for a secret: a PIN, the PUK, an activation PIN, a card access
 * number, or a password. Every such field in the app is this one.
 *
 * The field draws a bullet per character unless the holder reveals it, and
 * whatever it draws, it tells the rest of the system only the bullets:
 * the accessibility node's text, its text-change and selection events, and
 * the autofill and content-capture structure all carry one
 * [SECRET_MASK_CHARACTER] per typed character, never the characters
 * themselves. A screen reader can count what was typed and read nothing
 * else. Compose's own text field reports the typed text to accessibility
 * and autofill even with password semantics, so this field overrides the
 * text semantics on the outermost modifier, which Compose applies last.
 * The field is also kept out of autofill, which the activity disables for
 * the whole window as well.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming", "LongParameterList")
@Composable
internal fun SecretField(
    state: TextFieldState,
    testTag: String,
    modifier: Modifier = Modifier,
    label: String? = null,
    enabled: Boolean = true,
    inputTransformation: InputTransformation? = null,
    keyboardType: KeyboardType = KeyboardType.NumberPassword,
    imeAction: ImeAction = ImeAction.Unspecified,
    onKeyboardAction: (() -> Unit)? = null,
    revealNames: SecretRevealNames? = null,
) {
    var revealed by remember { mutableStateOf(false) }
    SecureTextField(
        state = state,
        modifier = modifier.testTag(testTag).secretSemantics(state),
        enabled = enabled,
        label = if (label != null) ({ Text(label) }) else null,
        labelPosition = SecretFieldLabelPosition,
        inputTransformation = inputTransformation,
        textObfuscationMode =
            if (revealed && revealNames != null) TextObfuscationMode.Visible else TextObfuscationMode.Hidden,
        keyboardOptions =
            KeyboardOptions(
                autoCorrectEnabled = false,
                keyboardType = keyboardType,
                imeAction = imeAction,
            ),
        onKeyboardAction = onKeyboardAction?.let { action -> { action() } },
        trailingIcon =
            if (revealNames != null) {
                {
                    IconButton(
                        onClick = { revealed = !revealed },
                        modifier = Modifier.testTag(secretRevealTestTag(testTag)),
                    ) {
                        Icon(
                            painter =
                                painterResource(
                                    if (revealed) R.drawable.ic_visibility_off else R.drawable.ic_visibility,
                                ),
                            contentDescription =
                                stringResource(if (revealed) revealNames.hide else revealNames.show),
                        )
                    }
                }
            } else {
                null
            },
    )
}

/** The test tag of the reveal control of the secret field tagged [fieldTestTag]. */
internal fun secretRevealTestTag(fieldTestTag: String): String = "${fieldTestTag}Toggle"

/** What a secret field reports for [length] typed characters: that many bullets. */
internal fun maskedSecret(length: Int): String = SECRET_MASK_CHARACTER.toString().repeat(length)

/**
 * Replaces the text semantics the text field sets with the masked value.
 * The lambda reads [state], so Compose recomputes it as the holder types.
 */
private fun Modifier.secretSemantics(state: TextFieldState): Modifier =
    semantics {
        val masked = maskedSecret(state.text.length)
        editableText = AnnotatedString(masked)
        inputText = AnnotatedString(masked)
        contentDataType = ContentDataType.None
        FillableData.createFromText(masked)?.let { fillableData = it }
    }
