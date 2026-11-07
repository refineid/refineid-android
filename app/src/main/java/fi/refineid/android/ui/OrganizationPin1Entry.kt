// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.core.organizationPin1Refused

/**
 * Entry for an organization card's Basic PIN 1, the password that opens the
 * card; it has no access number. The tries the card reports show before any
 * entry and after any refusal. At two or one tries left, and for a blocked PIN,
 * no entry is offered: the retry floor would refuse it.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun OrganizationPin1Entry(
    attemptsLeft: Int?,
    answer: Pin1Verification?,
    isOpening: Boolean,
    onSubmit: (Pin1Submission) -> Unit,
    modifier: Modifier = Modifier,
) {
    val pin = remember { TextFieldState() }
    DisposableEffect(pin) {
        onDispose { pin.clearText() }
    }
    val refused = organizationPin1Refused(attemptsLeft)
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(ENTRY_SPACING)) {
        answerMessage(answer)?.let { message ->
            Text(text = stringResource(message), color = MaterialTheme.colorScheme.error)
        }
        if (attemptsLeft != null && attemptsLeft < FULL_ATTEMPTS && attemptsLeft > 0) {
            Text(stringResource(R.string.pin_attempts_left, attemptsLeft))
        }
        if (refused) {
            Text(text = stringResource(refusalMessage(attemptsLeft)), color = MaterialTheme.colorScheme.error)
        } else {
            Text(stringResource(R.string.organization_card_found_enter_pin1))
            SecureTextField(
                state = pin,
                modifier = Modifier.fillMaxWidth().testTag(UiAutomationIds.NFC_ORGANIZATION_PIN1_FIELD),
                enabled = !isOpening,
                label = { Text(stringResource(R.string.pin1)) },
                labelPosition = SecretFieldLabelPosition,
                inputTransformation = Pin1InputTransformation,
                textObfuscationMode = TextObfuscationMode.Hidden,
                keyboardOptions =
                    KeyboardOptions(
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.NumberPassword,
                    ),
            )
            Button(
                enabled = !isOpening && Pin1Submission.isComplete(pin.text),
                modifier = Modifier.fillMaxWidth().testTag(UiAutomationIds.NFC_ORGANIZATION_CONNECT_ACTION),
                onClick = {
                    val submitted = Pin1Submission.from(pin.text)
                    pin.clearText()
                    onSubmit(submitted)
                },
            ) { Text(stringResource(R.string.read_identity_card)) }
        }
    }
}

private fun answerMessage(answer: Pin1Verification?): Int? =
    when (answer?.result) {
        Pin1VerificationResult.WRONG_PIN -> R.string.wrong_pin1
        Pin1VerificationResult.VERIFICATION_REJECTED -> R.string.pin_refused
        else -> null
    }

private fun refusalMessage(attemptsLeft: Int?): Int =
    if (attemptsLeft == 0) R.string.pin1_blocked else R.string.refuse_low_attempts_pin

private const val FULL_ATTEMPTS = fi.refineid.android.core.FINEID_PIN_TRY_LIMIT
private val ENTRY_SPACING = 12.dp
