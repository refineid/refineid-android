package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import fi.refineid.android.R
import fi.refineid.android.core.AuthenticationPreparation
import fi.refineid.android.core.AuthenticationPreparationState
import fi.refineid.android.core.AuthenticationPurpose
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.nfc.NfcReaderStatus

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun AuthenticationPreparationDialog(
    preparation: AuthenticationPreparation,
    state: AuthenticationPreparationState,
    nfcStatus: NfcReaderStatus? = null,
) {
    val title = purposeTitle(preparation.purpose.collectAsState().value)
    when (state) {
        is AuthenticationPreparationState.Credentials -> {
            PreparationCredentialsDialog(preparation, state, title)
        }

        is AuthenticationPreparationState.Failed -> {
            val message = failureMessage(state.result) ?: return
            AlertDialog(
                onDismissRequest = preparation::cancel,
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
                title = { Text(stringResource(title)) },
                text = { Text(stringResource(message)) },
                confirmButton = { TextButton(onClick = preparation::retry) { Text(stringResource(R.string.retry)) } },
                dismissButton = { TextButton(onClick = preparation::cancel) { Text(stringResource(R.string.cancel)) } },
            )
        }

        AuthenticationPreparationState.WaitingForCard, AuthenticationPreparationState.Verifying -> {
            AlertDialog(
                onDismissRequest = preparation::cancel,
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
                title = { Text(stringResource(title)) },
                text = { Text(stringResource(cardMessage(state, nfcStatus))) },
                confirmButton = { TextButton(onClick = preparation::cancel) { Text(stringResource(R.string.cancel)) } },
            )
        }

        AuthenticationPreparationState.Idle, AuthenticationPreparationState.Ready -> {}
    }
}

private fun purposeTitle(purpose: AuthenticationPurpose): Int =
    when (purpose) {
        AuthenticationPurpose.SIGN_IN -> R.string.sign_in
        AuthenticationPurpose.REMOTE_ACCESS -> R.string.card_remote_access
    }

/** What stopped the preparation; a verified result shows nothing. */
private fun failureMessage(result: Pin1VerificationResult): Int? =
    when (result) {
        Pin1VerificationResult.VERIFIED -> null
        Pin1VerificationResult.CARD_UNAVAILABLE -> R.string.card_not_found
        Pin1VerificationResult.TRANSPORT_ERROR -> R.string.card_contact_lost
        Pin1VerificationResult.PACE_REJECTED -> R.string.wrong_can
        Pin1VerificationResult.INVALID_PIN -> R.string.pin_invalid
        Pin1VerificationResult.WRONG_PIN -> R.string.wrong_pin
        Pin1VerificationResult.PIN_LOCKED -> R.string.pin_locked
        Pin1VerificationResult.SAFETY_REFUSED -> R.string.refuse_low_attempts_pin
        Pin1VerificationResult.VERIFICATION_REJECTED -> R.string.pin_refused
        Pin1VerificationResult.BRIDGE_ERROR -> R.string.card_read_failed
    }

/**
 * Where the card is, as the reader sees it: found and being read, lost
 * again, or still awaited. A reader without NFC status is a USB slot.
 */
private fun cardMessage(
    state: AuthenticationPreparationState,
    nfcStatus: NfcReaderStatus?,
): Int =
    when {
        state == AuthenticationPreparationState.Verifying -> R.string.card_reading_hold_still
        nfcStatus == null -> R.string.hold_card
        nfcStatus in CARD_BEING_READ -> R.string.card_reading_hold_still
        nfcStatus == NfcReaderStatus.WRONG_CAN -> R.string.wrong_can
        else -> R.string.hold_card_against_back
    }

private val CARD_BEING_READ =
    setOf(
        NfcReaderStatus.CHECKING,
        NfcReaderStatus.CARD_RECOGNIZED,
        NfcReaderStatus.CONNECTING,
        NfcReaderStatus.CARD_READY,
    )

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun PreparationCredentialsDialog(
    preparation: AuthenticationPreparation,
    state: AuthenticationPreparationState.Credentials,
    title: Int,
) {
    val can = remember { TextFieldState(CanSessionStore.currentCan ?: "") }
    val pin = remember { TextFieldState() }
    DisposableEffect(can, pin) {
        onDispose {
            can.clearText()
            pin.clearText()
        }
    }
    val canReady = !state.needsCan || CanSubmission.isComplete(can.text)
    val pinReady = !state.needsPin || Pin1Submission.isComplete(pin.text)
    AlertDialog(
        onDismissRequest = preparation::cancel,
        modifier = Modifier.testTag("AuthenticationPreparationDialog"),
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                if (state.needsCan) {
                    SecureTextField(
                        state = can,
                        label = { Text(stringResource(R.string.can)) },
                        inputTransformation = CanInputTransformation,
                        textObfuscationMode = TextObfuscationMode.Visible,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth().testTag("AuthenticationPreparationCan"),
                    )
                }
                if (state.needsPin) {
                    SecureTextField(
                        state = pin,
                        label = { Text(stringResource(R.string.pin1)) },
                        inputTransformation = Pin1InputTransformation,
                        textObfuscationMode = TextObfuscationMode.Hidden,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth().testTag("AuthenticationPreparationPin1"),
                    )
                }
            }
        },
        confirmButton = {
            Button(
                enabled = canReady && pinReady,
                modifier = Modifier.testTag("AuthenticationPreparationSubmit"),
                onClick = {
                    val submittedCan = if (state.needsCan) CanSubmission.from(can.text) else null
                    val submittedPin = if (state.needsPin) Pin1Submission.from(pin.text) else null
                    can.clearText()
                    pin.clearText()
                    preparation.submit(submittedCan, submittedPin)
                },
            ) { Text(stringResource(R.string.unlock)) }
        },
        dismissButton = { TextButton(onClick = preparation::cancel) { Text(stringResource(R.string.cancel)) } },
    )
}
