@file:Suppress("MagicNumber", "MaxLineLength")

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import fi.refineid.android.R
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.nfc.NfcCardWait
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.rapp.RappAuthAction
import fi.refineid.android.rapp.RappAuthRequest
import fi.refineid.android.rapp.rappRequestText

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappAuthorizationDialog(request: RappAuthRequest) {
    var pin by remember(request.requestId) { mutableStateOf("") }
    val isPinValid =
        when (request) {
            is RappAuthRequest.BrowserAuth -> Pin1Submission.isComplete(pin)
            is RappAuthRequest.DocumentSign -> Pin2Submission.isComplete(pin)
        }

    Dialog(
        onDismissRequest = {
            pin = ""
            request.onDenied()
        },
        properties =
            DialogProperties(
                dismissOnBackPress = request.action == RappAuthAction.BROWSER_AUTH,
                dismissOnClickOutside = false,
                securePolicy = SecureFlagPolicy.SecureOn,
            ),
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    text =
                        when (request.action) {
                            RappAuthAction.BROWSER_AUTH -> "Enter PIN 1"
                            RappAuthAction.DOCUMENT_SIGN -> "Sign Document"
                        },
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )

                Text(
                    text = rappRequestText(LocalResources.current, request),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (request is RappAuthRequest.DocumentSign) {
                    RappDocumentNames(request.documentNames)
                }

                OutlinedTextField(
                    value = pin,
                    onValueChange = { typed ->
                        val digits = typed.filter { it in '0'..'9' }
                        val accepts =
                            when (request) {
                                is RappAuthRequest.BrowserAuth -> Pin1Submission.acceptsEntry(digits)
                                is RappAuthRequest.DocumentSign -> Pin2Submission.acceptsEntry(digits)
                            }
                        if (accepts) {
                            pin = digits
                        }
                    },
                    label = {
                        Text(
                            when (request.action) {
                                RappAuthAction.BROWSER_AUTH -> "PIN 1"
                                RappAuthAction.DOCUMENT_SIGN -> "PIN 2"
                            },
                        )
                    },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    OutlinedButton(
                        onClick = {
                            pin = ""
                            request.onDenied()
                        },
                        modifier = Modifier.padding(end = 8.dp),
                    ) {
                        // Browser auth: Cancel (no conceptual denial, just close).
                        // Document sign: Deny (explicit refusal to sign).
                        Text(
                            when (request.action) {
                                RappAuthAction.BROWSER_AUTH -> "Cancel"
                                RappAuthAction.DOCUMENT_SIGN -> "Deny"
                            },
                        )
                    }
                    Button(
                        onClick = {
                            val currentPin = pin
                            pin = ""
                            when (request) {
                                is RappAuthRequest.BrowserAuth -> {
                                    request.onApproved(Pin1Submission.from(currentPin))
                                }

                                is RappAuthRequest.DocumentSign -> {
                                    request.onApproved(Pin2Submission.from(currentPin))
                                }
                            }
                        },
                        enabled = isPinValid,
                    ) {
                        Text(
                            when (request.action) {
                                RappAuthAction.BROWSER_AUTH -> "Continue"
                                RappAuthAction.DOCUMENT_SIGN -> "Approve & Sign"
                            },
                        )
                    }
                }
            }
        }
    }
}

/** The documents an approval signs, in signing order. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun RappDocumentNames(names: List<String>) {
    if (names.isEmpty()) return
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .heightIn(max = 200.dp)
                .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        names.forEach { name ->
            Text(
                text = name,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappCardTapDialog(
    prompt: fi.refineid.android.rapp.RappCardTapPrompt,
    usbReaderPresent: Boolean,
    nfcStatus: NfcReaderStatus = NfcReaderStatus.WAITING_FOR_CARD,
    accessNumberKnown: Boolean = true,
    onSubmitAccessNumber: (CanSubmission) -> Unit = { it.close() },
) {
    var wasReading by remember(prompt.requestId) { mutableStateOf(false) }
    val reading = nfcStatus == NfcReaderStatus.CHECKING || nfcStatus == NfcReaderStatus.CONNECTING
    if (reading) wasReading = true
    val needsAccessNumber = !usbReaderPresent && NfcCardWait.needsAccessNumber(nfcStatus, accessNumberKnown)
    val message =
        when {
            usbReaderPresent -> R.string.insert_card_into_reader
            reading -> R.string.card_reading_hold_still
            nfcStatus == NfcReaderStatus.WRONG_CAN -> R.string.wrong_can
            wasReading && nfcStatus == NfcReaderStatus.WAITING_FOR_CARD -> R.string.card_contact_lost
            nfcStatus == NfcReaderStatus.CARD_RECOGNIZED && needsAccessNumber -> R.string.card_found_enter_can
            else -> R.string.hold_card_against_back
        }
    val accessNumber = remember(prompt.requestId) { TextFieldState(CanSessionStore.currentCan ?: "") }
    DisposableEffect(accessNumber) {
        onDispose { accessNumber.clearText() }
    }
    Dialog(
        onDismissRequest = { prompt.onCancel() },
        properties =
            DialogProperties(
                dismissOnBackPress = true,
                dismissOnClickOutside = false,
                securePolicy = SecureFlagPolicy.SecureOn,
            ),
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    text = stringResource(message),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                    modifier =
                        Modifier
                            .testTag("RappCardTapMessage")
                            .semantics { liveRegion = LiveRegionMode.Polite },
                )

                if (needsAccessNumber) {
                    SecureTextField(
                        state = accessNumber,
                        label = { Text(stringResource(R.string.can)) },
                        inputTransformation = CanInputTransformation,
                        textObfuscationMode = TextObfuscationMode.Visible,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth().testTag("RappCardTapCan"),
                    )
                } else {
                    androidx.compose.material3.CircularProgressIndicator(
                        modifier = Modifier.padding(vertical = 8.dp),
                        strokeWidth = 3.dp,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    OutlinedButton(
                        onClick = { prompt.onCancel() },
                    ) {
                        Text(stringResource(R.string.cancel))
                    }
                    if (needsAccessNumber) {
                        Button(
                            enabled = CanSubmission.isComplete(accessNumber.text),
                            modifier = Modifier.testTag("RappCardTapCanSubmit"),
                            onClick = {
                                val submitted = CanSubmission.from(accessNumber.text)
                                accessNumber.clearText()
                                onSubmitAccessNumber(submitted)
                            },
                        ) {
                            Text(stringResource(R.string.unlock))
                        }
                    }
                }
            }
        }
    }
}
