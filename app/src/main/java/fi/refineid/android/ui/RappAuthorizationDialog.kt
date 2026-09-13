@file:Suppress("MagicNumber", "MaxLineLength")

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import fi.refineid.android.R
import fi.refineid.android.rapp.RappAuthAction
import fi.refineid.android.rapp.RappAuthRequest

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappAuthorizationDialog(request: RappAuthRequest) {
    var pin by remember { mutableStateOf("") }
    val isPinValid = pin.length in 4..8

    Dialog(
        onDismissRequest = { request.onDenied() },
        properties =
            DialogProperties(
                dismissOnBackPress = request.action == RappAuthAction.BROWSER_AUTH,
                dismissOnClickOutside = false,
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
                    text =
                        when (request.action) {
                            RappAuthAction.BROWSER_AUTH -> {
                                "${request.requester} needs your identity card.\n" +
                                    "Enter PIN 1 and hold the card to the phone."
                            }

                            RappAuthAction.DOCUMENT_SIGN -> {
                                "${request.requester} is requesting a document signature.\n" +
                                    "Enter PIN 2 and hold your ID card to the phone to sign."
                            }
                        },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                OutlinedTextField(
                    value = pin,
                    onValueChange = { typed -> pin = typed.filter { it in '0'..'9' }.take(8) },
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
                        onClick = { request.onDenied() },
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
                        onClick = { request.onApproved(pin) },
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

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappCardTapDialog(prompt: fi.refineid.android.rapp.RappCardTapPrompt) {
    Dialog(
        onDismissRequest = { prompt.onCancel() },
        properties = DialogProperties(dismissOnBackPress = true, dismissOnClickOutside = false),
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
                    text = stringResource(R.string.phone_needs_id_card),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                )

                Text(
                    text = stringResource(R.string.hold_card_against_back),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                )

                androidx.compose.material3.CircularProgressIndicator(
                    modifier = Modifier.padding(vertical = 8.dp),
                    strokeWidth = 3.dp,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    OutlinedButton(
                        onClick = { prompt.onCancel() },
                    ) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
}
