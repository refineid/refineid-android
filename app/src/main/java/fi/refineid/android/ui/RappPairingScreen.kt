package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fi.refineid.android.R
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.rapp.PairedPeer
import fi.refineid.android.rapp.PairingPhase
import fi.refineid.android.rapp.RappPairingCode
import fi.refineid.android.rapp.RappPairingModel
import kotlinx.coroutines.delay

private const val PAIRED_AUTO_DISMISS_DELAY_MS = 1500L
private val OFFERING_CODE_FONT_SIZE = 40.sp
private val OFFERING_CODE_LETTER_SPACING = 4.sp

private fun applyCredentialsAndConnect(
    canInput: String,
    pin1Input: String,
    pinCache: AuthenticationPinCache?,
    onConnectCard: (CanSubmission?, Pin1Submission?) -> Unit,
) {
    if (canInput.isNotBlank()) {
        CanSessionStore.remember(canInput)
    }
    val pin1Submission =
        if (Pin1Submission.isComplete(pin1Input)) {
            val pinBytes = pin1Input.toByteArray(Charsets.US_ASCII)
            pinCache?.recordVerified(pinBytes)
            Pin1Submission.from(pin1Input)
        } else if (pinCache?.hasPin == true) {
            pinCache.take()
        } else {
            null
        }
    val canSubmission =
        if (CanSubmission.isComplete(canInput)) {
            CanSubmission.from(canInput)
        } else {
            null
        }
    if (canSubmission != null || pin1Submission != null) {
        onConnectCard(canSubmission, pin1Submission)
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappPairingScreen(
    model: RappPairingModel,
    hasNfc: Boolean = true,
    pinCache: AuthenticationPinCache? = null,
    holderName: String? = null,
    onConnectCard: (CanSubmission?, Pin1Submission?) -> Unit = { _, _ -> },
    onBack: () -> Unit,
) {
    val phase = model.phase

    LaunchedEffect(!hasNfc) {
        if (!hasNfc && model.phase is PairingPhase.Idle && model.activeConnectedPeer == null) {
            model.createOffer()
        }
    }

    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        when (phase) {
            is PairingPhase.Idle, is PairingPhase.CodeEntry -> {
                if (model.pairedDevices.isNotEmpty()) {
                    PairedDevicesList(
                        peers = model.pairedDevices,
                        activePeer = model.activeConnectedPeer,
                        onDisconnect = { model.disconnectActivePeer() },
                        onRemove = { idHex -> model.removePair(idHex) },
                    )
                }
                val initialCan = remember { CanSessionStore.currentCan ?: "" }
                val initialPin1 = remember { pinCache?.peekPin() ?: "" }
                CodeEntryCard(
                    onConnectWithCode = { code, can, pin1 ->
                        applyCredentialsAndConnect(can, pin1, pinCache, onConnectCard)
                        model.connectWithCode(code)
                    },
                    onShowPairingCode = { can, pin1 ->
                        applyCredentialsAndConnect(can, pin1, pinCache, onConnectCard)
                        model.createOffer()
                    },
                    initialCan = initialCan,
                    initialPin1 = initialPin1,
                )
            }

            is PairingPhase.Offering -> {
                OfferingPhaseView(
                    code = phase.code,
                    holderName = holderName,
                    onEnterCode = { model.startCodeEntry() },
                    onCancel = {
                        model.reset()
                        onBack()
                    },
                )
            }

            is PairingPhase.Connecting -> {
                ConnectingPhaseView(
                    message = phase.message,
                    holderName = holderName,
                )
            }

            is PairingPhase.Paired -> {
                PairedPhaseView(
                    peer = phase.peer,
                    onBack = onBack,
                )
            }

            is PairingPhase.Failed -> {
                FailedPhaseView(
                    reason = phase.reason,
                    onRetry = { model.reset() },
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun PairedPeerRow(
    peer: PairedPeer,
    isConnected: Boolean,
    onDisconnect: () -> Unit,
    onRemove: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = peer.displayName,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                    )
                    Text(
                        text = peer.platform,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                IconButton(onClick = onRemove) {
                    Icon(
                        imageVector = Icons.Outlined.Delete,
                        contentDescription = stringResource(R.string.forget),
                        tint = MaterialTheme.colorScheme.error,
                    )
                }
            }
            if (isConnected) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.connected_status),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.SemiBold,
                    )
                    OutlinedButton(onClick = onDisconnect) {
                        Text(stringResource(R.string.disconnect))
                    }
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun PairedDevicesList(
    peers: List<PairedPeer>,
    activePeer: PairedPeer?,
    onDisconnect: () -> Unit,
    onRemove: (String) -> Unit,
) {
    Text(
        text = stringResource(R.string.paired_devices),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold,
    )
    for (peer in peers) {
        val isConnected = activePeer?.pairIdHex == peer.pairIdHex
        PairedPeerRow(
            peer = peer,
            isConnected = isConnected,
            onDisconnect = onDisconnect,
            onRemove = { onRemove(peer.pairIdHex) },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun CodeEntryCard(
    onConnectWithCode: (String, String, String) -> Unit,
    onShowPairingCode: (String, String) -> Unit,
    initialCan: String,
    initialPin1: String,
) {
    var codeInput by remember { mutableStateOf("") }
    var canInput by remember { mutableStateOf(initialCan) }
    var pin1Input by remember { mutableStateOf(initialPin1) }
    val canValid = CanSubmission.isComplete(canInput)
    val codeValid = RappPairingCode.isValid(codeInput)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            OutlinedTextField(
                value = codeInput,
                onValueChange = { codeInput = RappPairingCode.normalize(it) },
                label = { Text(stringResource(R.string.pairing_code)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                textStyle =
                    MaterialTheme.typography.bodyLarge.copy(
                        textAlign = TextAlign.Center,
                        fontFamily = FontFamily.Monospace,
                    ),
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = canInput,
                onValueChange = { canInput = it.filter { c -> c in '0'..'9' }.take(CanSubmission.CAN_DIGITS) },
                label = { Text(stringResource(R.string.can)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                textStyle =
                    MaterialTheme.typography.bodyLarge.copy(
                        textAlign = TextAlign.Center,
                        fontFamily = FontFamily.Monospace,
                    ),
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = pin1Input,
                onValueChange = { input ->
                    val digits = input.filter { it in '0'..'9' }
                    if (Pin1Submission.acceptsEntry(digits)) {
                        pin1Input = digits
                    }
                },
                label = { Text(stringResource(R.string.pin1_optional)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                textStyle =
                    MaterialTheme.typography.bodyLarge.copy(
                        textAlign = TextAlign.Center,
                        fontFamily = FontFamily.Monospace,
                    ),
                modifier = Modifier.fillMaxWidth(),
            )

            Button(
                onClick = { onConnectWithCode(codeInput, canInput, pin1Input) },
                enabled = codeValid && canValid,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.pair_computer))
            }

            OutlinedButton(
                onClick = { onShowPairingCode(canInput, pin1Input) },
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("showPairingCodeButton"),
            ) {
                Text(stringResource(R.string.show_pairing_code))
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun OfferingPhaseView(
    code: String,
    holderName: String?,
    onEnterCode: () -> Unit,
    onCancel: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = RappPairingCode.formatted(code),
                style = MaterialTheme.typography.headlineLarge,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = OFFERING_CODE_FONT_SIZE,
                letterSpacing = OFFERING_CODE_LETTER_SPACING,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.testTag("offeringCodeText"),
            )
            if (holderName != null) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Check,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = holderName,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                    )
                }
            } else {
                Text(
                    text = stringResource(R.string.hold_card_to_phone),
                    style = MaterialTheme.typography.bodySmall,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(
                onClick = onEnterCode,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("enterPairingCodeButton"),
            ) {
                Text(stringResource(R.string.enter_pairing_code))
            }
            Button(
                onClick = onCancel,
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.cancel))
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ConnectingPhaseView(
    message: String,
    holderName: String?,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator()
            Text(
                text = message,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
            )
            if (holderName == null) {
                Text(
                    text = stringResource(R.string.hold_card_to_phone),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                Text(
                    text = holderName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun PairedPhaseView(
    peer: PairedPeer,
    onBack: () -> Unit,
) {
    LaunchedEffect(Unit) {
        delay(PAIRED_AUTO_DISMISS_DELAY_MS)
        onBack()
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        ) {
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Check,
                    contentDescription = stringResource(R.string.peer_connected, peer.displayName),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(44.dp),
                )
                Text(
                    text = stringResource(R.string.peer_connected, peer.displayName),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                )
            }
        }
        Button(
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.ready))
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun FailedPhaseView(
    reason: String,
    onRetry: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Icon(
                imageVector = Icons.Outlined.Clear,
                contentDescription = "Failed",
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(48.dp),
            )
            Text(
                text = stringResource(R.string.pairing_failed),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = reason,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Button(onClick = onRetry) {
                Text(stringResource(R.string.retry))
            }
        }
    }
}
