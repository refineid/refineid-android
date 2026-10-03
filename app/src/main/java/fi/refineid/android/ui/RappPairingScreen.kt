package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import fi.refineid.android.R
import fi.refineid.android.rapp.PairedPeer
import fi.refineid.android.rapp.PairingPhase
import fi.refineid.android.rapp.RappPairingCode
import fi.refineid.android.rapp.RappPairingModel
import kotlinx.coroutines.delay

private const val PAIRED_AUTO_DISMISS_DELAY_MS = 1500L
private val OFFERING_CODE_FONT_SIZE = 36.sp
private val OFFERING_CODE_LETTER_SPACING = 2.sp

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappPairingScreen(
    model: RappPairingModel,
    onBack: () -> Unit,
) {
    val phase = model.phase

    LaunchedEffect(model.pairedDevices.isEmpty()) {
        if (model.pairedDevices.isEmpty() && model.phase is PairingPhase.Idle && model.activeConnectedPeer == null) {
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
            is PairingPhase.Idle -> {
                if (model.pairedDevices.isNotEmpty()) {
                    PairedDevicesList(
                        peers = model.pairedDevices,
                        activePeer = model.activeConnectedPeer,
                        onDisconnect = { model.disconnectActivePeer() },
                        onRemove = { idHex -> model.removePair(idHex) },
                    )
                }
                Button(
                    onClick = { model.createOffer() },
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag("pairNewComputerButton"),
                ) {
                    Text(stringResource(R.string.pair_new_computer))
                }
            }

            is PairingPhase.Offering -> {
                OfferingPhaseView(
                    code = phase.code,
                    onRegenerateCode = { model.createOffer() },
                    onCancel = {
                        model.reset()
                        onBack()
                    },
                )
            }

            is PairingPhase.Connecting -> {
                ConnectingPhaseView(
                    message = phase.message,
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
private fun OfferingPhaseView(
    code: String,
    onRegenerateCode: () -> Unit,
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
            Text(
                text = stringResource(R.string.enter_code_on_computer),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(
                onClick = onRegenerateCode,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("regenerateCodeButton"),
            ) {
                Text(stringResource(R.string.regenerate_code))
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
private fun ConnectingPhaseView(message: String) {
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
