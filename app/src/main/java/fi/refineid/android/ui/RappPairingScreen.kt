package fi.refineid.android.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Clear
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import fi.refineid.android.R
import fi.refineid.android.rapp.PairedPeer
import fi.refineid.android.rapp.PairingPhase
import fi.refineid.android.rapp.RappCustodianService
import fi.refineid.android.rapp.RappPairingCode
import fi.refineid.android.rapp.RappPairingModel

private val OFFERING_CODE_FONT_SIZE = 36.sp
private val OFFERING_CODE_LETTER_SPACING = 2.sp

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappPairingScreen(
    model: RappPairingModel,
    modifier: Modifier = Modifier,
    onEnableRemoteAccess: () -> Unit = { model.setRemoteAccessEnabled(true) },
) {
    val context = LocalContext.current
    val phase = model.phase

    var notificationsAllowed by remember { mutableStateOf(rappNotificationsAllowed(context)) }
    val refreshNotifications = {
        notificationsAllowed = rappNotificationsAllowed(context)
        if (notificationsAllowed) RappCustodianService.refreshNotification(context)
    }
    val notificationPermissionLauncher =
        rememberLauncherForActivityResult(
            contract = ActivityResultContracts.RequestPermission(),
        ) { _ -> refreshNotifications() }
    val settingsLauncher =
        rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult(),
        ) { _ -> refreshNotifications() }

    // A pairing offer needs neither the card nor a PIN: the page offers its
    // code whenever Remote Access is on and no computer is connected.
    LaunchedEffect(model.isRemoteAccessEnabled) {
        if (model.isRemoteAccessEnabled && phase is PairingPhase.Idle &&
            model.activeConnectedPeer == null
        ) {
            model.createOffer()
        }
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SUBSCREEN_ITEM_SPACING),
    ) {
        CardRemoteAccessSwitchCard(
            enabled = model.isRemoteAccessEnabled,
            onCheckedChange = { isChecked ->
                if (isChecked) {
                    if (ContextCompat.checkSelfPermission(
                            context,
                            Manifest.permission.POST_NOTIFICATIONS,
                        ) != PackageManager.PERMISSION_GRANTED
                    ) {
                        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                } else {
                    model.reset()
                }
                if (isChecked) onEnableRemoteAccess() else model.setRemoteAccessEnabled(false)
            },
        )

        if (model.isRemoteAccessEnabled && !notificationsAllowed) {
            NavigationGroup {
                NavigationRow(
                    icon = Icons.Outlined.Notifications,
                    label = stringResource(R.string.allow_notifications),
                    tag = UiAutomationIds.ALLOW_NOTIFICATIONS_ROW,
                    onClick = {
                        settingsLauncher.launch(
                            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
                        )
                    },
                )
            }
        }

        if (model.isRemoteAccessEnabled) {
            when (phase) {
                is PairingPhase.Offering -> {
                    OfferingPhaseView(code = phase.code)
                }

                is PairingPhase.Connecting -> {
                    ConnectingPhaseView(message = phase.message)
                }

                is PairingPhase.Failed -> {
                    FailedPhaseView(reason = phase.reason, onRetry = { model.createOffer() })
                }

                is PairingPhase.Idle -> {
                }
            }
        }

        if (model.pairedDevices.isNotEmpty()) {
            Section(stringResource(R.string.paired_devices)) {
                NavigationGroup {
                    model.pairedDevices.forEachIndexed { index, peer ->
                        if (index > 0) {
                            HorizontalDivider(modifier = Modifier.padding(start = GROUP_DIVIDER_INSET))
                        }
                        PairedPeerRow(
                            peer = peer,
                            onRemove = { model.removePair(peer.pairIdHex) },
                        )
                    }
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun CardRemoteAccessSwitchCard(
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.CARD_REMOTE_ACCESS_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = ROW_VERTICAL_PADDING),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_satellite_alt),
                    contentDescription = null,
                    tint =
                        if (enabled) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    modifier = Modifier.size(ROW_ICON_SIZE),
                )
                Text(
                    text = stringResource(R.string.card_remote_access),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onCheckedChange,
                modifier = Modifier.testTag(UiAutomationIds.CARD_REMOTE_ACCESS_SWITCH),
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun PairedPeerRow(
    peer: PairedPeer,
    onRemove: () -> Unit,
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .padding(horizontal = ROW_HORIZONTAL_PADDING, vertical = PAIRED_PEER_ROW_VERTICAL_PADDING),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(ROW_ITEM_SPACING),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = peer.displayName,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface,
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
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun OfferingPhaseView(code: String) {
    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag("pairingCodeDisplay"),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
    ) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
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
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun ConnectingPhaseView(message: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
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
private fun FailedPhaseView(
    reason: String,
    onRetry: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = GROUP_ELEVATION),
        shape = RoundedCornerShape(GROUP_CORNER_RADIUS),
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

private fun rappNotificationsAllowed(context: Context): Boolean =
    NotificationManagerCompat.from(context).areNotificationsEnabled()
