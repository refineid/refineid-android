package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.rapp.LOCAL_NETWORK_CLOSED_REASON
import fi.refineid.android.rapp.RappDisplayText
import fi.refineid.android.rapp.RappPairingSearch
import fi.refineid.android.rapp.RemoteCardModel

/**
 * Pairs this computer with its phone (RAPP v26.11.2 section 4.7): the
 * holder's remote-use switch, off until turned on, and the pairing code
 * entry, offered while remote use is on and no remote card is presented.
 * The entry takes each complete code to the search; a failed search says
 * how it ended, with a retry.
 *
 * [onToggleRemoteUse] moves the switch, asking for the local network
 * first when turning on without it; [onRequestLocalNetwork] asks again
 * from a failure for it. The phone that forgot this computer is named
 * until the next pairing or the switch.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun RappRequesterPairingScreen(
    remoteCardModel: RemoteCardModel,
    onToggleRemoteUse: (Boolean) -> Unit,
    onRequestLocalNetwork: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val remoteUseEnabled by remoteCardModel.remoteUseEnabled.collectAsState()
    val searchPhase by remoteCardModel.searchPhase.collectAsState()
    val holderName by remoteCardModel.holderName.collectAsState()
    val phoneThatForgot by remoteCardModel.phoneThatForgot.collectAsState()
    var entry by remember { mutableStateOf("") }
    LaunchedEffect(searchPhase) {
        if (searchPhase is RemoteCardModel.SearchPhase.Entry) entry = ""
    }

    // The enclosing SubScreen scrolls, pads and carries the screen's tag;
    // a second vertical scroll inside it would be measured unbounded.
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        RemoteUseSwitchCard(
            checked = remoteUseEnabled,
            onCheckedChange = onToggleRemoteUse,
        )
        if (!remoteUseEnabled) return@Column
        when (val phase = searchPhase) {
            RemoteCardModel.SearchPhase.Entry -> {
                // The code entry is shown exactly while no remote card is
                // presented; the card itself shows on the home screen.
                if (holderName == null) {
                    phoneThatForgot?.let { phone ->
                        Text(
                            text = stringResource(R.string.phone_forgot_computer, RappDisplayText.inert(phone)),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    PairingCodeField(
                        value = entry,
                        onValueChange = { entry = it },
                        onComplete = remoteCardModel::submitPairingCode,
                        enabled = true,
                    )
                }
            }

            RemoteCardModel.SearchPhase.Searching -> {
                PairingCodeField(
                    value = entry,
                    onValueChange = {},
                    onComplete = {},
                    enabled = false,
                )
                CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
            }

            is RemoteCardModel.SearchPhase.Failed -> {
                FailedPhaseView(
                    reason = searchFailureReason(phase.outcome),
                    onRetry = {
                        if (phase.outcome == RappPairingSearch.Outcome.LocalNetworkClosed) {
                            onRequestLocalNetwork()
                        } else {
                            remoteCardModel.dismissFailure()
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun searchFailureReason(outcome: RappPairingSearch.Outcome): String =
    when (outcome) {
        RappPairingSearch.Outcome.NotAccepted -> stringResource(R.string.pairing_code_not_accepted)
        RappPairingSearch.Outcome.NoneFound -> stringResource(R.string.no_phone_in_pairing_mode)
        RappPairingSearch.Outcome.Unreachable -> stringResource(R.string.phone_unreachable)
        RappPairingSearch.Outcome.CeremonyEnded -> stringResource(R.string.pairing_ended_incomplete)
        RappPairingSearch.Outcome.LocalNetworkClosed -> LOCAL_NETWORK_CLOSED_REASON
        is RappPairingSearch.Outcome.Paired -> ""
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun RemoteUseSwitchCard(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val statusText = stringResource(if (checked) R.string.on else R.string.off)
    OutlinedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.outlinedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.card_remote_access),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = statusText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                modifier =
                    Modifier
                        .testTag(UiAutomationIds.REQUESTER_REMOTE_USE_SWITCH)
                        .semantics { stateDescription = statusText },
            )
        }
    }
}
