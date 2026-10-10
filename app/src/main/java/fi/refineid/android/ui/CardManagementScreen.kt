@file:Suppress(
    "CyclomaticComplexMethod",
    "FunctionName",
    "LongMethod",
    "LongParameterList",
    "MagicNumber",
    "MaxLineLength",
    "TooManyFunctions",
    "UnusedParameter",
    "ktlint:standard:function-naming",
)

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State

private enum class ManagementTask {
    CHANGE_PIN1,
    CHANGE_PIN2,
    RESET_PIN1,
    RESET_PIN2,
    ACTIVATE_CARD,
}

private data class OutcomeNotice(
    val resId: Int,
    val arg: String? = null,
)

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun CardManagementScreen(
    cardManagementService: CardManagementService?,
    onConnectNfc: ((CanSubmission) -> Unit)? = null,
    isCardReady: Boolean = false,
    pinCache: fi.refineid.android.core.AuthenticationPinCache? = null,
    onPin1Changed: (() -> Unit)? = null,
    activationRequired: Boolean = false,
    onActivationSucceeded: (() -> Unit)? = null,
    onNeedsActivationChanged: ((Boolean) -> Unit)? = null,
) {
    var health by remember { mutableStateOf<CredentialHealth?>(null) }
    var isProbing by remember { mutableStateOf(false) }
    var isOperating by remember { mutableStateOf(false) }
    var selectedTask by
        remember(activationRequired) {
            mutableStateOf(if (activationRequired) ManagementTask.ACTIVATE_CARD else ManagementTask.CHANGE_PIN1)
        }
    var outcomeNotice by remember { mutableStateOf<OutcomeNotice?>(null) }
    var outcomeIsError by remember { mutableStateOf(false) }
    var showConfirmDialog by remember { mutableStateOf(false) }

    val currentPinState = remember { TextFieldState() }
    val newPinState = remember { TextFieldState() }
    val newPinConfirmState = remember { TextFieldState() }
    val newPin2State = remember { TextFieldState() }
    val newPin2ConfirmState = remember { TextFieldState() }
    val pukState = remember { TextFieldState() }
    val activationCodeState = remember { TextFieldState() }
    val canState =
        remember {
            TextFieldState(fi.refineid.android.core.CanSessionStore.currentCan ?: "")
        }

    fun clearEntries() {
        currentPinState.clearText()
        newPinState.clearText()
        newPinConfirmState.clearText()
        newPin2State.clearText()
        newPin2ConfirmState.clearText()
        pukState.clearText()
        activationCodeState.clearText()
    }

    DisposableEffect(Unit) {
        onDispose {
            clearEntries()
        }
    }

    fun probe() {
        if (cardManagementService == null) return
        isProbing = true
        cardManagementService.probeCredentialHealth { result ->
            isProbing = false
            when (result) {
                is CardManagementResult.Success -> {
                    health = result.value
                    val needsActivation = result.value.activationNeeds.any
                    onNeedsActivationChanged?.invoke(needsActivation)
                    if (needsActivation) {
                        selectedTask = ManagementTask.ACTIVATE_CARD
                    } else if (result.value.pin1State is NativePin1State.Locked) {
                        selectedTask = ManagementTask.RESET_PIN1
                    } else if (result.value.pin2State is NativePin2State.Locked) {
                        selectedTask = ManagementTask.RESET_PIN2
                    } else if (selectedTask == ManagementTask.ACTIVATE_CARD) {
                        selectedTask = ManagementTask.CHANGE_PIN1
                    }
                }

                is CardManagementResult.Failure -> {
                    outcomeNotice =
                        OutcomeNotice(
                            when (result.kind) {
                                CardManagementFailure.CARD_UNAVAILABLE -> R.string.unavailable
                                else -> R.string.error
                            },
                        )
                    outcomeIsError = true
                }
            }
        }
    }

    LaunchedEffect(isCardReady) {
        if (isCardReady) {
            probe()
        }
    }

    val isActivationFlow =
        (activationRequired && (health == null || health?.activationNeeds?.any == true)) ||
            (health?.activationNeeds?.any == true) ||
            selectedTask == ManagementTask.ACTIVATE_CARD

    val needsPin1 = health?.activationNeeds?.pin1 ?: true
    val needsPin2 = health?.activationNeeds?.pin2 ?: true

    val currentPin = currentPinState.text.toString()
    val newPin = newPinState.text.toString()
    val newPinConfirm = newPinConfirmState.text.toString()
    val newPin2 = newPin2State.text.toString()
    val newPin2Confirm = newPin2ConfirmState.text.toString()
    val puk = pukState.text.toString()
    val activationCode = activationCodeState.text.toString()

    val pin1Bounds = 4..12
    val pin2Bounds = 6..12
    val pukBounds = 8..8
    val activationCodeBounds =
        when (health?.activationScheme) {
            CardManagementScheme.PRESET_PIN -> 7..7
            CardManagementScheme.PUK -> 8..8
            else -> 7..8
        }

    val targetBounds =
        if (selectedTask == ManagementTask.CHANGE_PIN2 || selectedTask == ManagementTask.RESET_PIN2) {
            pin2Bounds
        } else {
            pin1Bounds
        }

    val currentPinValid = targetBounds.contains(currentPin.length) && currentPin.all { it in '0'..'9' }
    val newPinValid = targetBounds.contains(newPin.length) && newPin.all { it in '0'..'9' }
    val confirmationValid = newPinValid && newPin == newPinConfirm
    val pinsDiffer = currentPin.isNotEmpty() && newPin.isNotEmpty() && currentPin != newPin
    val pukValid = pukBounds.contains(puk.length) && puk.all { it in '0'..'9' }

    val activationCodeValid =
        activationCodeBounds.contains(activationCode.length) && activationCode.all { it in '0'..'9' }

    val newPin1Valid = pin1Bounds.contains(newPin.length) && newPin.all { it in '0'..'9' }
    val newPin1ConfirmValid = newPin1Valid && newPin == newPinConfirm

    val newPin2Valid = pin2Bounds.contains(newPin2.length) && newPin2.all { it in '0'..'9' }
    val newPin2ConfirmValid = newPin2Valid && newPin2 == newPin2Confirm

    val pin1Attempts = health?.pin1State?.let { getAttempts(it) }
    val pin2Attempts = health?.pin2State?.let { getAttempts(it) }
    val pukAttempts = health?.pukState?.let { getAttempts(it) }

    val pukLocked = isLocked(health?.pukState)
    val pukLow = isLowAttempts(pukAttempts)
    val pukWarning = isWarningAttempts(pukAttempts)

    val pin1Locked = isLocked(health?.pin1State)
    val pin1Low = isLowAttempts(pin1Attempts)
    val pin1Warning = isWarningAttempts(pin1Attempts)

    val pin2Locked = isLocked(health?.pin2State)
    val pin2Low = isLowAttempts(pin2Attempts)
    val pin2Warning = isWarningAttempts(pin2Attempts)

    val isRefusedByPolicy =
        pukLocked ||
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1 -> pin1Locked || pin1Low
                ManagementTask.CHANGE_PIN2 -> pin2Locked || pin2Low
                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> pukLow
                ManagementTask.ACTIVATE_CARD -> false
            }

    val (guidanceMessage, guidanceTone) =
        when {
            pukLocked -> {
                stringResource(R.string.unrecoverable_card) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Locked -> {
                stringResource(R.string.recovery_guidance_pin1) to BannerTone.INFO
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Low -> {
                stringResource(R.string.refuse_low_attempts_pin) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN1 && pin1Warning -> {
                stringResource(R.string.spent_attempts_notice, "PIN 1", pin1Attempts ?: 0, 5) to BannerTone.WARNING
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Locked -> {
                stringResource(R.string.recovery_guidance_pin2) to BannerTone.INFO
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Low -> {
                stringResource(R.string.refuse_low_attempts_pin) to BannerTone.CRITICAL
            }

            selectedTask == ManagementTask.CHANGE_PIN2 && pin2Warning -> {
                stringResource(R.string.spent_attempts_notice, "PIN 2", pin2Attempts ?: 0, 5) to BannerTone.WARNING
            }

            (selectedTask == ManagementTask.RESET_PIN1 || selectedTask == ManagementTask.RESET_PIN2) && pukLow -> {
                stringResource(R.string.refuse_low_attempts_puk) to BannerTone.CRITICAL
            }

            (selectedTask == ManagementTask.RESET_PIN1 || selectedTask == ManagementTask.RESET_PIN2) && pukWarning -> {
                stringResource(R.string.spent_attempts_notice, "PUK", pukAttempts ?: 0, 5) to BannerTone.WARNING
            }

            selectedTask == ManagementTask.RESET_PIN1 && pin1Locked -> {
                stringResource(R.string.recovery_guidance_pin1) to BannerTone.INFO
            }

            selectedTask == ManagementTask.RESET_PIN2 && pin2Locked -> {
                stringResource(R.string.recovery_guidance_pin2) to BannerTone.INFO
            }

            else -> {
                null to null
            }
        }

    val canExecute =
        !isRefusedByPolicy &&
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                    currentPinValid && newPinValid && confirmationValid &&
                        pinsDiffer
                }

                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                    pukValid && newPinValid && confirmationValid
                }

                ManagementTask.ACTIVATE_CARD -> {
                    activationCodeValid &&
                        (!needsPin1 || newPin1ConfirmValid) &&
                        (!needsPin2 || newPin2ConfirmValid) &&
                        (needsPin1 || needsPin2)
                }
            }

    fun executeOperation() {
        if (!canExecute || cardManagementService == null) return
        isOperating = true
        outcomeNotice = null

        when (selectedTask) {
            ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                val curBytes = currentPin.toByteArray(Charsets.US_ASCII)
                val newBytes = newPin.toByteArray(Charsets.US_ASCII)
                val isPin1 = selectedTask == ManagementTask.CHANGE_PIN1
                val pinName = if (isPin1) "PIN 1" else "PIN 2"
                if (isPin1) {
                    pinCache?.clear()
                    onPin1Changed?.invoke()
                }
                val callback: (CardManagementResult<ManageOutcome>) -> Unit = { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            if (result.value is ManageOutcome.Succeeded) {
                                outcomeNotice = OutcomeNotice(R.string.pin_changed_success, pinName)
                                outcomeIsError = false
                                if (isPin1) {
                                    pinCache?.clear()
                                    onPin1Changed?.invoke()
                                }
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                            }
                            probe()
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
                if (isPin1) {
                    cardManagementService.changePin1(curBytes, newBytes, callback)
                } else {
                    cardManagementService.changePin2(curBytes, newBytes, callback)
                }
            }

            ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                val pukBytes = puk.toByteArray(Charsets.US_ASCII)
                val newBytes = newPin.toByteArray(Charsets.US_ASCII)
                val isPin1 = selectedTask == ManagementTask.RESET_PIN1
                val pinName = if (isPin1) "PIN 1" else "PIN 2"
                if (isPin1) {
                    pinCache?.clear()
                    onPin1Changed?.invoke()
                }
                val callback: (CardManagementResult<ManageOutcome>) -> Unit = { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            if (result.value is ManageOutcome.Succeeded) {
                                outcomeNotice = OutcomeNotice(R.string.pin_reset_success, pinName)
                                outcomeIsError = false
                                if (isPin1) {
                                    pinCache?.clear()
                                    onPin1Changed?.invoke()
                                }
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                            }
                            probe()
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
                if (isPin1) {
                    cardManagementService.unblockPin1(pukBytes, newBytes, callback)
                } else {
                    cardManagementService.unblockPin2(pukBytes, newBytes, callback)
                }
            }

            ManagementTask.ACTIVATE_CARD -> {
                val codeBytes = activationCode.toByteArray(Charsets.US_ASCII)
                val new1Bytes =
                    if (needsPin1) {
                        newPin.toByteArray(Charsets.US_ASCII)
                    } else {
                        null
                    }
                val new2Bytes =
                    if (needsPin2) {
                        newPin2.toByteArray(Charsets.US_ASCII)
                    } else {
                        null
                    }
                val scheme = health?.activationScheme ?: CardManagementScheme.PRESET_PIN
                pinCache?.clear()
                onPin1Changed?.invoke()
                cardManagementService.activateCard(scheme, codeBytes, new1Bytes, new2Bytes) { result ->
                    isOperating = false
                    clearEntries()
                    when (result) {
                        is CardManagementResult.Success -> {
                            val actReport = result.value
                            val pin1Ok = new1Bytes == null || actReport.pin1Outcome is ManageOutcome.Succeeded
                            val pin2Ok = new2Bytes == null || actReport.pin2Outcome is ManageOutcome.Succeeded
                            if (pin1Ok && pin2Ok && (new1Bytes != null || new2Bytes != null)) {
                                outcomeNotice = OutcomeNotice(R.string.card_activated_success)
                                outcomeIsError = false
                                pinCache?.clear()
                                onPin1Changed?.invoke()
                                onActivationSucceeded?.invoke()
                                probe()
                            } else {
                                outcomeNotice = OutcomeNotice(R.string.error)
                                outcomeIsError = true
                                probe()
                            }
                        }

                        is CardManagementResult.Failure -> {
                            outcomeNotice = OutcomeNotice(R.string.error)
                            outcomeIsError = true
                        }
                    }
                }
            }
        }
    }

    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .imePadding()
                .testTag("CardManagementScreen"),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // NFC Connection section if card is not ready
        if (!isCardReady && onConnectNfc != null) {
            Section(stringResource(R.string.nfc)) {
                NavigationGroup {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        val canReady = CanSubmission.isComplete(canState.text)
                        SecureTextField(
                            state = canState,
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .testTag("managementCardAccessNumber"),
                            label = { Text(stringResource(R.string.can)) },
                            inputTransformation = CanInputTransformation,
                            textObfuscationMode = TextObfuscationMode.Visible,
                            keyboardOptions =
                                KeyboardOptions(
                                    autoCorrectEnabled = false,
                                    keyboardType = KeyboardType.NumberPassword,
                                    imeAction = ImeAction.Done,
                                ),
                        )
                        Button(
                            onClick = {
                                if (canReady) {
                                    fi.refineid.android.core.CanSessionStore
                                        .remember(canState.text)
                                    onConnectNfc(CanSubmission.from(canState.text))
                                }
                            },
                            enabled = canReady,
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .testTag("managementReadCard"),
                        ) {
                            Text(stringResource(R.string.read_identity_card))
                        }
                    }
                }
            }
        }

        // Outcome Banner
        if (outcomeNotice != null) {
            val notice = outcomeNotice!!
            val message =
                if (notice.arg != null) {
                    stringResource(notice.resId, notice.arg)
                } else {
                    stringResource(notice.resId)
                }
            OutcomeBanner(
                message = message,
                isError = outcomeIsError,
            )
        }

        // Guidance / Policy Banner
        if (guidanceMessage != null && guidanceTone != null && outcomeNotice == null) {
            GuidanceBanner(
                message = guidanceMessage,
                tone = guidanceTone,
            )
        }

        // If card awaits activation
        if (isActivationFlow) {
            CardActivationForm(
                health =
                    health ?: CredentialHealth(
                        pin1State = NativePin1State.Remaining(3),
                        pin2State = NativePin2State.Remaining(3),
                        pukState = NativePin1State.Remaining(3),
                        scheme = fi.refineid.android.core.NativePinReferenceScheme.CITIZEN,
                        activationScheme = CardManagementScheme.PRESET_PIN,
                        activationNeeds =
                            fi.refineid.android.core.CardActivationNeeds(
                                pin1 = true,
                                pin2 = true,
                            ),
                    ),
                needsPin1 = needsPin1,
                needsPin2 = needsPin2,
                activationCodeState = activationCodeState,
                newPin1State = newPinState,
                newPin1ConfirmState = newPinConfirmState,
                newPin2State = newPin2State,
                newPin2ConfirmState = newPin2ConfirmState,
                canExecute = canExecute,
                isOperating = isOperating,
                onSubmit = { showConfirmDialog = true },
            )
        } else {
            // Task Form
            Section(
                when (selectedTask) {
                    ManagementTask.CHANGE_PIN1 -> stringResource(R.string.change_pin1)
                    ManagementTask.CHANGE_PIN2 -> stringResource(R.string.change_pin2)
                    ManagementTask.RESET_PIN1 -> stringResource(R.string.reset_pin1)
                    ManagementTask.RESET_PIN2 -> stringResource(R.string.reset_pin2)
                    ManagementTask.ACTIVATE_CARD -> ""
                },
            ) {
                when (selectedTask) {
                    ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                        ChangePinForm(
                            task = selectedTask,
                            currentState = currentPinState,
                            newState = newPinState,
                            confirmState = newPinConfirmState,
                            canExecute = canExecute,
                            isOperating = isOperating,
                            currentValid = currentPinValid,
                            newValid = newPinValid,
                            confirmValid = confirmationValid,
                            pinsDiffer = pinsDiffer,
                            onSubmit = { showConfirmDialog = true },
                        )
                    }

                    ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                        ResetPinForm(
                            task = selectedTask,
                            pukState = pukState,
                            newState = newPinState,
                            confirmState = newPinConfirmState,
                            canExecute = canExecute,
                            isOperating = isOperating,
                            pukValid = pukValid,
                            newValid = newPinValid,
                            confirmValid = confirmationValid,
                            onSubmit = { showConfirmDialog = true },
                        )
                    }

                    ManagementTask.ACTIVATE_CARD -> {}
                }
            }

            // Task Selector (at the bottom)
            Section(stringResource(R.string.card_pins)) {
                TaskSelector(
                    selectedTask = selectedTask,
                    onSelect = { task ->
                        selectedTask = task
                        outcomeNotice = null
                        clearEntries()
                    },
                )
            }
        }
    }

    if (showConfirmDialog) {
        val (dialogTitle, dialogMsg) =
            when (selectedTask) {
                ManagementTask.CHANGE_PIN1, ManagementTask.CHANGE_PIN2 -> {
                    val isPin1 = selectedTask == ManagementTask.CHANGE_PIN1
                    val pinName = if (isPin1) "PIN 1" else "PIN 2"
                    val attempts = if (isPin1) pin1Attempts else pin2Attempts
                    val title = stringResource(R.string.confirm_change_title, pinName)
                    val msg =
                        if (attempts != null && (attempts == 3 || attempts == 4)) {
                            stringResource(R.string.confirm_pin_change_warning, pinName, attempts)
                        } else {
                            null
                        }
                    title to msg
                }

                ManagementTask.RESET_PIN1, ManagementTask.RESET_PIN2 -> {
                    val isPin1 = selectedTask == ManagementTask.RESET_PIN1
                    val pinName = if (isPin1) "PIN 1" else "PIN 2"
                    val attempts = pukAttempts
                    val title = stringResource(R.string.confirm_reset_title, pinName)
                    val msg =
                        if (attempts != null && (attempts == 3 || attempts == 4)) {
                            stringResource(R.string.confirm_pin_reset_warning, "PUK", attempts)
                        } else {
                            null
                        }
                    title to msg
                }

                ManagementTask.ACTIVATE_CARD -> {
                    val title = stringResource(R.string.confirm_activation_title)
                    val msg =
                        if (needsPin1 && needsPin2) {
                            stringResource(R.string.confirm_activation_dialog_msg_both)
                        } else if (needsPin1) {
                            stringResource(R.string.confirm_activation_dialog_msg_single, "PIN 1")
                        } else {
                            stringResource(R.string.confirm_activation_dialog_msg_single, "PIN 2")
                        }
                    title to msg
                }
            }

        AlertDialog(
            onDismissRequest = { showConfirmDialog = false },
            title = { Text(dialogTitle) },
            text = dialogMsg?.let { msg -> { Text(msg) } },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDialog = false
                        executeOperation()
                    },
                    modifier = Modifier.testTag("managementConfirmButton"),
                ) {
                    Text(stringResource(R.string.proceed))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showConfirmDialog = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }
}

private enum class BannerTone {
    INFO,
    WARNING,
    CRITICAL,
}

private fun getAttempts(state: Any): Int? =
    when (state) {
        is NativePin1State.Remaining -> state.attempts
        is NativePin2State.Remaining -> state.attempts
        is NativePin1State.Locked, is NativePin2State.Locked -> 0
        is NativePin1State.Verified, is NativePin2State.Verified -> 5
        else -> null
    }

private fun isLowAttempts(attempts: Int?): Boolean = attempts != null && (attempts == 1 || attempts == 2)

private fun isWarningAttempts(attempts: Int?): Boolean = attempts != null && (attempts == 3 || attempts == 4)

private fun isLocked(state: Any?): Boolean =
    state is NativePin1State.Locked || state is NativePin2State.Locked || (state?.let { getAttempts(it) } == 0)

@Composable
private fun GuidanceBanner(
    message: String,
    tone: BannerTone,
    modifier: Modifier = Modifier,
) {
    val (containerColor, contentColor, icon) =
        when (tone) {
            BannerTone.CRITICAL -> {
                Triple(
                    MaterialTheme.colorScheme.errorContainer,
                    MaterialTheme.colorScheme.onErrorContainer,
                    Icons.Outlined.Warning,
                )
            }

            BannerTone.WARNING -> {
                val warning = warningContainerColors()
                Triple(warning.container, warning.content, Icons.Outlined.Warning)
            }

            BannerTone.INFO -> {
                Triple(
                    MaterialTheme.colorScheme.secondaryContainer,
                    MaterialTheme.colorScheme.onSecondaryContainer,
                    Icons.Outlined.CheckCircle,
                )
            }
        }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = contentColor,
            )
            Text(text = message, color = contentColor, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun TaskSelector(
    selectedTask: ManagementTask,
    onSelect: (ManagementTask) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TaskButton(
                text = stringResource(R.string.change_pin1),
                isSelected = selectedTask == ManagementTask.CHANGE_PIN1,
                onClick = { onSelect(ManagementTask.CHANGE_PIN1) },
                modifier = Modifier.weight(1f).testTag("managementTask.changePin1"),
            )
            TaskButton(
                text = stringResource(R.string.change_pin2),
                isSelected = selectedTask == ManagementTask.CHANGE_PIN2,
                onClick = { onSelect(ManagementTask.CHANGE_PIN2) },
                modifier = Modifier.weight(1f).testTag("managementTask.changePin2"),
            )
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TaskButton(
                text = stringResource(R.string.reset_pin1),
                isSelected = selectedTask == ManagementTask.RESET_PIN1,
                onClick = { onSelect(ManagementTask.RESET_PIN1) },
                modifier = Modifier.weight(1f).testTag("managementTask.resetPin1"),
            )
            TaskButton(
                text = stringResource(R.string.reset_pin2),
                isSelected = selectedTask == ManagementTask.RESET_PIN2,
                onClick = { onSelect(ManagementTask.RESET_PIN2) },
                modifier = Modifier.weight(1f).testTag("managementTask.resetPin2"),
            )
        }
    }
}

@Composable
private fun TaskButton(
    text: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (isSelected) {
        Button(
            onClick = onClick,
            modifier = modifier,
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
            shape = RoundedCornerShape(10.dp),
        ) {
            Text(text = text, style = MaterialTheme.typography.labelLarge)
        }
    } else {
        OutlinedButton(
            onClick = onClick,
            modifier = modifier,
            shape = RoundedCornerShape(10.dp),
        ) {
            Text(text = text, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun OutcomeBanner(
    message: String,
    isError: Boolean,
) {
    val success = successContainerColors()
    val containerColor = if (isError) MaterialTheme.colorScheme.errorContainer else success.container
    val contentColor = if (isError) MaterialTheme.colorScheme.onErrorContainer else success.content

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        shape = RoundedCornerShape(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = if (isError) Icons.Outlined.Warning else Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = contentColor,
            )
            Text(text = message, color = contentColor, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun ChangePinForm(
    task: ManagementTask,
    currentState: TextFieldState,
    newState: TextFieldState,
    confirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    currentValid: Boolean,
    newValid: Boolean,
    confirmValid: Boolean,
    pinsDiffer: Boolean,
    onSubmit: () -> Unit,
) {
    NavigationGroup {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val isPin2 = task == ManagementTask.CHANGE_PIN2
            val currentLabel =
                if (isPin2) {
                    stringResource(R.string.current_pin2)
                } else {
                    stringResource(R.string.current_pin1)
                }
            val newLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2)
                } else {
                    stringResource(R.string.new_pin1)
                }
            val repeatLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2_again)
                } else {
                    stringResource(R.string.new_pin1_again)
                }
            val buttonLabel =
                if (isPin2) {
                    stringResource(R.string.change_signature_pin2)
                } else {
                    stringResource(R.string.change_basic_pin1)
                }
            val lengthHint =
                if (isPin2) {
                    stringResource(R.string.pin2_length_hint)
                } else {
                    stringResource(R.string.pin1_length_hint)
                }

            val pinMismatch =
                confirmState.text.isNotEmpty() &&
                    confirmState.text.toString() != newState.text.toString()

            ManagedPasswordField(
                state = currentState,
                label = currentLabel,
                maxLength = 12,
                supportingText = lengthHint,
                imeAction = ImeAction.Next,
                testTag = "managementCurrentPin",
            )

            ManagedPasswordField(
                state = newState,
                label = newLabel,
                maxLength = 12,
                supportingText = lengthHint,
                imeAction = ImeAction.Next,
                testTag = "managementNewPin",
            )

            ManagedPasswordField(
                state = confirmState,
                label = repeatLabel,
                maxLength = 12,
                isError = pinMismatch,
                errorMessage = if (pinMismatch) stringResource(R.string.pins_do_not_match) else null,
                imeAction = ImeAction.Done,
                onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
                testTag = "managementNewPinRepeat",
            )

            Button(
                onClick = onSubmit,
                enabled = canExecute && !isOperating,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("managementSubmit"),
            ) {
                if (isOperating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(buttonLabel)
                }
            }
        }
    }
}

@Composable
private fun ResetPinForm(
    task: ManagementTask,
    pukState: TextFieldState,
    newState: TextFieldState,
    confirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    pukValid: Boolean,
    newValid: Boolean,
    confirmValid: Boolean,
    onSubmit: () -> Unit,
) {
    NavigationGroup {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            val isPin2 = task == ManagementTask.RESET_PIN2
            val newLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2)
                } else {
                    stringResource(R.string.new_pin1)
                }
            val repeatLabel =
                if (isPin2) {
                    stringResource(R.string.new_pin2_again)
                } else {
                    stringResource(R.string.new_pin1_again)
                }
            val buttonLabel =
                if (isPin2) {
                    stringResource(R.string.reset_pin2)
                } else {
                    stringResource(R.string.reset_pin1)
                }
            val lengthHint =
                if (isPin2) {
                    stringResource(R.string.pin2_length_hint)
                } else {
                    stringResource(R.string.pin1_length_hint)
                }

            val pinMismatch =
                confirmState.text.isNotEmpty() &&
                    confirmState.text.toString() != newState.text.toString()

            ManagedPasswordField(
                state = pukState,
                label = stringResource(R.string.puk_code),
                maxLength = 8,
                supportingText = stringResource(R.string.activation_code_length_hint, 8),
                imeAction = ImeAction.Next,
                testTag = "managementPuk",
            )

            ManagedPasswordField(
                state = newState,
                label = newLabel,
                maxLength = 12,
                supportingText = lengthHint,
                imeAction = ImeAction.Next,
                testTag = "managementNewPin",
            )

            ManagedPasswordField(
                state = confirmState,
                label = repeatLabel,
                maxLength = 12,
                isError = pinMismatch,
                errorMessage = if (pinMismatch) stringResource(R.string.pins_do_not_match) else null,
                imeAction = ImeAction.Done,
                onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
                testTag = "managementNewPinRepeat",
            )

            Button(
                onClick = onSubmit,
                enabled = canExecute && !isOperating,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag("managementSubmit"),
            ) {
                if (isOperating) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text(buttonLabel)
                }
            }
        }
    }
}

@Composable
private fun CardActivationForm(
    health: CredentialHealth,
    needsPin1: Boolean,
    needsPin2: Boolean,
    activationCodeState: TextFieldState,
    newPin1State: TextFieldState,
    newPin1ConfirmState: TextFieldState,
    newPin2State: TextFieldState,
    newPin2ConfirmState: TextFieldState,
    canExecute: Boolean,
    isOperating: Boolean,
    onSubmit: () -> Unit,
) {
    val activationCodeLength =
        when (health.activationScheme) {
            CardManagementScheme.PRESET_PIN -> 7
            CardManagementScheme.PUK -> 8
            else -> 7
        }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (!needsPin1 && needsPin2) {
            Text(
                text = stringResource(R.string.half_activated_pin2_needed),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        } else if (needsPin1 && !needsPin2) {
            Text(
                text = stringResource(R.string.half_activated_pin1_needed),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }

        NavigationGroup {
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                ManagedPasswordField(
                    state = activationCodeState,
                    label = stringResource(R.string.activation_pin),
                    maxLength = activationCodeLength,
                    supportingText = stringResource(R.string.activation_code_length_hint, activationCodeLength),
                    imeAction = ImeAction.Next,
                    testTag = UiAutomationIds.ACTIVATION_CODE_FIELD,
                )
            }
        }

        if (needsPin1) {
            val pin1Mismatch =
                newPin1ConfirmState.text.isNotEmpty() &&
                    newPin1ConfirmState.text.toString() != newPin1State.text.toString()

            Section(stringResource(R.string.pin1_section_title)) {
                NavigationGroup {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        ManagedPasswordField(
                            state = newPin1State,
                            label = stringResource(R.string.new_pin1),
                            maxLength = 12,
                            supportingText = stringResource(R.string.pin1_length_hint),
                            imeAction = ImeAction.Next,
                            testTag = UiAutomationIds.ACTIVATION_NEW_PIN1_FIELD,
                        )

                        ManagedPasswordField(
                            state = newPin1ConfirmState,
                            label = stringResource(R.string.new_pin1_again),
                            maxLength = 12,
                            isError = pin1Mismatch,
                            errorMessage = if (pin1Mismatch) stringResource(R.string.pins_do_not_match) else null,
                            imeAction = if (needsPin2) ImeAction.Next else ImeAction.Done,
                            onKeyboardAction =
                                if (!needsPin2) {
                                    { if (canExecute && !isOperating) onSubmit() }
                                } else {
                                    null
                                },
                            testTag = UiAutomationIds.ACTIVATION_NEW_PIN1_REPEAT_FIELD,
                        )
                    }
                }
            }
        }

        if (needsPin2) {
            val pin2Mismatch =
                newPin2ConfirmState.text.isNotEmpty() &&
                    newPin2ConfirmState.text.toString() != newPin2State.text.toString()

            Section(stringResource(R.string.pin2_section_title)) {
                NavigationGroup {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        ManagedPasswordField(
                            state = newPin2State,
                            label = stringResource(R.string.new_pin2),
                            maxLength = 12,
                            supportingText = stringResource(R.string.pin2_length_hint),
                            imeAction = ImeAction.Next,
                            testTag = UiAutomationIds.ACTIVATION_NEW_PIN2_FIELD,
                        )

                        ManagedPasswordField(
                            state = newPin2ConfirmState,
                            label = stringResource(R.string.new_pin2_again),
                            maxLength = 12,
                            isError = pin2Mismatch,
                            errorMessage = if (pin2Mismatch) stringResource(R.string.pins_do_not_match) else null,
                            imeAction = ImeAction.Done,
                            onKeyboardAction = { if (canExecute && !isOperating) onSubmit() },
                            testTag = UiAutomationIds.ACTIVATION_NEW_PIN2_REPEAT_FIELD,
                        )
                    }
                }
            }
        }

        Button(
            onClick = onSubmit,
            enabled = canExecute && !isOperating,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.ACTIVATION_SUBMIT_ACTION),
        ) {
            if (isOperating) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            } else {
                Text(stringResource(R.string.activate_card))
            }
        }
    }
}

@Composable
private fun ManagedPasswordField(
    state: TextFieldState,
    label: String,
    modifier: Modifier = Modifier,
    imeAction: ImeAction = ImeAction.Next,
    onKeyboardAction: (() -> Unit)? = null,
    maxLength: Int = 12,
    supportingText: String? = null,
    isError: Boolean = false,
    errorMessage: String? = null,
    testTag: String? = null,
) {
    var passwordVisible by remember { mutableStateOf(false) }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        SecureTextField(
            state = state,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .then(if (testTag != null) Modifier.testTag(testTag) else Modifier),
            label = { Text(label) },
            textObfuscationMode =
                if (passwordVisible) {
                    TextObfuscationMode.Visible
                } else {
                    TextObfuscationMode.Hidden
                },
            inputTransformation = remember(maxLength) { digitsOnlyTransformation(maxLength) },
            keyboardOptions =
                KeyboardOptions(
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.NumberPassword,
                    imeAction = imeAction,
                ),
            onKeyboardAction = onKeyboardAction?.let { action -> { action() } },
            trailingIcon = {
                IconButton(
                    onClick = { passwordVisible = !passwordVisible },
                    modifier = Modifier.testTag(if (testTag != null) "${testTag}Toggle" else "passwordToggle"),
                ) {
                    Icon(
                        painter =
                            painterResource(
                                if (passwordVisible) R.drawable.ic_visibility_off else R.drawable.ic_visibility,
                            ),
                        contentDescription =
                            stringResource(
                                if (passwordVisible) R.string.hide_pin else R.string.show_pin,
                            ),
                    )
                }
            },
        )
        if (isError && errorMessage != null) {
            Text(
                text = errorMessage,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 16.dp),
            )
        } else if (supportingText != null) {
            Text(
                text = supportingText,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 16.dp),
            )
        }
    }
}

private fun digitsOnlyTransformation(maxLength: Int): InputTransformation =
    InputTransformation {
        val text = asCharSequence()
        if (text.length > maxLength || !text.all { it in '0'..'9' }) {
            revertAllChanges()
        }
    }
