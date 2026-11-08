// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("LongMethod", "TooGenericExceptionCaught")

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.network.MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT
import fi.refineid.android.network.MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT
import fi.refineid.android.network.SigningNetworkLimits
import fi.refineid.android.settings.TimestampAuthorityConfiguration
import fi.refineid.android.settings.TimestampAuthorityRepository
import fi.refineid.android.settings.TimestampAuthorityStoreException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class TimestampAuthoritySettingsStatus {
    LOADING,
    READY,
    SAVING,
    SAVED,
    ERROR,
}

/** Debug settings surface for the holder-owned ordered timestamp-authority list. */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun TimestampAuthoritySettingsHarness(
    repository: TimestampAuthorityRepository?,
    launcher: (@Composable (onOpen: () -> Unit) -> Unit)? = null,
) {
    if (repository == null) {
        return
    }
    var isOpen by remember { mutableStateOf(false) }
    if (!isOpen) {
        if (launcher != null) {
            launcher { isOpen = true }
            return
        }
        Button(
            onClick = { isOpen = true },
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.TIMESTAMP_SETTINGS_ACTION),
        ) {
            Text(stringResource(R.string.timestamp_authorities))
        }
        return
    }
    TimestampAuthoritySettingsCard(
        repository = repository,
        onClose = { isOpen = false },
    )
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun TimestampAuthoritySettingsCard(
    repository: TimestampAuthorityRepository,
    onClose: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val editors = remember { mutableStateListOf<TimestampAuthorityEditor>() }
    var status by remember { mutableStateOf(TimestampAuthoritySettingsStatus.LOADING) }
    val isWorking =
        status == TimestampAuthoritySettingsStatus.LOADING || status == TimestampAuthoritySettingsStatus.SAVING

    LaunchedEffect(repository) {
        status = TimestampAuthoritySettingsStatus.LOADING
        try {
            loadAuthorityEditors(repository, editors)
            status = TimestampAuthoritySettingsStatus.READY
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: TimestampAuthorityStoreException) {
            status = TimestampAuthoritySettingsStatus.ERROR
        } catch (_: RuntimeException) {
            status = TimestampAuthoritySettingsStatus.ERROR
        }
    }
    DisposableEffect(editors) {
        onDispose(editors::closeAndClear)
    }

    val save = {
        if (!isWorking && editors.size >= MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT) {
            val configurations =
                try {
                    editors.copyConfigurations()
                } catch (_: IllegalArgumentException) {
                    status = TimestampAuthoritySettingsStatus.ERROR
                    null
                } catch (_: IllegalStateException) {
                    status = TimestampAuthoritySettingsStatus.ERROR
                    null
                }
            if (configurations != null) {
                status = TimestampAuthoritySettingsStatus.SAVING
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            repository.save(configurations)
                        }
                        status = TimestampAuthoritySettingsStatus.SAVED
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: TimestampAuthorityStoreException) {
                        status = TimestampAuthoritySettingsStatus.ERROR
                    } catch (_: RuntimeException) {
                        status = TimestampAuthoritySettingsStatus.ERROR
                    } finally {
                        closeConfigurations(configurations)
                    }
                }
            }
        }
        Unit
    }
    val restore = {
        if (!isWorking) {
            status = TimestampAuthoritySettingsStatus.LOADING
            scope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        repository.restoreDefaults()
                    }
                    loadAuthorityEditors(repository, editors)
                    status = TimestampAuthoritySettingsStatus.READY
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: TimestampAuthorityStoreException) {
                    status = TimestampAuthoritySettingsStatus.ERROR
                } catch (_: RuntimeException) {
                    status = TimestampAuthoritySettingsStatus.ERROR
                }
            }
        }
        Unit
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.TIMESTAMP_SETTINGS_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = SETTINGS_CARD_ELEVATION),
        shape = RoundedCornerShape(SETTINGS_CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(SETTINGS_CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(SETTINGS_ITEM_SPACING),
        ) {
            Text(
                text = stringResource(R.string.timestamp_authorities),
                fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.titleLarge,
            )
            editors.forEachIndexed { index, editor ->
                HorizontalDivider()
                TimestampAuthorityFields(
                    editor = editor,
                    index = index,
                    enabled = !isWorking,
                    onEdit = { status = TimestampAuthoritySettingsStatus.READY },
                    canMoveUp = index > FIRST_AUTHORITY_INDEX,
                    canMoveDown = index < editors.lastIndex,
                    canDelete = editors.size > MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT,
                    onMoveUp = {
                        editors.move(index, index - PREVIOUS_AUTHORITY_OFFSET)
                        status = TimestampAuthoritySettingsStatus.READY
                    },
                    onMoveDown = {
                        editors.move(index, index + NEXT_AUTHORITY_OFFSET)
                        status = TimestampAuthoritySettingsStatus.READY
                    },
                    onDelete = {
                        editors.removeAt(index).close()
                        status = TimestampAuthoritySettingsStatus.READY
                    },
                )
            }
            Button(
                onClick = {
                    editors += TimestampAuthorityEditor.empty()
                    status = TimestampAuthoritySettingsStatus.READY
                },
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.TIMESTAMP_ADD_ACTION),
                enabled = !isWorking && editors.size < MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT,
            ) {
                Text(stringResource(R.string.add))
            }
            Button(
                onClick = save,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.TIMESTAMP_SAVE_ACTION),
                enabled = !isWorking && editors.size >= MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT,
            ) {
                Text(stringResource(R.string.save))
            }
            TextButton(
                onClick = restore,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.TIMESTAMP_RESTORE_ACTION),
                enabled = !isWorking,
            ) {
                Text(stringResource(R.string.restore))
            }
            TextButton(
                onClick = onClose,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .testTag(UiAutomationIds.TIMESTAMP_CLOSE_ACTION),
                enabled = !isWorking,
            ) {
                Text(stringResource(R.string.close))
            }
            TimestampAuthoritySettingsStatusText(status)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun TimestampAuthorityFields(
    editor: TimestampAuthorityEditor,
    index: Int,
    enabled: Boolean,
    onEdit: () -> Unit,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    canDelete: Boolean,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit,
    onDelete: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(SETTINGS_FIELD_SPACING)) {
        TextField(
            state = editor.address,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.timestampAddressField(index)),
            enabled = enabled,
            label = { Text(stringResource(R.string.address)) },
            inputTransformation = addressInputTransformation(onEdit),
            keyboardOptions =
                KeyboardOptions(
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Uri,
                    imeAction = ImeAction.Next,
                ),
            lineLimits = TextFieldLineLimits.SingleLine,
        )
        TextField(
            state = editor.username,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.timestampUsernameField(index)),
            enabled = enabled,
            label = { Text(stringResource(R.string.username)) },
            inputTransformation = usernameInputTransformation(onEdit),
            keyboardOptions =
                KeyboardOptions(
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Text,
                    imeAction = ImeAction.Next,
                ),
            lineLimits = TextFieldLineLimits.SingleLine,
        )
        SecretField(
            state = editor.password,
            testTag = UiAutomationIds.timestampPasswordField(index),
            modifier = Modifier.fillMaxWidth(),
            enabled = enabled,
            label = stringResource(R.string.password),
            inputTransformation = passwordInputTransformation(onEdit),
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Done,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceEvenly,
        ) {
            TextButton(
                onClick = onMoveUp,
                modifier = Modifier.testTag(UiAutomationIds.timestampMoveUpAction(index)),
                enabled = enabled && canMoveUp,
            ) {
                Text(stringResource(R.string.up))
            }
            TextButton(
                onClick = onMoveDown,
                modifier = Modifier.testTag(UiAutomationIds.timestampMoveDownAction(index)),
                enabled = enabled && canMoveDown,
            ) {
                Text(stringResource(R.string.down))
            }
            TextButton(
                onClick = onDelete,
                modifier = Modifier.testTag(UiAutomationIds.timestampDeleteAction(index)),
                enabled = enabled && canDelete,
            ) {
                Text(stringResource(R.string.delete))
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun TimestampAuthoritySettingsStatusText(status: TimestampAuthoritySettingsStatus) {
    val text =
        when (status) {
            TimestampAuthoritySettingsStatus.LOADING -> stringResource(R.string.checking)
            TimestampAuthoritySettingsStatus.READY -> null
            TimestampAuthoritySettingsStatus.SAVING -> stringResource(R.string.saving)
            TimestampAuthoritySettingsStatus.SAVED -> stringResource(R.string.saved)
            TimestampAuthoritySettingsStatus.ERROR -> stringResource(R.string.error)
        }
    if (text != null) {
        Text(
            text = text,
            modifier = Modifier.testTag(UiAutomationIds.TIMESTAMP_SETTINGS_STATUS),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

private suspend fun loadAuthorityEditors(
    repository: TimestampAuthorityRepository,
    editors: SnapshotStateList<TimestampAuthorityEditor>,
) {
    withContext(Dispatchers.IO) {
        val configurations = repository.load()
        try {
            withContext(Dispatchers.Main.immediate) {
                editors.replaceWith(configurations)
            }
        } finally {
            closeConfigurations(configurations)
        }
    }
}

private class TimestampAuthorityEditor private constructor(
    addressValue: String,
    usernameValue: String?,
    passwordValue: CharArray?,
) : AutoCloseable {
    val address = TextFieldState(initialText = addressValue)
    val username = TextFieldState(initialText = usernameValue.orEmpty())
    val password = TextFieldState()
    private var isClosed = false

    init {
        password.edit {
            passwordValue?.forEach { character -> append(character) }
        }
    }

    fun copyConfiguration(): TimestampAuthorityConfiguration {
        check(!isClosed) {
            "timestamp-authority editor is closed"
        }
        val addressValue = address.text.toString()
        val usernameValue = username.text.toString().ifEmpty { null }
        if (usernameValue == null && password.text.isNotEmpty()) {
            throw IllegalArgumentException("password requires a username")
        }
        val passwordValue =
            usernameValue?.let {
                CharArray(password.text.length) { index -> password.text[index] }
            }
        return try {
            TimestampAuthorityConfiguration.copyOf(
                address = addressValue,
                username = usernameValue,
                password = passwordValue,
            )
        } finally {
            passwordValue?.fill(CLEARED_CHARACTER)
        }
    }

    override fun close() {
        if (!isClosed) {
            address.clearText()
            username.clearText()
            password.clearText()
            isClosed = true
        }
    }

    companion object {
        fun copyOf(configuration: TimestampAuthorityConfiguration): TimestampAuthorityEditor {
            val copiedPassword = configuration.copyPassword()
            return try {
                TimestampAuthorityEditor(
                    addressValue = configuration.address,
                    usernameValue = configuration.username,
                    passwordValue = copiedPassword,
                )
            } finally {
                copiedPassword?.fill(CLEARED_CHARACTER)
            }
        }

        fun empty(): TimestampAuthorityEditor =
            TimestampAuthorityEditor(
                addressValue = EMPTY_FIELD,
                usernameValue = null,
                passwordValue = null,
            )

        private const val EMPTY_FIELD = ""
    }
}

private fun SnapshotStateList<TimestampAuthorityEditor>.replaceWith(
    configurations: List<TimestampAuthorityConfiguration>,
) {
    val replacements = mutableListOf<TimestampAuthorityEditor>()
    try {
        configurations.mapTo(replacements, TimestampAuthorityEditor::copyOf)
    } catch (failure: RuntimeException) {
        closeEditors(replacements)
        throw failure
    }
    closeAndClear()
    addAll(replacements)
}

private fun SnapshotStateList<TimestampAuthorityEditor>.copyConfigurations(): List<TimestampAuthorityConfiguration> {
    val configurations = mutableListOf<TimestampAuthorityConfiguration>()
    try {
        mapTo(configurations, TimestampAuthorityEditor::copyConfiguration)
        return configurations
    } catch (failure: RuntimeException) {
        closeConfigurations(configurations)
        throw failure
    }
}

private fun SnapshotStateList<TimestampAuthorityEditor>.move(
    fromIndex: Int,
    toIndex: Int,
) {
    add(toIndex, removeAt(fromIndex))
}

private fun SnapshotStateList<TimestampAuthorityEditor>.closeAndClear() {
    closeEditors(this)
    clear()
}

private fun closeEditors(editors: Iterable<TimestampAuthorityEditor>) {
    editors.forEach(TimestampAuthorityEditor::close)
}

private fun closeConfigurations(configurations: Iterable<TimestampAuthorityConfiguration>) {
    configurations.forEach(TimestampAuthorityConfiguration::close)
}

private fun addressInputTransformation(onAcceptedEdit: () -> Unit) =
    InputTransformation {
        if (length > SigningNetworkLimits.MAXIMUM_ADDRESS_CHARACTERS) {
            revertAllChanges()
        } else {
            onAcceptedEdit()
        }
    }

private fun usernameInputTransformation(onAcceptedEdit: () -> Unit) =
    InputTransformation {
        if (
            length > SigningNetworkLimits.MAXIMUM_USERNAME_CHARACTERS ||
            asCharSequence().any(::isForbiddenUsernameCharacter)
        ) {
            revertAllChanges()
        } else {
            onAcceptedEdit()
        }
    }

private fun passwordInputTransformation(onAcceptedEdit: () -> Unit) =
    InputTransformation {
        if (
            length > SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS ||
            asCharSequence().any(::isForbiddenCredentialCharacter)
        ) {
            revertAllChanges()
        } else {
            onAcceptedEdit()
        }
    }

private fun isForbiddenUsernameCharacter(character: Char): Boolean =
    character == BASIC_CREDENTIAL_SEPARATOR || isForbiddenCredentialCharacter(character)

private fun isForbiddenCredentialCharacter(character: Char): Boolean =
    character == CARRIAGE_RETURN || character == LINE_FEED || character == NULL_CHARACTER

private const val FIRST_AUTHORITY_INDEX = 0
private const val PREVIOUS_AUTHORITY_OFFSET = 1
private const val NEXT_AUTHORITY_OFFSET = 1
private const val BASIC_CREDENTIAL_SEPARATOR = ':'
private const val CARRIAGE_RETURN = '\r'
private const val LINE_FEED = '\n'
private const val NULL_CHARACTER = '\u0000'
private const val CLEARED_CHARACTER = '\u0000'
private val SETTINGS_CARD_PADDING = 20.dp
private val SETTINGS_ITEM_SPACING = 14.dp
private val SETTINGS_FIELD_SPACING = 10.dp
private val SETTINGS_CARD_CORNER_RADIUS = 22.dp
private val SETTINGS_CARD_ELEVATION = 2.dp
