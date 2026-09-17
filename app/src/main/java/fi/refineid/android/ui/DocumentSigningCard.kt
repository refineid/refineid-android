// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("LongMethod")

package fi.refineid.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.InputTransformation
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin2Submission

internal enum class DocumentSigningStatus {
    IDLE,
    READING,
    HOLD_CARD,
    SIGNING,
    FINALIZING,
    SAVING,
    SIGNED,
    CERT_REVOKED,
    NO_CARD,
    WRONG_PIN,
    PIN_LOCKED,
    UNAVAILABLE,
    ERROR,
}

/**
 * What the signature produces: PDF or ASiC-E container / portfolio (Salkku).
 */
internal enum class SignatureFormat {
    PDF,
    CONTAINER,
}

/**
 * The signing card:
 * 1. Before selection: shows a single primary action button:
 *    - "Valitse asiakirjat"
 * 2. After selection: shows the list of chosen document names,
 *    an "Lisää tiedosto" button,
 *    followed by CAN (if contactless unprimed reader), PIN 2,
 *    and the format action buttons:
 *    - "Allekirjoita asiakirja(t) (PDF)" (only if all selected files are PDFs)
 *    - "Allekirjoita salkku (ASiC-E)"
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentSigningCard(
    hasDocument: Boolean,
    documentNames: List<String> = emptyList(),
    canSignPdf: Boolean = true,
    progressText: String? = null,
    canRequired: Boolean,
    canSign: Boolean,
    status: DocumentSigningStatus,
    onChooseDocuments: () -> Unit,
    onAddDocument: () -> Unit,
    onSign: (SignatureFormat, Pin2Submission, CanSubmission?) -> Unit,
) {
    val initialCan = remember { fi.refineid.android.core.CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }
    val pinState = remember { TextFieldState() }
    DisposableEffect(pinState) {
        onDispose {
            pinState.clearText()
        }
    }
    val isWorking =
        status == DocumentSigningStatus.READING ||
            status == DocumentSigningStatus.HOLD_CARD ||
            status == DocumentSigningStatus.SIGNING ||
            status == DocumentSigningStatus.FINALIZING ||
            status == DocumentSigningStatus.SAVING
    val hasRememberedCan = fi.refineid.android.core.CanSessionStore.hasCan
    val canReady = !canRequired || hasRememberedCan || CanSubmission.isComplete(canState.text)
    val pinReady = Pin2Submission.isComplete(pinState.text)
    val submit = { targetFormat: SignatureFormat ->
        if (canReady && pinReady) {
            val can =
                if (CanSubmission.isComplete(canState.text)) {
                    fi.refineid.android.core.CanSessionStore
                        .remember(canState.text)
                    CanSubmission.from(canState.text)
                } else if (fi.refineid.android.core.CanSessionStore.hasCan) {
                    fi.refineid.android.core.CanSessionStore.currentCan
                        ?.let { CanSubmission.from(it) }
                } else {
                    null
                }
            val pin2 = Pin2Submission.from(pinState.text)
            pinState.clearText()
            onSign(targetFormat, pin2, can)
        }
        Unit
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.DOCUMENT_SIGNING_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = DOCUMENT_CARD_ELEVATION),
        shape = RoundedCornerShape(DOCUMENT_CARD_CORNER_RADIUS),
    ) {
        Column(
            modifier = Modifier.padding(DOCUMENT_CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(DOCUMENT_ITEM_SPACING),
        ) {
            if (!hasDocument) {
                Button(
                    onClick = onChooseDocuments,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION),
                    enabled = !isWorking,
                ) {
                    Text(stringResource(R.string.choose_documents))
                }
            } else {
                OutlinedCard(
                    onClick = onChooseDocuments,
                    enabled = !isWorking,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.DOCUMENT_CHOOSE_ACTION),
                    shape = RoundedCornerShape(12.dp),
                    colors =
                        CardDefaults.outlinedCardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
                        ),
                ) {
                    Column(
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        documentNames.forEach { name ->
                            Text(
                                text = name,
                                modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_SELECTED_STATUS),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }

                OutlinedButton(
                    onClick = onAddDocument,
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !isWorking,
                ) {
                    Text(stringResource(R.string.add_file))
                }

                if (canRequired) {
                    SecureTextField(
                        state = canState,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .testTag(UiAutomationIds.DOCUMENT_CAN_FIELD),
                        enabled = !isWorking,
                        label = { Text(stringResource(R.string.can)) },
                        inputTransformation = CanInputTransformation,
                        textObfuscationMode = TextObfuscationMode.Visible,
                        keyboardOptions =
                            KeyboardOptions(
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.NumberPassword,
                                imeAction = ImeAction.Next,
                            ),
                    )
                }
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.PIN2_FIELD),
                    enabled = !isWorking,
                    label = { Text(stringResource(R.string.signature_pin2)) },
                    inputTransformation = Pin2InputTransformation,
                    textObfuscationMode = TextObfuscationMode.Hidden,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                )

                if (canSignPdf) {
                    val pdfButtonText =
                        if (documentNames.size <= 1) {
                            stringResource(R.string.sign_pdf_single)
                        } else {
                            stringResource(R.string.sign_pdf_multiple)
                        }
                    Button(
                        onClick = { submit(SignatureFormat.PDF) },
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .testTag(UiAutomationIds.DOCUMENT_SIGN_ACTION),
                        enabled = canSign && !isWorking && canReady && pinReady,
                    ) {
                        Text(pdfButtonText)
                    }
                }
                Button(
                    onClick = { submit(SignatureFormat.CONTAINER) },
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.DOCUMENT_FORMAT_CONTAINER),
                    enabled = canSign && !isWorking && canReady && pinReady,
                ) {
                    Text(stringResource(R.string.sign_container))
                }
            }
            DocumentSigningStatusText(status = status, progressText = progressText)
        }
    }
}

internal val Pin2InputTransformation =
    InputTransformation {
        if (!Pin2Submission.acceptsEntry(asCharSequence())) {
            revertAllChanges()
        }
    }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentSigningStatusText(
    status: DocumentSigningStatus,
    progressText: String? = null,
) {
    val text =
        if (progressText != null &&
            (
                status == DocumentSigningStatus.SIGNING ||
                    status == DocumentSigningStatus.FINALIZING ||
                    status == DocumentSigningStatus.SAVING
            )
        ) {
            progressText
        } else {
            when (status) {
                DocumentSigningStatus.IDLE -> null
                DocumentSigningStatus.READING -> stringResource(R.string.checking)
                DocumentSigningStatus.HOLD_CARD -> stringResource(R.string.hold_card)
                DocumentSigningStatus.SIGNING -> stringResource(R.string.signing)
                DocumentSigningStatus.FINALIZING -> stringResource(R.string.finalizing_signature)
                DocumentSigningStatus.SAVING -> stringResource(R.string.saving)
                DocumentSigningStatus.SIGNED -> stringResource(R.string.signed)
                DocumentSigningStatus.CERT_REVOKED -> stringResource(R.string.signed_cert_revoked)
                DocumentSigningStatus.NO_CARD -> stringResource(R.string.no_card)
                DocumentSigningStatus.WRONG_PIN -> stringResource(R.string.wrong_pin)
                DocumentSigningStatus.PIN_LOCKED -> stringResource(R.string.pin_locked)
                DocumentSigningStatus.UNAVAILABLE -> stringResource(R.string.unavailable)
                DocumentSigningStatus.ERROR -> stringResource(R.string.error)
            }
        }
    if (text != null) {
        Text(
            text = text,
            modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_SIGNING_STATUS),
            color =
                if (status == DocumentSigningStatus.SIGNED) {
                    successStatusColor()
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

private val DOCUMENT_CARD_PADDING = 20.dp
private val DOCUMENT_ITEM_SPACING = 14.dp
private val DOCUMENT_CARD_CORNER_RADIUS = 22.dp
private val DOCUMENT_CARD_ELEVATION = 2.dp
