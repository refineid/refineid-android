package fi.refineid.android.ui

import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import fi.refineid.android.R
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.docsign.CoreDocuments
import fi.refineid.android.docsign.NamedInput
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.refineid_doc_sign_android.DocumentVerdict
import uniffi.refineid_doc_sign_android.JudgedSignature
import uniffi.refineid_doc_sign_android.RevisionStatus
import uniffi.refineid_doc_sign_android.RevocationStatus
import uniffi.refineid_doc_sign_android.SignatureVerdict
import uniffi.refineid_doc_sign_android.VerifyFailure
import java.io.File
import java.io.IOException
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

private sealed interface DocumentValidationUiState {
    data object Idle : DocumentValidationUiState

    data object Working : DocumentValidationUiState

    data class Done(
        val verdict: DocumentVerdict,
    ) : DocumentValidationUiState

    data object Unsigned : DocumentValidationUiState

    data object Malformed : DocumentValidationUiState

    data object ReadFailed : DocumentValidationUiState

    data object AnchorsUnavailable : DocumentValidationUiState
}

/**
 * The Verify screen: the core judges every signature of the chosen file,
 * asking the responders about a signer the file leaves unchecked, and
 * the verdict is shown.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun DocumentValidationHarness(initialUri: Uri? = null) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<DocumentValidationUiState>(DocumentValidationUiState.Idle) }

    LaunchedEffect(initialUri) {
        if (initialUri != null) {
            state = DocumentValidationUiState.Working
            AppTrace.documentValidationStarted()
            scope.launch {
                state =
                    withContext(Dispatchers.IO) {
                        verifyChosen(context, initialUri)
                    }
                AppTrace.documentValidationCompleted(state is DocumentValidationUiState.Done)
            }
        }
    }

    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .testTag(UiAutomationIds.DOCUMENT_VALIDATION_CARD),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = VALIDATION_CARD_ELEVATION),
    ) {
        Column(
            modifier = Modifier.padding(VALIDATION_CARD_PADDING),
            verticalArrangement = Arrangement.spacedBy(VALIDATION_CARD_SPACING),
        ) {
            DocumentValidationStatus(state = state)
        }
    }
}

/** The core's verdict on the file at [uri]; blocks on the file and the network. */
private fun verifyChosen(
    context: android.content.Context,
    uri: Uri,
): DocumentValidationUiState {
    val resolver = context.contentResolver
    val input =
        NamedInput(displayName(resolver, uri)) {
            resolver.openInputStream(uri) ?: throw IOException("document could not be opened")
        }
    val workDirectory = File(context.cacheDir, VERIFY_DIRECTORY).apply { mkdirs() }
    val cacheDirectory = File(context.cacheDir, TRUSTED_LISTS_DIRECTORY).apply { mkdirs() }
    return try {
        CoreDocuments.installHttpClient()
        DocumentValidationUiState.Done(CoreDocuments.verify(input, workDirectory, cacheDirectory))
    } catch (failure: VerifyFailure) {
        AppTrace.documentVerificationFailed(failure.javaClass.simpleName)
        when (failure) {
            is VerifyFailure.NoSignatures -> DocumentValidationUiState.Unsigned

            is VerifyFailure.NotASignedDocument,
            is VerifyFailure.Unreadable,
            is VerifyFailure.Unsupported,
            -> DocumentValidationUiState.Malformed

            is VerifyFailure.FileRead -> DocumentValidationUiState.ReadFailed

            is VerifyFailure.AnchorsUnavailable -> DocumentValidationUiState.AnchorsUnavailable
        }
    } catch (failure: IOException) {
        AppTrace.documentVerificationFailed(failure.javaClass.simpleName)
        DocumentValidationUiState.ReadFailed
    } catch (failure: SecurityException) {
        AppTrace.documentVerificationFailed(failure.javaClass.simpleName)
        DocumentValidationUiState.ReadFailed
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationStatus(state: DocumentValidationUiState) {
    when (state) {
        DocumentValidationUiState.Idle -> {
            // Nothing to show before a document is picked.
        }

        DocumentValidationUiState.Working -> {
            Text(stringResource(R.string.checking))
        }

        DocumentValidationUiState.ReadFailed -> {
            Text(stringResource(R.string.error), color = MaterialTheme.colorScheme.error)
        }

        DocumentValidationUiState.Unsigned -> {
            Text(stringResource(R.string.document_unsigned))
        }

        DocumentValidationUiState.Malformed -> {
            Text(stringResource(R.string.document_malformed), color = MaterialTheme.colorScheme.error)
        }

        DocumentValidationUiState.AnchorsUnavailable -> {
            Text(stringResource(R.string.document_anchors_unavailable), color = MaterialTheme.colorScheme.error)
        }

        is DocumentValidationUiState.Done -> {
            DocumentValidationVerdict(verdict = state.verdict)
        }
    }
}

/** The judged signatures of [verdict]. */
private fun DocumentVerdict.judged(): List<JudgedSignature> =
    signatures.mapNotNull { entry -> (entry.verdict as? SignatureVerdict.Judged)?.signature }

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DocumentValidationVerdict(verdict: DocumentVerdict) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        val judged = verdict.judged()
        val revoked = judged.any { it.revocation is RevocationStatus.Revoked }
        val revocationChecked = judged.isNotEmpty() && judged.all { it.revocation is RevocationStatus.Good }
        val headline =
            when {
                revoked -> {
                    stringResource(R.string.signed_cert_revoked)
                }

                verdict.valid && revocationChecked -> {
                    stringResource(R.string.document_valid_revocation_checked)
                }

                verdict.valid -> {
                    stringResource(R.string.document_valid)
                }

                else -> {
                    stringResource(R.string.document_invalid)
                }
            }
        Text(
            text = headline,
            color =
                if (verdict.valid) {
                    successStatusColor()
                } else {
                    MaterialTheme.colorScheme.error
                },
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.testTag(UiAutomationIds.DOCUMENT_VALIDATION_STATUS),
        )

        verdict.signatures.forEachIndexed { index, entry ->
            SignatureDetailsCard(index = index, verdict = entry.verdict)
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun SignatureDetailsCard(
    index: Int,
    verdict: SignatureVerdict,
) {
    val judged = (verdict as? SignatureVerdict.Judged)?.signature
    val signer =
        when (verdict) {
            is SignatureVerdict.Judged -> verdict.signature.signer
            is SignatureVerdict.Unsupported -> verdict.signer
        }
    val time = judged?.let { it.proofOfExistence ?: it.claimedSigningTime }

    OutlinedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors =
            CardDefaults.outlinedCardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
            ),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.document_signature_ordinal, index + 1),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    if (judged?.valid == true) {
                        StatusChip(
                            text = stringResource(R.string.signature_status_valid),
                            color = successStatusColor(),
                        )
                    } else {
                        StatusChip(
                            text = stringResource(R.string.signature_status_invalid),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (judged?.chainVerified == true) {
                        StatusChip(
                            text = stringResource(R.string.signature_status_trusted),
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }

            if (!signer.isNullOrBlank()) {
                DetailRow(
                    label = stringResource(R.string.signature_details_signer),
                    value = signer,
                )
            }
            if (!time.isNullOrBlank()) {
                DetailRow(
                    label = stringResource(R.string.signature_details_time),
                    value = formatDisplayTime(time),
                )
            }

            if (judged?.revision == RevisionStatus.CHANGED_AFTER_SIGNING) {
                Text(
                    stringResource(R.string.document_partial_coverage),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                )
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun StatusChip(
    text: String,
    color: Color,
) {
    Box(
        modifier =
            Modifier
                .background(
                    color = color.copy(alpha = 0.12f),
                    shape = RoundedCornerShape(8.dp),
                ).padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun DetailRow(
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = "$label:",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.widthIn(min = 60.dp),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Normal,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** The core's RFC 3339 time as `YYYY-MM-DD HH:MM:SS UTC`; any other text as it is. */
internal fun formatDisplayTime(raw: String): String =
    try {
        DISPLAY_TIME.format(Instant.parse(raw))
    } catch (_: DateTimeParseException) {
        raw
    }

private fun displayName(
    resolver: android.content.ContentResolver,
    uri: Uri,
): String =
    try {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) cursor.getString(index) else null
            } else {
                null
            }
        }
    } catch (_: RuntimeException) {
        null
    }?.takeIf { it.isNotBlank() } ?: DEFAULT_DOCUMENT_NAME

private val DISPLAY_TIME: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC)
private const val VERIFY_DIRECTORY = "verify"
private const val TRUSTED_LISTS_DIRECTORY = "trusted-lists"
private const val DEFAULT_DOCUMENT_NAME = "document"
private val VALIDATION_CARD_PADDING = 20.dp
private val VALIDATION_CARD_SPACING = 12.dp
private val VALIDATION_CARD_ELEVATION = 2.dp
