// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import fi.refineid.android.R
import fi.refineid.android.nfc.NfcCardProblem
import fi.refineid.android.nfc.NfcReaderSnapshot

/** What the holder is told about a card that answered and cannot be used. */
internal fun cardProblemMessage(problem: NfcCardProblem): Int =
    when (problem) {
        NfcCardProblem.NO_KNOWN_KIND -> R.string.card_problem_no_known_kind
        NfcCardProblem.ACCESS_FILE_REFUSED -> R.string.card_problem_access_file_refused
        NfcCardProblem.ACCESS_FILE_MALFORMED -> R.string.card_problem_access_file_malformed
        NfcCardProblem.READ_FAILED -> R.string.card_read_failed
    }

/**
 * The reason a card in the field cannot be used, in the error colour; nothing
 * while the card is usable or awaited.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun NfcCardProblemText(
    snapshot: NfcReaderSnapshot?,
    modifier: Modifier = Modifier,
) {
    val problem = snapshot?.cardProblem ?: return
    Text(
        text = stringResource(cardProblemMessage(problem)),
        color = MaterialTheme.colorScheme.error,
        modifier = modifier.testTag(UiAutomationIds.NFC_CARD_PROBLEM),
    )
}
