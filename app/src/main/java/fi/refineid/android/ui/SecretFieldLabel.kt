// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.ui

import androidx.compose.material3.TextFieldLabelPosition

/**
 * Where every PIN, PUK and access-number field shows its label: above
 * the field, across its full width. A label inside the field shares the
 * row with the padding and the reveal control, so a long Finnish name
 * such as "Allekirjoitustunnusluku 2" wraps there; above the field it
 * has the whole column and keeps the name with its number.
 */
internal val SecretFieldLabelPosition: TextFieldLabelPosition = TextFieldLabelPosition.Above()
