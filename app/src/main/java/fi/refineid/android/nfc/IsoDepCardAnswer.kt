// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import android.nfc.tech.IsoDep

/**
 * What the card answered at reset, as the NFC stack reports it: the
 * historical bytes of a Type A card, or the higher-layer response of a
 * Type B card. Empty when the stack reports neither; the native border
 * then names no activation scheme and opens the card as an activated one.
 */
internal fun IsoDep.cardAnswer(): ByteArray = historicalBytes ?: hiLayerResponse ?: ByteArray(0)
