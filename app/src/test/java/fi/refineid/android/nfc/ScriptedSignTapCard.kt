// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import fi.refineid.android.core.NativeCardAccessFailure
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardAccessSummary
import fi.refineid.android.core.NfcCardKind

/** One presentation of a scripted card: each tap is a fresh handle. */
internal data class ScriptedTag(
    val presentation: Int,
)

/**
 * A card on the antenna as the signature's tap sees it, answering from a
 * script and recording what it was asked. [held] stands for a session the
 * reader opened before the signature began; [read] for an organisation card
 * whose certificates this phone kept when Basic PIN 1 opened it.
 */
internal class ScriptedSignTapCard(
    private val access: NativeCardAccessResult,
    var held: Boolean = false,
    private val read: Boolean = false,
    private val inField: Boolean = true,
) : SignTapCard<ScriptedTag> {
    val adopted = mutableListOf<ScriptedTag>()
    val probed = mutableListOf<ScriptedTag>()
    var citizenAccessNumber: String? = null
    var organizationOpened = false
    var closed = false

    override fun hasSession(): Boolean = held

    override fun adopt(tag: ScriptedTag) {
        adopted += tag
    }

    override fun connect(tag: ScriptedTag): Boolean = inField

    override fun probe(tag: ScriptedTag): NativeCardAccessResult {
        probed += tag
        return access
    }

    override fun openCitizen(
        tag: ScriptedTag,
        accessNumber: ByteArray,
    ) {
        citizenAccessNumber = String(accessNumber, Charsets.US_ASCII)
        held = true
    }

    override fun openOrganization(tag: ScriptedTag): Boolean {
        if (!read) return false
        organizationOpened = true
        held = true
        return true
    }

    /** The reader's session closes; stands for the controller's closeActiveSession. */
    fun close() {
        closed = true
        held = false
    }

    companion object {
        const val FIRST_TAP = 1
        const val SECOND_TAP = 2
        const val PACE_ENTRIES = 1

        fun answering(kind: NfcCardKind?): NativeCardAccessResult =
            NativeCardAccessResult.Success(NativeCardAccessSummary(cardKind = kind, paceEntryCount = PACE_ENTRIES))

        fun failing(kind: NativeCardAccessFailure): NativeCardAccessResult = NativeCardAccessResult.Failure(kind)
    }
}
