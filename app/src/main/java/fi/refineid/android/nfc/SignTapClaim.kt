// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import fi.refineid.android.core.NativeCardAccessFailure
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NfcCardKind

/** Why a signature waiting on a contactless card ended without one. */
internal enum class SignTapFailure {
    /** No card answered while the signature waited. */
    NO_CARD,

    /** A card answered and left the field before it could be read. */
    CARD_LEFT,

    /** A citizen card answered and no access number is known for it. */
    ACCESS_NUMBER_REQUIRED,

    /** An organisation card answered that this phone has not read with Basic PIN 1. */
    ORGANIZATION_CARD_NOT_READ,

    /** EF.CardAccess names neither a citizen nor an organisation card. */
    NO_KNOWN_KIND,

    /** The card refused the read of EF.CardAccess. */
    ACCESS_FILE_REFUSED,

    /** EF.CardAccess did not parse. */
    ACCESS_FILE_MALFORMED,

    /** The exchange with the card failed. */
    READ_FAILED,
}

/** What a card presented to a waiting signature came to. */
internal sealed interface SignTapClaim {
    /**
     * A session serves the signature. [opened] says the tap opened it, so the
     * tap closes it; a session the reader already held stays the reader's.
     */
    data class Ready(
        val opened: Boolean,
    ) : SignTapClaim

    /** The card left before it answered; the wait goes on. */
    data object CardLeft : SignTapClaim

    /** The card answered and cannot sign here. */
    data class Refused(
        val failure: SignTapFailure,
    ) : SignTapClaim
}

/**
 * The card operations a signature's tap needs, over the tag type the platform
 * delivers. The ISO-DEP implementation lives in [NfcTapToSign]; JVM tests
 * script a card behind it.
 */
internal interface SignTapCard<Tag> {
    /** Whether the reader holds an open session on a card. */
    fun hasSession(): Boolean

    /** Hand a fresh tag handle to the open session. */
    fun adopt(tag: Tag)

    /** Connect the tag; false when the card has left the field. */
    fun connect(tag: Tag): Boolean

    /** EF.CardAccess, read in plain with no secret. */
    fun probe(tag: Tag): NativeCardAccessResult

    /** Open a citizen card's signing session with the access number, which it takes. */
    fun openCitizen(
        tag: Tag,
        accessNumber: ByteArray,
    )

    /** Open the organisation card this phone has read; false when it has read none. */
    fun openOrganization(tag: Tag): Boolean
}

/**
 * Worker-thread logic of one tag presented to a waiting signature. An open
 * session takes the fresh handle and serves at once. Otherwise EF.CardAccess
 * names the card's kind before any secret is touched: a citizen card opens
 * with its access number, an organisation card with the certificates kept
 * when Basic PIN 1 read it; each signature then runs PACE with Signature
 * PIN 2. A card that answered and cannot sign is refused with its reason.
 */
internal object SignTapClaimer {
    fun <Tag> claim(
        card: SignTapCard<Tag>,
        tag: Tag,
        accessNumber: () -> ByteArray?,
    ): SignTapClaim {
        if (card.hasSession()) {
            card.adopt(tag)
            return SignTapClaim.Ready(opened = false)
        }
        if (!card.connect(tag)) {
            return SignTapClaim.CardLeft
        }
        return when (val access = card.probe(tag)) {
            is NativeCardAccessResult.Success -> {
                open(card, tag, access.summary.cardKind, accessNumber)
            }

            is NativeCardAccessResult.Failure -> {
                access.kind.claim()
            }
        }
    }

    private fun <Tag> open(
        card: SignTapCard<Tag>,
        tag: Tag,
        kind: NfcCardKind?,
        accessNumber: () -> ByteArray?,
    ): SignTapClaim =
        when (kind) {
            NfcCardKind.PERSONAL -> {
                val number = accessNumber()
                if (number == null) {
                    SignTapClaim.Refused(SignTapFailure.ACCESS_NUMBER_REQUIRED)
                } else {
                    card.openCitizen(tag, number)
                    SignTapClaim.Ready(opened = true)
                }
            }

            NfcCardKind.ORGANIZATION -> {
                if (card.openOrganization(tag)) {
                    SignTapClaim.Ready(opened = true)
                } else {
                    SignTapClaim.Refused(SignTapFailure.ORGANIZATION_CARD_NOT_READ)
                }
            }

            null -> {
                SignTapClaim.Refused(SignTapFailure.NO_KNOWN_KIND)
            }
        }

    private fun NativeCardAccessFailure.claim(): SignTapClaim =
        when (this) {
            NativeCardAccessFailure.CARD_UNAVAILABLE -> {
                SignTapClaim.CardLeft
            }

            NativeCardAccessFailure.REJECTED -> {
                SignTapClaim.Refused(SignTapFailure.ACCESS_FILE_REFUSED)
            }

            NativeCardAccessFailure.INVALID_CARD_ACCESS -> {
                SignTapClaim.Refused(SignTapFailure.ACCESS_FILE_MALFORMED)
            }

            NativeCardAccessFailure.TRANSPORT_ERROR, NativeCardAccessFailure.BRIDGE_ERROR -> {
                SignTapClaim.Refused(SignTapFailure.READ_FAILED)
            }
        }
}
