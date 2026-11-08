package fi.refineid.android.nfc

import fi.refineid.android.core.NativeCardAccessFailure
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NfcCardKind
import fi.refineid.android.core.PersonCardDetails
import fi.refineid.android.core.Pin1Verification

internal enum class NfcReaderStatus {
    NOT_AVAILABLE,
    TURNED_OFF,
    WAITING_FOR_CARD,
    CHECKING,
    CARD_RECOGNIZED,
    CONNECTING,
    CARD_READY,
    WRONG_CAN,
    CARD_NOT_SUPPORTED,
    TRANSPORT_ERROR,
    ACTIVATION_REQUIRED,
}

internal data class NfcReaderSnapshot(
    val status: NfcReaderStatus = NfcReaderStatus.NOT_AVAILABLE,
    /** True while a card access number is stored for tap-to-open. */
    val isPrimed: Boolean = false,
    /** True while a stored access number is opening a discovered card. */
    val isPrimedOpening: Boolean = false,
    /**
     * True while a card-dependent operation is pending and only the
     * card is missing: the holder tapped connect, or a live session
     * was lost. The UI shows a present-card prompt until the card
     * returns or the holder cancels. Idle listening leaves this false.
     */
    val awaitingCard: Boolean = false,
    /** The cardholder name read from the certificate or primed store. */
    val holderName: String? = null,
    /** The detailed cardholder identity info parsed from the certificate. */
    val cardDetails: PersonCardDetails? = null,
    /** What opens the card last read in the field; null before one has answered. */
    val cardKind: NfcCardKind? = null,
    /** An organization card's PIN 1 tries, read before any entry; null when not read. */
    val pin1AttemptsLeft: Int? = null,
    /** The organization card's answer to the PIN 1 last offered to open it. */
    val pin1Answer: Pin1Verification? = null,
    /** Why the card in the field cannot be used, while the status says so. */
    val cardProblem: NfcCardProblem? = null,
)

/** Why a card that answered cannot be used; the holder is told which. */
internal enum class NfcCardProblem {
    /** EF.CardAccess names neither a citizen nor an organization card. */
    NO_KNOWN_KIND,

    /** The card refused the read of EF.CardAccess. */
    ACCESS_FILE_REFUSED,

    /** EF.CardAccess did not parse. */
    ACCESS_FILE_MALFORMED,

    /** The exchange with the card failed. */
    READ_FAILED,
}

/** Why the probe leaves the card unusable; null for a usable card or one that left the field. */
internal fun NativeCardAccessResult.cardProblem(): NfcCardProblem? =
    when (this) {
        is NativeCardAccessResult.Success -> {
            if (summary.cardKind == null) NfcCardProblem.NO_KNOWN_KIND else null
        }

        is NativeCardAccessResult.Failure -> {
            when (kind) {
                NativeCardAccessFailure.CARD_UNAVAILABLE -> {
                    null
                }

                NativeCardAccessFailure.REJECTED -> {
                    NfcCardProblem.ACCESS_FILE_REFUSED
                }

                NativeCardAccessFailure.INVALID_CARD_ACCESS -> {
                    NfcCardProblem.ACCESS_FILE_MALFORMED
                }

                NativeCardAccessFailure.TRANSPORT_ERROR, NativeCardAccessFailure.BRIDGE_ERROR -> {
                    NfcCardProblem.READ_FAILED
                }
            }
        }
    }

/** The statuses in which the card in the field cannot be used, and the holder is told why. */
internal val CARD_UNUSABLE = setOf(NfcReaderStatus.CARD_NOT_SUPPORTED, NfcReaderStatus.TRANSPORT_ERROR)

/** Coarse holder-facing status for one completed card-access probe. */
internal fun NativeCardAccessResult.toReaderStatus(): NfcReaderStatus =
    when (this) {
        is NativeCardAccessResult.Success -> {
            if (summary.cardKind != null) {
                NfcReaderStatus.CARD_RECOGNIZED
            } else {
                NfcReaderStatus.CARD_NOT_SUPPORTED
            }
        }

        is NativeCardAccessResult.Failure -> {
            when (kind) {
                // The card left the field mid-probe; the reader keeps
                // listening and another tap starts over.
                NativeCardAccessFailure.CARD_UNAVAILABLE -> {
                    NfcReaderStatus.WAITING_FOR_CARD
                }

                NativeCardAccessFailure.REJECTED,
                NativeCardAccessFailure.INVALID_CARD_ACCESS,
                -> {
                    NfcReaderStatus.CARD_NOT_SUPPORTED
                }

                NativeCardAccessFailure.TRANSPORT_ERROR,
                NativeCardAccessFailure.BRIDGE_ERROR,
                -> {
                    NfcReaderStatus.TRANSPORT_ERROR
                }
            }
        }
    }

/** Coarse holder-facing status for one completed session open. */
internal fun NativeCertificateReadFailure.toConnectStatus(): NfcReaderStatus =
    when (this) {
        NativeCertificateReadFailure.PACE_REJECTED -> NfcReaderStatus.WRONG_CAN

        NativeCertificateReadFailure.ORGANIZATION_CARD -> NfcReaderStatus.CARD_RECOGNIZED

        NativeCertificateReadFailure.CARD_UNAVAILABLE -> NfcReaderStatus.WAITING_FOR_CARD

        NativeCertificateReadFailure.REJECTED,
        NativeCertificateReadFailure.INVALID_CERTIFICATE,
        -> NfcReaderStatus.CARD_NOT_SUPPORTED

        NativeCertificateReadFailure.TRANSPORT_ERROR,
        NativeCertificateReadFailure.BRIDGE_ERROR,
        -> NfcReaderStatus.TRANSPORT_ERROR

        NativeCertificateReadFailure.ACTIVATION_REQUIRED -> NfcReaderStatus.ACTIVATION_REQUIRED
    }
