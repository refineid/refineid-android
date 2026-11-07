package fi.refineid.android.nfc

import fi.refineid.android.core.NativeCardAccessFailure
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardAccessSummary
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NfcCardKind
import org.junit.Assert.assertEquals
import org.junit.Test

class NfcCardRecognitionTest {
    @Test
    fun bothKindsOfCardAreRecognized() {
        assertEquals(NfcReaderStatus.CARD_RECOGNIZED, summary(NfcCardKind.PERSONAL).toReaderStatus())
        assertEquals(NfcReaderStatus.CARD_RECOGNIZED, summary(NfcCardKind.ORGANIZATION).toReaderStatus())
    }

    @Test
    fun aCardOfNoKnownKindIsNotSupported() {
        assertEquals(NfcReaderStatus.CARD_NOT_SUPPORTED, summary(null).toReaderStatus())
    }

    @Test
    fun anAccessNumberRefusedForAnOrganizationCardIsARecognizedCard() {
        assertEquals(
            NfcReaderStatus.CARD_RECOGNIZED,
            NativeCertificateReadFailure.ORGANIZATION_CARD.toConnectStatus(),
        )
    }

    @Test
    fun aLostCardReturnsTheReaderToWaiting() {
        assertEquals(
            NfcReaderStatus.WAITING_FOR_CARD,
            failure(NativeCardAccessFailure.CARD_UNAVAILABLE).toReaderStatus(),
        )
    }

    @Test
    fun rejectionAndInvalidFilesAreUnsupportedCards() {
        assertEquals(
            NfcReaderStatus.CARD_NOT_SUPPORTED,
            failure(NativeCardAccessFailure.REJECTED).toReaderStatus(),
        )
        assertEquals(
            NfcReaderStatus.CARD_NOT_SUPPORTED,
            failure(NativeCardAccessFailure.INVALID_CARD_ACCESS).toReaderStatus(),
        )
    }

    @Test
    fun transportAndBridgeFailuresSurfaceAsErrors() {
        assertEquals(
            NfcReaderStatus.TRANSPORT_ERROR,
            failure(NativeCardAccessFailure.TRANSPORT_ERROR).toReaderStatus(),
        )
        assertEquals(
            NfcReaderStatus.TRANSPORT_ERROR,
            failure(NativeCardAccessFailure.BRIDGE_ERROR).toReaderStatus(),
        )
    }

    private fun summary(cardKind: NfcCardKind?): NativeCardAccessResult =
        NativeCardAccessResult.Success(
            NativeCardAccessSummary(
                cardKind = cardKind,
                paceEntryCount = SYNTHETIC_ENTRY_COUNT,
            ),
        )

    private fun failure(kind: NativeCardAccessFailure): NativeCardAccessResult = NativeCardAccessResult.Failure(kind)

    private companion object {
        const val SYNTHETIC_ENTRY_COUNT = 2
    }
}
