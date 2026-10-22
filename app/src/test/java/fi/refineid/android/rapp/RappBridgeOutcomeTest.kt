// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationDescriptor
import uniffi.refineid_rapp.RappOperationKind
import uniffi.refineid_rapp.RappSignatureAlgorithm
import java.security.MessageDigest
import java.security.SecureRandom

/** The binding border types each engine action once and refuses one whose fields do not fit its kind. */
class RappBridgeOutcomeTest {
    private companion object {
        const val FRAME_TEXT = "sealed frame"
        const val SHORT_TEXT = "short"
        const val DOCUMENT_NAME = "Contract.pdf"
        const val ORIGIN = "https://login.example.fi"
        const val FINGERPRINT_ALGORITHM = "SHA-256"
        const val DIGEST_ALGORITHM = "SHA-384"
    }

    @Before
    fun setUp() {
        RappNativeTestLibrary.require()
    }

    private val operationId = RappOperationId.random(SecureRandom())

    private fun action(
        kind: RappBridgeActionKind,
        operationId: ByteArray? = null,
        operation: RappOperationDescriptor? = null,
        frame: ByteArray? = null,
        cardPresent: Boolean? = null,
        certificateFingerprint: ByteArray? = null,
        closeSessionAfterSend: Boolean = false,
        closeReason: RappCloseReason? = null,
    ) = RappBridgeAction(
        kind = kind,
        operationId = operationId,
        operation = operation,
        frame = frame,
        result = null,
        terminalReason = null,
        progressEvent = null,
        cardPresent = cardPresent,
        certificateFingerprint = certificateFingerprint,
        closeSessionAfterSend = closeSessionAfterSend,
        closeReason = closeReason,
        cardExchangeContinues = false,
    )

    private fun digest(algorithm: String) = MessageDigest.getInstance(algorithm).digest(FRAME_TEXT.encodeToByteArray())

    private fun descriptor(
        kind: RappOperationKind,
        displayContext: String? = null,
        documentNames: List<String> = emptyList(),
        digests: List<ByteArray> = emptyList(),
    ) = RappOperationDescriptor(
        kind = kind,
        displayContext = displayContext,
        keyProfile = RappCardKeyProfile.ECDSA_P384,
        algorithm = RappSignatureAlgorithm.ECDSA_SHA384,
        digest = if (digests.isEmpty()) digest(DIGEST_ALGORITHM) else byteArrayOf(),
        documentNames = documentNames,
        digests = digests,
    )

    @Test
    fun aSendCarriesItsFrameAndWhetherTheSessionEndsAfterIt() {
        val send =
            RappBridgeOutcome.from(
                action(RappBridgeActionKind.SEND_FRAME, frame = FRAME_TEXT.encodeToByteArray()),
            )
        send as RappBridgeOutcome.Send
        assertTrue(send.frame.contentEquals(FRAME_TEXT.encodeToByteArray()))
        assertNull(send.closesWith)

        val closing =
            RappBridgeOutcome.from(
                action(
                    RappBridgeActionKind.SEND_FRAME,
                    frame = FRAME_TEXT.encodeToByteArray(),
                    closeSessionAfterSend = true,
                    closeReason = RappCloseReason.PAIRING_REVOKED,
                ),
            )
        assertEquals(RappCloseReason.PAIRING_REVOKED, (closing as RappBridgeOutcome.Send).closesWith)
    }

    @Test
    fun aFrameOnlyTravelsOnASendAndAClosingSendNamesItsReason() {
        assertThrows(
            IllegalStateException::class.java,
        ) { RappBridgeOutcome.from(action(RappBridgeActionKind.SEND_FRAME)) }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(action(RappBridgeActionKind.NO_ACTION, frame = FRAME_TEXT.encodeToByteArray()))
        }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(
                action(
                    RappBridgeActionKind.SEND_FRAME,
                    frame = FRAME_TEXT.encodeToByteArray(),
                    closeSessionAfterSend = true,
                ),
            )
        }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(
                action(
                    RappBridgeActionKind.SEND_FRAME,
                    frame = FRAME_TEXT.encodeToByteArray(),
                    closeReason = RappCloseReason.NORMAL,
                ),
            )
        }
    }

    @Test
    fun anOperationIdentifierHasTheEnginesSize() {
        val admitted =
            RappBridgeOutcome.from(
                action(RappBridgeActionKind.INSPECT_PREREQUISITES, operationId = operationId.toWire()),
            )
        assertEquals(operationId, (admitted as RappBridgeOutcome.Admitted).operationId)
        assertNull(RappOperationId.fromWire(SHORT_TEXT.encodeToByteArray()))
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(
                action(RappBridgeActionKind.INSPECT_PREREQUISITES, operationId = SHORT_TEXT.encodeToByteArray()),
            )
        }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(action(RappBridgeActionKind.INSPECT_PREREQUISITES))
        }
    }

    @Test
    fun aPresentCardIsNamedByAFingerprintAndAnAbsentOneByNone() {
        val fingerprint = digest(FINGERPRINT_ALGORITHM)
        val present =
            RappBridgeOutcome.from(
                action(RappBridgeActionKind.CARD_STATUS, cardPresent = true, certificateFingerprint = fingerprint),
            )
        assertEquals(
            RappCertificateFingerprint.fromWire(fingerprint),
            ((present as RappBridgeOutcome.CardStatus).status as RappCardStatus.Present).fingerprint,
        )
        val absent = RappBridgeOutcome.from(action(RappBridgeActionKind.CARD_STATUS, cardPresent = false))
        assertSame(RappCardStatus.Absent, (absent as RappBridgeOutcome.CardStatus).status)

        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(action(RappBridgeActionKind.CARD_STATUS, cardPresent = true))
        }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(
                action(
                    RappBridgeActionKind.CARD_STATUS,
                    cardPresent = true,
                    certificateFingerprint = SHORT_TEXT.encodeToByteArray(),
                ),
            )
        }
        assertThrows(IllegalStateException::class.java) {
            RappBridgeOutcome.from(
                action(RappBridgeActionKind.CARD_STATUS, cardPresent = false, certificateFingerprint = fingerprint),
            )
        }
    }

    @Test
    fun aRequestHasTheFieldsItsKindNames() {
        val authenticate = RappRequest.from(descriptor(RappOperationKind.BROWSER_AUTHENTICATE, displayContext = ORIGIN))
        assertEquals(ORIGIN, (authenticate as RappRequest.BrowserAuthenticate).origin)
        assertThrows(IllegalStateException::class.java) {
            RappRequest.from(descriptor(RappOperationKind.BROWSER_AUTHENTICATE))
        }

        val digests = listOf(digest(DIGEST_ALGORITHM), digest(DIGEST_ALGORITHM))
        val batch =
            RappRequest.from(
                descriptor(
                    RappOperationKind.BATCH_SIGN_DOCUMENTS,
                    documentNames = digests.map { DOCUMENT_NAME },
                    digests = digests,
                ),
            )
        assertEquals(digests.size, (batch as RappRequest.BatchSignDocuments).documents.size)
        assertThrows(IllegalStateException::class.java) {
            RappRequest.from(
                descriptor(
                    RappOperationKind.BATCH_SIGN_DOCUMENTS,
                    documentNames = listOf(DOCUMENT_NAME),
                    digests = digests,
                ),
            )
        }
    }
}
