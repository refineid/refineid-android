// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.document.ArchivalLevelPolicy
import fi.refineid.android.document.BaselineLevel
import fi.refineid.android.document.PdfValidationMaterial
import fi.refineid.android.document.QualifiedPdfTimestampPhase
import fi.refineid.android.document.QualifiedPdfTimestampSource
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import fi.refineid.android.document.QualifiedPdfValidationSource
import fi.refineid.android.document.SignedDocumentName
import fi.refineid.android.document.ValidationMaterialCollectionException
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationPathRole
import fi.refineid.android.document.VerifiedTimestampCertificatePath
import fi.refineid.android.document.VerifiedTimestampToken
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.time.Instant
import javax.xml.parsers.DocumentBuilderFactory

/** XAdES-B-LTA completion of an ASiC-E container over a synthetic timestamp source. */
class QualifiedAsicArchivalCompletionTest {
    @Test
    fun placesOneArchiveTimestampLastOverTheExactArchiveInput() {
        val timestamps = RecordingTimestampSource()
        val result =
            QualifiedAsicArchivalCompletion.complete(
                prepared = prepared(),
                timestampSource = timestamps,
                validationSource = RecordingValidationSource(),
                policy = ArchivalLevelPolicy.LONG_TERM_ONLY,
            )

        val container = (result as AsicSigningResult.Success).container
        val xml = XadesArchiveInputReading.signatureXml(container)
        assertEquals(
            SINGLE,
            XadesArchiveInputReading.occurrences(xml, XadesArchiveInputReading.ARCHIVE_TIMESTAMP_START),
        )
        assertFalse(xml.contains(XADES_132_ARCHIVE_TIMESTAMP))
        val archiveStart = xml.indexOf(XadesArchiveInputReading.ARCHIVE_TIMESTAMP_START)
        assertTrue(archiveStart > xml.indexOf(XadesArchiveInputReading.CERTIFICATE_VALUES_END))
        assertTrue(archiveStart > xml.indexOf(XadesArchiveInputReading.REVOCATION_VALUES_END))
        assertTrue(
            xml.startsWith(
                XadesArchiveInputReading.ARCHIVE_TIMESTAMP_END + LINE_BREAK +
                    XadesArchiveInputReading.UNSIGNED_SIGNATURE_PROPERTIES_END,
                xml.indexOf(XadesArchiveInputReading.ARCHIVE_TIMESTAMP_END),
            ),
        )
        assertArchiveTimestampIsLastByNamespace(xml)
        assertEquals(EXPECTED_PRECEDING_PROPERTY_COUNT, XadesArchiveInputReading.precedingUnsignedProperties(xml).size)

        val recomputed = XadesArchiveInputReading.archiveDigest(container)
        assertArrayEquals(recomputed, timestamps.archiveDigest)
        val token = XadesArchiveInputReading.archiveTimestampToken(xml)
        val tokenPrefix = ARCHIVE_TOKEN_PREFIX.encodeToByteArray()
        assertArrayEquals(tokenPrefix, token.copyOfRange(START, tokenPrefix.size))
        assertArrayEquals(recomputed, token.copyOfRange(tokenPrefix.size, token.size))
        assertEquals(
            listOf(QualifiedPdfTimestampPhase.SIGNATURE, QualifiedPdfTimestampPhase.ARCHIVE),
            timestamps.phases,
        )
    }

    @Test
    fun aReleaseBuildRefusesEveryContainerBelowLongTermAndKeepsNoBytes() {
        val policy = ArchivalLevelPolicy.forBuild(isDebugBuild = false)
        assertEquals(ArchivalLevelPolicy.LONG_TERM_ONLY, policy)
        for (case in REDUCIBLE_CASES) {
            val prepared = prepared()
            val result =
                QualifiedAsicArchivalCompletion.complete(
                    prepared = prepared,
                    timestampSource = RecordingTimestampSource(case.timestampFailure, case.timestampMode),
                    validationSource = RecordingValidationSource(case.validationFailure, case.coversArchiveAuthority),
                    policy = policy,
                )

            val failure = result as AsicSigningResult.Failure
            assertEquals(case.toString(), case.reason, failure.reason)
            assertTrue(prepared.rawSignature.all { byte -> byte == CLEARED_BYTE })
        }
    }

    @Test
    fun aDebugBuildKeepsTheLevelReachedAndNamesTheFileByIt() {
        val policy = ArchivalLevelPolicy.forBuild(isDebugBuild = true)
        assertEquals(ArchivalLevelPolicy.HIGHEST_REACHED, policy)
        for (case in REDUCIBLE_CASES) {
            val result =
                QualifiedAsicArchivalCompletion.complete(
                    prepared = prepared(),
                    timestampSource = RecordingTimestampSource(case.timestampFailure, case.timestampMode),
                    validationSource = RecordingValidationSource(case.validationFailure, case.coversArchiveAuthority),
                    policy = policy,
                )

            val reduced = result as AsicSigningResult.BelowLongTerm
            assertEquals(case.toString(), case.level, reduced.level)
            assertEquals(case.toString(), case.reason, reduced.reason)
            val xml = XadesArchiveInputReading.signatureXml(reduced.container)
            assertFalse(xml.contains(XadesArchiveInputReading.ARCHIVE_TIMESTAMP_START))
            assertEquals(case.level != BaselineLevel.B_B, xml.contains(SIGNATURE_TIMESTAMP_START))
            assertEquals(case.level == BaselineLevel.B_LT, xml.contains(CERTIFICATE_VALUES_START))
            assertEquals(
                CONTAINER_NAME_BASE + DEVELOPMENT_MARK + case.level.label + CONTAINER_EXTENSION,
                SignedDocumentName.belowLongTerm(CONTAINER_NAME_BASE + CONTAINER_EXTENSION, reduced.level),
            )
        }
    }

    private fun assertArchiveTimestampIsLastByNamespace(xml: String) {
        val document =
            DocumentBuilderFactory
                .newInstance()
                .apply { isNamespaceAware = true }
                .newDocumentBuilder()
                .parse(xml.byteInputStream())
        val properties =
            document.getElementsByTagNameNS(XadesSignature.NAMESPACE_XADES, UNSIGNED_SIGNATURE_PROPERTIES).item(START)
        var last: Element? = null
        var child = properties.firstChild
        while (child != null) {
            if (child is Element) {
                last = child
            }
            child = child.nextSibling
        }
        assertEquals(XadesSignature.NAMESPACE_XADES_141, checkNotNull(last).namespaceURI)
        assertEquals(ARCHIVE_TIMESTAMP, last.localName)
        assertEquals(
            SINGLE,
            document.getElementsByTagNameNS(XadesSignature.NAMESPACE_XADES_141, ARCHIVE_TIMESTAMP).length,
        )
    }

    private fun prepared(): PreparedAsicSignature {
        val objects =
            listOf(
                AsicDataObject(FIRST_NAME, FIRST_CONTENT.encodeToByteArray(), TEXT_MEDIA_TYPE),
                AsicDataObject(SECOND_NAME, SECOND_CONTENT.encodeToByteArray(), TEXT_MEDIA_TYPE),
            )
        val certificate = SIGNER_CERTIFICATE.encodeToByteArray()
        val plan =
            XadesSignature.plan(
                profile = NativeCardKeyProfile.ECDSA_P384,
                objects = objects,
                certificateDer = certificate,
                signedAt = SIGNED_AT,
            )
        return PreparedAsicSignature(
            plan = plan,
            objects = objects,
            rawSignature = CARD_SIGNATURE.encodeToByteArray(),
            certificateDer = certificate,
        )
    }

    private class RecordingTimestampSource(
        private val failurePhase: QualifiedPdfTimestampPhase? = null,
        private val failureMode: TimestampFailureMode? = null,
    ) : QualifiedPdfTimestampSource {
        val phases = mutableListOf<QualifiedPdfTimestampPhase>()
        var archiveDigest: ByteArray? = null
            private set

        override fun acquire(digest: ByteArray): VerifiedTimestampToken {
            val phase =
                if (phases.isEmpty()) QualifiedPdfTimestampPhase.SIGNATURE else QualifiedPdfTimestampPhase.ARCHIVE
            phases += phase
            if (phase == QualifiedPdfTimestampPhase.ARCHIVE) {
                archiveDigest = digest.copyOf()
            }
            if (phase == failurePhase && failureMode == TimestampFailureMode.UNAVAILABLE) {
                throw QualifiedPdfTimestampSourceException()
            }
            val imprint = digest.copyOf()
            if (phase == failurePhase && failureMode == TimestampFailureMode.WRONG_IMPRINT) {
                imprint[imprint.lastIndex] = (imprint.last().toInt() xor DIFFERENT_DIGEST_BIT).toByte()
            }
            val prefix =
                when (phase) {
                    QualifiedPdfTimestampPhase.SIGNATURE -> SIGNATURE_TOKEN_PREFIX
                    QualifiedPdfTimestampPhase.ARCHIVE -> ARCHIVE_TOKEN_PREFIX
                }
            return VerifiedTimestampToken(
                ownedEncoding = prefix.encodeToByteArray() + imprint,
                ownedMessageImprint = imprint,
                ownedSignerCertificate = TIMESTAMP_SIGNER.encodeToByteArray(),
                ownedEmbeddedCertificates = emptyList(),
                ownedCertificatePath =
                    VerifiedTimestampCertificatePath(
                        ownedCertificates = listOf(TIMESTAMP_SIGNER.encodeToByteArray()),
                        ownedTrustAnchor = TIMESTAMP_ROOT.encodeToByteArray(),
                    ),
                generatedAt = TIMESTAMP_TIME,
            )
        }
    }

    private class RecordingValidationSource(
        private val failure: ValidationMaterialCollectionException? = null,
        private val coversArchiveAuthority: Boolean = true,
    ) : QualifiedPdfValidationSource {
        override fun collect(
            signerCertificate: ByteArray,
            signatureTimestamp: VerifiedTimestampToken,
        ): PdfValidationMaterial {
            failure?.let { thrown -> throw thrown }
            val authority =
                if (coversArchiveAuthority) {
                    listOf(TIMESTAMP_SIGNER, TIMESTAMP_ROOT)
                } else {
                    listOf(TIMESTAMP_SIGNER)
                }
            return PdfValidationMaterial.copyOf(
                certificates = (authority + SIGNER_ISSUER).map(String::encodeToByteArray),
                ocspResponses = listOf(OCSP_RESPONSE.encodeToByteArray()),
                revocationLists = listOf(REVOCATION_LIST.encodeToByteArray()),
            )
        }
    }

    private enum class TimestampFailureMode {
        UNAVAILABLE,
        WRONG_IMPRINT,
    }

    private data class ReducibleCase(
        val level: BaselineLevel,
        val reason: AsicSigningFailure,
        val timestampFailure: QualifiedPdfTimestampPhase? = null,
        val timestampMode: TimestampFailureMode? = null,
        val validationFailure: ValidationMaterialCollectionException? = null,
        val coversArchiveAuthority: Boolean = true,
    )

    private companion object {
        const val FIRST_NAME = "agreement.txt"
        const val SECOND_NAME = "appendix.txt"
        const val FIRST_CONTENT = "synthetic agreement text"
        const val SECOND_CONTENT = "synthetic appendix text"
        const val TEXT_MEDIA_TYPE = "text/plain"
        const val SIGNER_CERTIFICATE = "synthetic signer certificate"
        const val SIGNER_ISSUER = "synthetic signer issuer"
        const val CARD_SIGNATURE = "synthetic card signature"
        const val TIMESTAMP_SIGNER = "synthetic timestamp signer"
        const val TIMESTAMP_ROOT = "synthetic timestamp root"
        const val OCSP_RESPONSE = "synthetic OCSP response"
        const val REVOCATION_LIST = "synthetic revocation list"
        const val SIGNATURE_TOKEN_PREFIX = "synthetic signature timestamp over "
        const val ARCHIVE_TOKEN_PREFIX = "synthetic archive timestamp over "
        const val CONTAINER_NAME_BASE = "Agreement - signed at 2026-11-08T12-00-00Z"
        const val CONTAINER_EXTENSION = "." + AsicContainer.FILE_EXTENSION
        const val DEVELOPMENT_MARK = "-dev-"
        const val UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties"
        const val ARCHIVE_TIMESTAMP = "ArchiveTimeStamp"
        const val XADES_132_ARCHIVE_TIMESTAMP = "<xades:ArchiveTimeStamp"
        const val SIGNATURE_TIMESTAMP_START = "<xades:SignatureTimeStamp "
        const val CERTIFICATE_VALUES_START = "<xades:CertificateValues "
        const val LINE_BREAK = "\n"
        const val SINGLE = 1
        const val START = 0

        // One SignatureTimeStamp, CertificateValues and RevocationValues.
        const val EXPECTED_PRECEDING_PROPERTY_COUNT = 3
        const val DIFFERENT_DIGEST_BIT = 1
        const val CLEARED_BYTE: Byte = 0
        val SIGNED_AT: Instant = Instant.parse("2026-11-08T12:00:00Z")
        val TIMESTAMP_TIME: Instant = Instant.parse("2026-11-08T12:00:05Z")

        val REDUCIBLE_CASES =
            listOf(
                ReducibleCase(
                    level = BaselineLevel.B_B,
                    reason = AsicSigningFailure.Timestamp(QualifiedPdfTimestampPhase.SIGNATURE),
                    timestampFailure = QualifiedPdfTimestampPhase.SIGNATURE,
                    timestampMode = TimestampFailureMode.UNAVAILABLE,
                ),
                ReducibleCase(
                    level = BaselineLevel.B_B,
                    reason = AsicSigningFailure.Timestamp(QualifiedPdfTimestampPhase.SIGNATURE),
                    timestampFailure = QualifiedPdfTimestampPhase.SIGNATURE,
                    timestampMode = TimestampFailureMode.WRONG_IMPRINT,
                ),
                ReducibleCase(
                    level = BaselineLevel.B_T,
                    reason =
                        AsicSigningFailure.Validation(
                            ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE,
                            ValidationPathRole.DOCUMENT_SIGNER,
                        ),
                    validationFailure =
                        ValidationMaterialCollectionException(
                            ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE,
                            ValidationPathRole.DOCUMENT_SIGNER,
                        ),
                ),
                ReducibleCase(
                    level = BaselineLevel.B_LT,
                    reason = AsicSigningFailure.Timestamp(QualifiedPdfTimestampPhase.ARCHIVE),
                    timestampFailure = QualifiedPdfTimestampPhase.ARCHIVE,
                    timestampMode = TimestampFailureMode.UNAVAILABLE,
                ),
                ReducibleCase(
                    level = BaselineLevel.B_LT,
                    reason = AsicSigningFailure.Timestamp(QualifiedPdfTimestampPhase.ARCHIVE),
                    timestampFailure = QualifiedPdfTimestampPhase.ARCHIVE,
                    timestampMode = TimestampFailureMode.WRONG_IMPRINT,
                ),
                ReducibleCase(
                    level = BaselineLevel.B_LT,
                    reason = AsicSigningFailure.ArchiveTimestampPathUncovered,
                    coversArchiveAuthority = false,
                ),
            )
    }
}
