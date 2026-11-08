package fi.refineid.android.document

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class QualifiedPdfArchivalCompletionTest {
    @Test
    fun completesExactCardTimestampValidationAndArchiveOrderAndClearsIntermediates() {
        val events = mutableListOf<CompletionEvent>()
        val cryptography = RecordingCryptography(events)
        val preparedFixture = preparedFixture(cryptography)
        val timestamps = RecordingTimestampSource(events)
        val validation = RecordingValidationSource(events)

        val result =
            QualifiedPdfArchivalCompletion.complete(
                prepared = preparedFixture.prepared,
                timestampSource = timestamps,
                validationSource = validation,
                policy = PadesLevelPolicy.LONG_TERM_ONLY,
            )

        val success = result as QualifiedPdfArchivalResult.Success
        try {
            success.document.useBytes { document ->
                PdfDocumentIndex.parse(document)
                val text = document.toString(Charsets.ISO_8859_1)
                assertTrue(text.contains(VALIDATION_STORE_TYPE))
                assertTrue(text.contains(DOCUMENT_TIMESTAMP_TYPE))
                assertTrue(text.indexOf(DOCUMENT_TIMESTAMP_TYPE) > text.indexOf(VALIDATION_STORE_TYPE))
            }
            assertEquals(EXPECTED_COMPLETION_EVENTS, events)
            assertEquals(EXPECTED_TIMESTAMP_COUNT, timestamps.records.size)
            assertFalse(success.toString().contains(SYNTHETIC_CERTIFICATE.decodeToString()))
        } finally {
            success.document.close()
        }

        assertCompletionOwnersCleared(preparedFixture, cryptography, timestamps, validation)
        assertThrows(IllegalStateException::class.java, success.document::copyBytes)
    }

    @Test
    fun mapsUnavailableAndWrongImprintToTheirExactTimestampPhase() {
        for (case in TIMESTAMP_FAILURE_CASES) {
            val events = mutableListOf<CompletionEvent>()
            val cryptography = RecordingCryptography(events)
            val preparedFixture = preparedFixture(cryptography)
            val timestamps =
                RecordingTimestampSource(
                    events = events,
                    failurePhase = case.phase,
                    failureMode = case.mode,
                )
            val validation = RecordingValidationSource(events)

            val result =
                QualifiedPdfArchivalCompletion.complete(
                    prepared = preparedFixture.prepared,
                    timestampSource = timestamps,
                    validationSource = validation,
                    policy = PadesLevelPolicy.LONG_TERM_ONLY,
                )

            assertEquals(
                QualifiedPdfArchivalResult.Failure(
                    QualifiedPdfArchivalFailure.Timestamp(case.phase),
                ),
                result,
            )
            assertEquals(case.expectedEvents, events)
            assertCompletionOwnersCleared(preparedFixture, cryptography, timestamps, validation)
        }
    }

    @Test
    fun retainsTypedValidationFailureAndSkipsArchiveTimestamp() {
        val events = mutableListOf<CompletionEvent>()
        val cryptography = RecordingCryptography(events)
        val preparedFixture = preparedFixture(cryptography)
        val timestamps = RecordingTimestampSource(events)
        val validationFailure =
            ValidationMaterialCollectionException(
                kind = ValidationMaterialCollectionFailure.REVOKED,
                pathRole = ValidationPathRole.TIMESTAMP_AUTHORITY,
            )
        val validation = RecordingValidationSource(events, collectionFailure = validationFailure)

        val result =
            QualifiedPdfArchivalCompletion.complete(
                prepared = preparedFixture.prepared,
                timestampSource = timestamps,
                validationSource = validation,
                policy = PadesLevelPolicy.LONG_TERM_ONLY,
            )

        assertEquals(
            QualifiedPdfArchivalResult.Failure(
                QualifiedPdfArchivalFailure.Validation(
                    kind = ValidationMaterialCollectionFailure.REVOKED,
                    pathRole = ValidationPathRole.TIMESTAMP_AUTHORITY,
                ),
            ),
            result,
        )
        assertEquals(EXPECTED_VALIDATION_FAILURE_EVENTS, events)
        assertCompletionOwnersCleared(preparedFixture, cryptography, timestamps, validation)
    }

    @Test
    fun mapsTimestampedCmsAndValidationSourceFailuresAndClearsTheirOwners() {
        val cmsEvents = mutableListOf<CompletionEvent>()
        val cmsFailure = QualifiedDocumentCmsFailure.TIMESTAMP_TOKEN_UNAVAILABLE
        val cmsCryptography = RecordingCryptography(cmsEvents, assemblyFailure = cmsFailure)
        val cmsPrepared = preparedFixture(cmsCryptography)
        val cmsTimestamps = RecordingTimestampSource(cmsEvents)
        val unusedValidation = RecordingValidationSource(cmsEvents)

        val cmsResult =
            QualifiedPdfArchivalCompletion.complete(
                prepared = cmsPrepared.prepared,
                timestampSource = cmsTimestamps,
                validationSource = unusedValidation,
                policy = PadesLevelPolicy.LONG_TERM_ONLY,
            )

        assertEquals(
            QualifiedPdfArchivalResult.Failure(QualifiedPdfArchivalFailure.Cms(cmsFailure)),
            cmsResult,
        )
        assertEquals(EXPECTED_CMS_FAILURE_EVENTS, cmsEvents)
        assertCompletionOwnersCleared(cmsPrepared, cmsCryptography, cmsTimestamps, unusedValidation)

        val validationEvents = mutableListOf<CompletionEvent>()
        val validationCryptography = RecordingCryptography(validationEvents)
        val validationPrepared = preparedFixture(validationCryptography)
        val validationTimestamps = RecordingTimestampSource(validationEvents)
        val unavailableValidation = RecordingValidationSource(validationEvents, unavailable = true)

        val validationResult =
            QualifiedPdfArchivalCompletion.complete(
                prepared = validationPrepared.prepared,
                timestampSource = validationTimestamps,
                validationSource = unavailableValidation,
                policy = PadesLevelPolicy.LONG_TERM_ONLY,
            )

        assertEquals(
            QualifiedPdfArchivalResult.Failure(QualifiedPdfArchivalFailure.ValidationUnavailable),
            validationResult,
        )
        assertEquals(EXPECTED_VALIDATION_FAILURE_EVENTS, validationEvents)
        assertCompletionOwnersCleared(
            validationPrepared,
            validationCryptography,
            validationTimestamps,
            unavailableValidation,
        )
    }

    @Test
    fun aReleaseBuildRefusesEveryDocumentBelowLongTerm() {
        assertEquals(PadesLevelPolicy.LONG_TERM_ONLY, PadesLevelPolicy.forBuild(isDebugBuild = false))
        assertEquals(PadesLevelPolicy.HIGHEST_REACHED, PadesLevelPolicy.forBuild(isDebugBuild = true))
        val releasePolicy = PadesLevelPolicy.forBuild(isDebugBuild = false)
        for (case in REDUCIBLE_FAILURE_CASES) {
            val events = mutableListOf<CompletionEvent>()
            val cryptography = RecordingCryptography(events)
            val preparedFixture = preparedFixture(cryptography)
            val timestamps = case.timestamps(events)
            val validation = case.validation(events)

            val result =
                QualifiedPdfArchivalCompletion.complete(
                    prepared = preparedFixture.prepared,
                    timestampSource = timestamps,
                    validationSource = validation,
                    policy = releasePolicy,
                )

            assertEquals(case.name, QualifiedPdfArchivalResult.Failure(case.kind), result)
            assertFalse(case.name, events.contains(CompletionEvent.BASELINE_ASSEMBLY))
            assertCompletionOwnersCleared(preparedFixture, cryptography, timestamps, validation)
        }
    }

    @Test
    fun aDebugBuildKeepsTheHighestLevelReachedAndNamesTheFailure() {
        val debugPolicy = PadesLevelPolicy.forBuild(isDebugBuild = true)
        for (case in REDUCIBLE_FAILURE_CASES) {
            val events = mutableListOf<CompletionEvent>()
            val cryptography = RecordingCryptography(events)
            val preparedFixture = preparedFixture(cryptography)
            val timestamps = case.timestamps(events)
            val validation = case.validation(events)

            val result =
                QualifiedPdfArchivalCompletion.complete(
                    prepared = preparedFixture.prepared,
                    timestampSource = timestamps,
                    validationSource = validation,
                    policy = debugPolicy,
                )

            val reduced = result as QualifiedPdfArchivalResult.BelowLongTerm
            try {
                assertEquals(case.name, case.level, reduced.level)
                assertEquals(case.name, case.kind, reduced.kind)
                reduced.document.useBytes { document ->
                    PdfDocumentIndex.parse(document)
                    val text = document.toString(Charsets.ISO_8859_1)
                    assertFalse(case.name, text.contains(VALIDATION_STORE_TYPE))
                    assertFalse(case.name, text.contains(DOCUMENT_TIMESTAMP_TYPE))
                }
                assertEquals(
                    case.name,
                    case.level == PadesBaselineLevel.B_B,
                    events.contains(CompletionEvent.BASELINE_ASSEMBLY),
                )
            } finally {
                reduced.document.close()
            }
            assertCompletionOwnersCleared(preparedFixture, cryptography, timestamps, validation)
        }
    }

    private class ReducibleFailureCase(
        val name: String,
        val kind: QualifiedPdfArchivalFailure,
        val level: PadesBaselineLevel,
        val timestamps: (MutableList<CompletionEvent>) -> RecordingTimestampSource,
        val validation: (MutableList<CompletionEvent>) -> RecordingValidationSource,
    )

    @Test
    fun interruptionEscapesAfterClearingThePreparedCardMaterial() {
        val events = mutableListOf<CompletionEvent>()
        val cryptography = RecordingCryptography(events)
        val preparedFixture = preparedFixture(cryptography)
        var borrowedDigest: ByteArray? = null

        assertThrows(InterruptedException::class.java) {
            QualifiedPdfArchivalCompletion
                .complete(
                    prepared = preparedFixture.prepared,
                    timestampSource =
                        QualifiedPdfTimestampSource { digest ->
                            borrowedDigest = digest
                            throw InterruptedException()
                        },
                    validationSource =
                        QualifiedPdfValidationSource { _, _ ->
                            error("validation must not follow interruption")
                        },
                    policy = PadesLevelPolicy.LONG_TERM_ONLY,
                ).closeDocument()
        }

        assertEquals(
            listOf(CompletionEvent.SIGNATURE_DIGEST),
            events,
        )
        assertAllZero(checkNotNull(borrowedDigest))
        assertAllZero(preparedFixture.attributes)
        assertAllZero(preparedFixture.signature)
        assertAllZero(preparedFixture.certificate)
        assertAllZero(checkNotNull(cryptography.returnedSignatureDigest))
        assertThrows(
            IllegalStateException::class.java,
            preparedFixture.prepared::copySignerCertificate,
        )
    }

    private fun preparedFixture(cryptography: QualifiedPdfCryptography): PreparedFixture {
        val attributes = SYNTHETIC_SIGNED_ATTRIBUTES.copyOf()
        val signatureBytes =
            ByteArray(QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.signatureLength) {
                SYNTHETIC_SIGNATURE_FILL
            }
        val certificateBytes = SYNTHETIC_CERTIFICATE.copyOf()
        val prepared =
            PreparedQualifiedPdfSignature(
                ownedPlaceholder =
                    PdfIncrementalSigner.prepare(
                        document = PdfTestDocuments.minimalClassic().document,
                        revision = PdfSignatureRevision.Signature(VALID_CLAIM),
                    ),
                ownedSignedAttributes = attributes,
                ownedSignature =
                    NativeQualifiedSignature(
                        algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                        ownedBytes = signatureBytes,
                    ),
                ownedSignerCertificate =
                    NativeQualifiedCertificate(
                        keyProfile = NativeCardKeyProfile.RSA_3072,
                        ownedDer = certificateBytes,
                    ),
                cryptography = cryptography,
            )
        return PreparedFixture(
            prepared = prepared,
            attributes = attributes,
            signature = signatureBytes,
            certificate = certificateBytes,
        )
    }

    private fun assertCompletionOwnersCleared(
        prepared: PreparedFixture,
        cryptography: RecordingCryptography,
        timestamps: RecordingTimestampSource,
        validation: RecordingValidationSource,
    ) {
        assertAllZero(prepared.attributes)
        assertAllZero(prepared.signature)
        assertAllZero(prepared.certificate)
        cryptography.returnedSignatureDigest?.let(::assertAllZero)
        cryptography.returnedCms?.let(::assertAllZero)
        timestamps.borrowedDigests.forEach(::assertAllZero)
        timestamps.records.flatMap(TokenRecord::ownedBuffers).forEach(::assertAllZero)
        timestamps.records.forEach { record ->
            assertThrows(IllegalStateException::class.java, record.token::copyEncoding)
        }
        validation.borrowedSignerCertificate?.let(::assertAllZero)
        validation.borrowedTimestamp?.let { timestamp ->
            assertThrows(IllegalStateException::class.java, timestamp::copyEncoding)
        }
        validation.returnedMaterial?.let { material ->
            val failure =
                assertThrows(PdfSigningException::class.java) {
                    material.isEmpty
                }
            assertEquals(PdfSigningFailure.VALIDATION_MATERIAL_UNAVAILABLE, failure.kind)
        }
        assertThrows(IllegalStateException::class.java, prepared.prepared::copySignerCertificate)
    }

    private fun assertAllZero(bytes: ByteArray) {
        assertTrue(bytes.all { byte -> byte == CLEARED_BYTE })
    }

    private fun QualifiedPdfArchivalResult.closeDocument() {
        if (this is QualifiedPdfArchivalResult.Success) {
            document.close()
        }
    }

    private class RecordingCryptography(
        private val events: MutableList<CompletionEvent>,
        private val assemblyFailure: QualifiedDocumentCmsFailure? = null,
    ) : QualifiedPdfCryptography {
        var returnedSignatureDigest: ByteArray? = null
            private set
        var returnedCms: ByteArray? = null
            private set

        override fun signedAttributes(
            byteRangeDigest: ByteArray,
            signerCertificate: NativeQualifiedCertificate,
        ): ByteArray = error("signed attributes are already prepared")

        override fun assemble(
            signedAttributes: ByteArray,
            signature: NativeQualifiedSignature,
            signerCertificate: NativeQualifiedCertificate,
        ): ByteArray {
            events += CompletionEvent.BASELINE_ASSEMBLY
            assertArrayEquals(SYNTHETIC_SIGNED_ATTRIBUTES, signedAttributes)
            assertEquals(QualifiedSigningAlgorithm.RSA_PKCS1_SHA384, signature.algorithm)
            return SYNTHETIC_BASELINE_CMS.copyOf().also { cms -> returnedCms = cms }
        }

        override fun signatureTimestampDigest(signature: NativeQualifiedSignature): ByteArray {
            events += CompletionEvent.SIGNATURE_DIGEST
            assertEquals(QualifiedSigningAlgorithm.RSA_PKCS1_SHA384, signature.algorithm)
            return SIGNATURE_TIMESTAMP_DIGEST.copyOf().also { digest ->
                returnedSignatureDigest = digest
            }
        }

        override fun assembleTimestamped(
            signedAttributes: ByteArray,
            signature: NativeQualifiedSignature,
            signerCertificate: NativeQualifiedCertificate,
            timestampTokens: List<VerifiedTimestampToken>,
        ): ByteArray {
            events += CompletionEvent.TIMESTAMPED_ASSEMBLY
            assemblyFailure?.let { failure -> throw QualifiedDocumentCmsException(failure) }
            assertArrayEquals(SYNTHETIC_SIGNED_ATTRIBUTES, signedAttributes)
            assertEquals(QualifiedSigningAlgorithm.RSA_PKCS1_SHA384, signature.algorithm)
            assertEquals(NativeCardKeyProfile.RSA_3072, signerCertificate.keyProfile)
            val timestamp = timestampTokens.single()
            return timestamp.useEncoding { encoding ->
                (SYNTHETIC_CMS_PREFIX + encoding).also { cms -> returnedCms = cms }
            }
        }
    }

    private class RecordingTimestampSource(
        private val events: MutableList<CompletionEvent>,
        private val failurePhase: QualifiedPdfTimestampPhase? = null,
        private val failureMode: TimestampFailureMode? = null,
    ) : QualifiedPdfTimestampSource {
        val borrowedDigests = mutableListOf<ByteArray>()
        val records = mutableListOf<TokenRecord>()
        private var nextPhase: QualifiedPdfTimestampPhase? = QualifiedPdfTimestampPhase.SIGNATURE

        override fun acquire(digest: ByteArray): VerifiedTimestampToken {
            val phase = checkNotNull(nextPhase)
            nextPhase =
                when (phase) {
                    QualifiedPdfTimestampPhase.SIGNATURE -> QualifiedPdfTimestampPhase.ARCHIVE
                    QualifiedPdfTimestampPhase.ARCHIVE -> null
                }
            events += timestampEvent(phase)
            borrowedDigests += digest
            when (phase) {
                QualifiedPdfTimestampPhase.SIGNATURE -> {
                    assertArrayEquals(SIGNATURE_TIMESTAMP_DIGEST, digest)
                }

                QualifiedPdfTimestampPhase.ARCHIVE -> {
                    assertEquals(SHA384_DIGEST_LENGTH_BYTES, digest.size)
                    assertFalse(digest.contentEquals(SIGNATURE_TIMESTAMP_DIGEST))
                }
            }
            if (failurePhase == phase && failureMode == TimestampFailureMode.UNAVAILABLE) {
                throw QualifiedPdfTimestampSourceException()
            }
            val imprint = digest.copyOf()
            if (failurePhase == phase && failureMode == TimestampFailureMode.WRONG_IMPRINT) {
                imprint[imprint.lastIndex] =
                    (imprint.last().toInt() xor DIFFERENT_DIGEST_BIT).toByte()
            }
            return token(imprint = imprint, phase = phase).also(records::add).token
        }

        private fun token(
            imprint: ByteArray,
            phase: QualifiedPdfTimestampPhase,
        ): TokenRecord {
            val encoding =
                when (phase) {
                    QualifiedPdfTimestampPhase.SIGNATURE -> SIGNATURE_TIMESTAMP_ENCODING.copyOf()
                    QualifiedPdfTimestampPhase.ARCHIVE -> ARCHIVE_TIMESTAMP_ENCODING.copyOf()
                }
            val signerCertificate = SYNTHETIC_TIMESTAMP_CERTIFICATE.copyOf()
            val embeddedCertificate = SYNTHETIC_TIMESTAMP_INTERMEDIATE.copyOf()
            val pathCertificate = SYNTHETIC_TIMESTAMP_CERTIFICATE.copyOf()
            val trustAnchor = SYNTHETIC_TIMESTAMP_TRUST_ANCHOR.copyOf()
            val token =
                VerifiedTimestampToken(
                    ownedEncoding = encoding,
                    ownedMessageImprint = imprint,
                    ownedSignerCertificate = signerCertificate,
                    ownedEmbeddedCertificates = listOf(embeddedCertificate),
                    ownedCertificatePath =
                        VerifiedTimestampCertificatePath(
                            ownedCertificates = listOf(pathCertificate),
                            ownedTrustAnchor = trustAnchor,
                        ),
                    generatedAt = TIMESTAMP_GENERATION_TIME,
                )
            return TokenRecord(
                token = token,
                ownedBuffers =
                    listOf(
                        encoding,
                        imprint,
                        signerCertificate,
                        embeddedCertificate,
                        pathCertificate,
                        trustAnchor,
                    ),
            )
        }
    }

    private class RecordingValidationSource(
        private val events: MutableList<CompletionEvent>,
        private val collectionFailure: ValidationMaterialCollectionException? = null,
        private val unavailable: Boolean = false,
    ) : QualifiedPdfValidationSource {
        var borrowedSignerCertificate: ByteArray? = null
            private set
        var borrowedTimestamp: VerifiedTimestampToken? = null
            private set
        var returnedMaterial: PdfValidationMaterial? = null
            private set

        override fun collect(
            signerCertificate: ByteArray,
            signatureTimestamp: VerifiedTimestampToken,
        ): PdfValidationMaterial {
            events += CompletionEvent.VALIDATION
            borrowedSignerCertificate = signerCertificate
            borrowedTimestamp = signatureTimestamp
            collectionFailure?.let { failure -> throw failure }
            if (unavailable) {
                throw QualifiedPdfValidationSourceException()
            }
            return PdfValidationMaterial
                .copyOf(
                    certificates = listOf(SYNTHETIC_VALIDATION_CERTIFICATE),
                    ocspResponses = listOf(SYNTHETIC_OCSP_RESPONSE),
                    revocationLists = listOf(SYNTHETIC_REVOCATION_LIST),
                ).also { material -> returnedMaterial = material }
        }
    }

    private data class PreparedFixture(
        val prepared: PreparedQualifiedPdfSignature,
        val attributes: ByteArray,
        val signature: ByteArray,
        val certificate: ByteArray,
    )

    private data class TokenRecord(
        val token: VerifiedTimestampToken,
        val ownedBuffers: List<ByteArray>,
    )

    private data class TimestampFailureCase(
        val phase: QualifiedPdfTimestampPhase,
        val mode: TimestampFailureMode,
        val expectedEvents: List<CompletionEvent>,
    )

    private enum class TimestampFailureMode {
        UNAVAILABLE,
        WRONG_IMPRINT,
    }

    private enum class CompletionEvent {
        BASELINE_ASSEMBLY,
        SIGNATURE_DIGEST,
        SIGNATURE_TIMESTAMP,
        TIMESTAMPED_ASSEMBLY,
        VALIDATION,
        ARCHIVE_TIMESTAMP,
    }

    private companion object {
        fun timestampEvent(phase: QualifiedPdfTimestampPhase): CompletionEvent =
            when (phase) {
                QualifiedPdfTimestampPhase.SIGNATURE -> CompletionEvent.SIGNATURE_TIMESTAMP
                QualifiedPdfTimestampPhase.ARCHIVE -> CompletionEvent.ARCHIVE_TIMESTAMP
            }

        const val DIFFERENT_DIGEST_BIT = 1
        const val SYNTHETIC_SIGNATURE_FILL: Byte = 0x5A
        const val CLEARED_BYTE: Byte = 0
        const val VALIDATION_STORE_TYPE = "/Type /DSS"
        const val DOCUMENT_TIMESTAMP_TYPE = "/Type /DocTimeStamp"
        val VALID_CLAIM =
            PdfSignatureClaim(
                signedAt = Instant.parse("2026-08-16T12:34:56Z"),
                reason = null,
                location = null,
            )
        val SYNTHETIC_CERTIFICATE = "synthetic qualified certificate".encodeToByteArray()
        val SYNTHETIC_SIGNED_ATTRIBUTES = "synthetic signed attributes".encodeToByteArray()
        val SYNTHETIC_CMS_PREFIX = "synthetic timestamped CMS".encodeToByteArray()
        val SYNTHETIC_BASELINE_CMS = "synthetic baseline CMS".encodeToByteArray()
        val SYNTHETIC_TIMESTAMP_CERTIFICATE = "synthetic timestamp certificate".encodeToByteArray()
        val SYNTHETIC_TIMESTAMP_INTERMEDIATE = "synthetic timestamp intermediate".encodeToByteArray()
        val SYNTHETIC_TIMESTAMP_TRUST_ANCHOR = "synthetic timestamp trust anchor".encodeToByteArray()
        val SYNTHETIC_VALIDATION_CERTIFICATE = "synthetic validation certificate".encodeToByteArray()
        val SYNTHETIC_OCSP_RESPONSE = "synthetic OCSP response".encodeToByteArray()
        val SYNTHETIC_REVOCATION_LIST = "synthetic revocation list".encodeToByteArray()
        val SIGNATURE_TIMESTAMP_DIGEST =
            ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_SIGNATURE_FILL }
        const val SIGNATURE_TIMESTAMP_TOKEN_VALUE = 1
        const val ARCHIVE_TIMESTAMP_TOKEN_VALUE = 2
        val SIGNATURE_TIMESTAMP_ENCODING =
            DerEncoder.sequence(listOf(DerEncoder.integer(SIGNATURE_TIMESTAMP_TOKEN_VALUE)))
        val ARCHIVE_TIMESTAMP_ENCODING =
            DerEncoder.sequence(listOf(DerEncoder.integer(ARCHIVE_TIMESTAMP_TOKEN_VALUE)))
        val TIMESTAMP_GENERATION_TIME: Instant = Instant.parse("2026-08-16T12:35:00Z")
        val EXPECTED_COMPLETION_EVENTS =
            listOf(
                CompletionEvent.SIGNATURE_DIGEST,
                CompletionEvent.SIGNATURE_TIMESTAMP,
                CompletionEvent.TIMESTAMPED_ASSEMBLY,
                CompletionEvent.VALIDATION,
                CompletionEvent.ARCHIVE_TIMESTAMP,
            )
        const val EXPECTED_TIMESTAMP_COUNT = 2
        val EXPECTED_VALIDATION_FAILURE_EVENTS =
            listOf(
                CompletionEvent.SIGNATURE_DIGEST,
                CompletionEvent.SIGNATURE_TIMESTAMP,
                CompletionEvent.TIMESTAMPED_ASSEMBLY,
                CompletionEvent.VALIDATION,
            )
        val EXPECTED_CMS_FAILURE_EVENTS =
            listOf(
                CompletionEvent.SIGNATURE_DIGEST,
                CompletionEvent.SIGNATURE_TIMESTAMP,
                CompletionEvent.TIMESTAMPED_ASSEMBLY,
            )
        val REDUCIBLE_FAILURE_CASES =
            listOf(
                ReducibleFailureCase(
                    name = "issuer unavailable",
                    kind =
                        QualifiedPdfArchivalFailure.Validation(
                            kind = ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE,
                            pathRole = null,
                        ),
                    level = PadesBaselineLevel.B_T,
                    timestamps = { events -> RecordingTimestampSource(events) },
                    validation = { events ->
                        RecordingValidationSource(
                            events,
                            collectionFailure =
                                ValidationMaterialCollectionException(
                                    ValidationMaterialCollectionFailure.ISSUER_UNAVAILABLE,
                                ),
                        )
                    },
                ),
                ReducibleFailureCase(
                    name = "validation unavailable",
                    kind = QualifiedPdfArchivalFailure.ValidationUnavailable,
                    level = PadesBaselineLevel.B_T,
                    timestamps = { events -> RecordingTimestampSource(events) },
                    validation = { events -> RecordingValidationSource(events, unavailable = true) },
                ),
                ReducibleFailureCase(
                    name = "archive timestamp",
                    kind = QualifiedPdfArchivalFailure.Timestamp(QualifiedPdfTimestampPhase.ARCHIVE),
                    level = PadesBaselineLevel.B_T,
                    timestamps = { events ->
                        RecordingTimestampSource(
                            events = events,
                            failurePhase = QualifiedPdfTimestampPhase.ARCHIVE,
                            failureMode = TimestampFailureMode.UNAVAILABLE,
                        )
                    },
                    validation = { events -> RecordingValidationSource(events) },
                ),
                ReducibleFailureCase(
                    name = "signature timestamp",
                    kind = QualifiedPdfArchivalFailure.Timestamp(QualifiedPdfTimestampPhase.SIGNATURE),
                    level = PadesBaselineLevel.B_B,
                    timestamps = { events ->
                        RecordingTimestampSource(
                            events = events,
                            failurePhase = QualifiedPdfTimestampPhase.SIGNATURE,
                            failureMode = TimestampFailureMode.UNAVAILABLE,
                        )
                    },
                    validation = { events -> RecordingValidationSource(events) },
                ),
            )
        val TIMESTAMP_FAILURE_CASES =
            TimestampFailureMode.entries.flatMap { mode ->
                listOf(
                    TimestampFailureCase(
                        phase = QualifiedPdfTimestampPhase.SIGNATURE,
                        mode = mode,
                        expectedEvents =
                            listOf(
                                CompletionEvent.SIGNATURE_DIGEST,
                                CompletionEvent.SIGNATURE_TIMESTAMP,
                            ),
                    ),
                    TimestampFailureCase(
                        phase = QualifiedPdfTimestampPhase.ARCHIVE,
                        mode = mode,
                        expectedEvents = EXPECTED_COMPLETION_EVENTS,
                    ),
                )
            }
    }
}
