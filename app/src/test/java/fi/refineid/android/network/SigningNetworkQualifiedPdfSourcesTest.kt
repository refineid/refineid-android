package fi.refineid.android.network

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import fi.refineid.android.document.DerEncoder
import fi.refineid.android.document.PdfValidationMaterial
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import fi.refineid.android.document.QualifiedPdfValidationSourceException
import fi.refineid.android.document.Rfc3161TimestampException
import fi.refineid.android.document.Rfc3161TimestampFailure
import fi.refineid.android.document.SignerAnchorSource
import fi.refineid.android.document.ValidationMaterialCollectionException
import fi.refineid.android.document.ValidationMaterialCollectionFailure
import fi.refineid.android.document.ValidationMaterialCollectorDependencies
import fi.refineid.android.document.ValidationMaterialGetResource
import fi.refineid.android.document.ValidationMaterialGetter
import fi.refineid.android.document.ValidationMaterialPoster
import fi.refineid.android.document.ValidationPathRole
import fi.refineid.android.document.ValidationSecureRandom
import fi.refineid.android.document.VerifiedTimestampCertificatePath
import fi.refineid.android.document.VerifiedTimestampToken
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration
import java.time.Instant

class SigningNetworkQualifiedPdfSourcesTest {
    @Test
    fun soleAuthorityRetriesOnlyTransientFailuresWithTheCappedSchedule() {
        val authority = authority(SOLE_AUTHORITY_MARKER)
        var attempts = NO_ATTEMPTS
        val waits = mutableListOf<Duration>()
        val source =
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = listOf(authority),
                acquirer =
                    SigningTimestampAcquirer { digest, observedAuthority ->
                        attempts += ATTEMPT_COUNT_INCREMENT
                        assertSame(authority, observedAuthority)
                        if (attempts <= TRANSIENT_FAILURE_COUNT) {
                            throw SigningNetworkException(SigningNetworkFailure.TRANSIENT_TRANSPORT)
                        }
                        verifiedToken(digest)
                    },
                retryWait = SigningTimestampRetryWait { delay -> waits += delay },
            )

        val token = source.acquire(SYNTHETIC_DIGEST)
        try {
            assertTrue(token.matchesMessageImprint(SYNTHETIC_DIGEST))
            assertEquals(TRANSIENT_FAILURE_COUNT + SUCCESSFUL_ATTEMPT_COUNT, attempts)
            assertEquals(EXPECTED_RETRY_DELAYS, waits)
        } finally {
            token.close()
            source.close()
        }

        assertAuthorityClosed(authority)
        assertFalse(source.toString().contains(SOLE_AUTHORITY_ADDRESS))
    }

    @Test
    fun multipleAuthoritiesAreTriedOnceInOrderWithoutWaiting() {
        val first = authority(FIRST_AUTHORITY_MARKER)
        val second = authority(SECOND_AUTHORITY_MARKER)
        val third = authority(THIRD_AUTHORITY_MARKER)
        val observed = mutableListOf<SigningTimestampAuthority>()
        var waitCount = NO_WAITS
        val source =
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = listOf(first, second, third),
                acquirer =
                    SigningTimestampAcquirer { digest, authority ->
                        observed += authority
                        when (authority) {
                            first -> {
                                throw SigningNetworkException(SigningNetworkFailure.TRANSIENT_TRANSPORT)
                            }

                            second -> {
                                throw Rfc3161TimestampException(Rfc3161TimestampFailure.REJECTED, REJECTION_STATUS)
                            }

                            third -> {
                                verifiedToken(digest)
                            }

                            else -> {
                                error("unexpected timestamp authority")
                            }
                        }
                    },
                retryWait = SigningTimestampRetryWait { waitCount += WAIT_COUNT_INCREMENT },
            )

        source.acquire(SYNTHETIC_DIGEST).close()
        source.close()

        assertEquals(listOf(first, second, third), observed)
        assertEquals(NO_WAITS, waitCount)
        listOf(first, second, third).forEach(::assertAuthorityClosed)
    }

    @Test
    fun timestampSourceOwnsTheTransferredAuthorityListStructure() {
        val first = authority(FIRST_AUTHORITY_MARKER)
        val second = authority(SECOND_AUTHORITY_MARKER)
        val transferredAuthorities = mutableListOf(first, second)
        val source =
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = transferredAuthorities,
                acquirer = SigningTimestampAcquirer { digest, _ -> verifiedToken(digest) },
            )

        transferredAuthorities.clear()

        assertEquals(EXPECTED_OWNED_AUTHORITY_COUNT, source.authorityCount)
        source.close()
        assertAuthorityClosed(first)
        assertAuthorityClosed(second)
    }

    @Test
    fun invalidAuthorityCountClosesEveryTransferredAuthority() {
        val transferredAuthorities =
            List(MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT + COUNT_INCREMENT) {
                authority(EXCESS_AUTHORITY_MARKER)
            }

        assertThrows(IllegalArgumentException::class.java) {
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = transferredAuthorities,
                acquirer = SigningTimestampAcquirer { digest, _ -> verifiedToken(digest) },
            )
        }
        transferredAuthorities.forEach(::assertAuthorityClosed)
    }

    @Test
    fun terminalFailureDoesNotRetryAndInterruptedWaitEscapes() {
        val terminalAuthority = authority(TERMINAL_AUTHORITY_MARKER)
        var terminalWaitCount = NO_WAITS
        val terminalSource =
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = listOf(terminalAuthority),
                acquirer =
                    SigningTimestampAcquirer { _, _ ->
                        throw Rfc3161TimestampException(Rfc3161TimestampFailure.RESPONSE_UNUSABLE)
                    },
                retryWait = SigningTimestampRetryWait { terminalWaitCount += WAIT_COUNT_INCREMENT },
            )

        assertThrows(QualifiedPdfTimestampSourceException::class.java) {
            terminalSource.acquire(SYNTHETIC_DIGEST).close()
        }
        assertEquals(NO_WAITS, terminalWaitCount)
        terminalSource.close()

        val interruptedAuthority = authority(INTERRUPTED_AUTHORITY_MARKER)
        val interruptedSource =
            NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = listOf(interruptedAuthority),
                acquirer =
                    SigningTimestampAcquirer { _, _ ->
                        throw SigningNetworkException(SigningNetworkFailure.TRANSIENT_TRANSPORT)
                    },
                retryWait = SigningTimestampRetryWait { throw InterruptedException() },
            )

        assertThrows(InterruptedException::class.java) {
            interruptedSource.acquire(SYNTHETIC_DIGEST).close()
        }
        interruptedSource.close()
    }

    @Test
    fun validationSourceCopiesExactTrustAndClearsItWhenClosed() {
        val signerTrust = byteArrayOf(SIGNER_TRUST_MARKER)
        val additionalCandidate = byteArrayOf(ADDITIONAL_CANDIDATE_MARKER)
        var capturedRequest: fi.refineid.android.document.ValidationMaterialCollectionRequest? = null
        val source =
            NetworkQualifiedPdfValidationSource.copyOf(
                dependencies = UNUSED_VALIDATION_DEPENDENCIES,
                signerTrustCertificates = listOf(signerTrust),
                additionalCandidates = listOf(additionalCandidate),
                collector =
                    SigningValidationMaterialCollector { request, _ ->
                        capturedRequest = request
                        PdfValidationMaterial.copyOf(emptyList(), emptyList(), emptyList())
                    },
            )
        signerTrust.fill(CLEARED_BYTE)
        additionalCandidate.fill(CLEARED_BYTE)
        val signerCertificate = SYNTHETIC_SIGNER_CERTIFICATE.copyOf()
        val timestamp = verifiedToken(SYNTHETIC_DIGEST)
        val material = source.collect(signerCertificate, timestamp)
        val request = checkNotNull(capturedRequest)
        try {
            assertSame(signerCertificate, request.signerCertificate)
            assertSame(timestamp, request.timestampTokens.single())
            assertArrayEquals(
                byteArrayOf(SIGNER_TRUST_MARKER),
                request.signerTrustCertificates.single(),
            )
            assertArrayEquals(
                byteArrayOf(ADDITIONAL_CANDIDATE_MARKER),
                request.additionalCandidates.single(),
            )
        } finally {
            material.close()
            timestamp.close()
            source.close()
            signerCertificate.fill(CLEARED_BYTE)
        }

        assertAllZero(request.signerTrustCertificates.single())
        assertAllZero(request.additionalCandidates.single())
        val closedSourceTimestamp = verifiedToken(SYNTHETIC_DIGEST)
        try {
            assertThrows(QualifiedPdfValidationSourceException::class.java) {
                source.collect(SYNTHETIC_SIGNER_CERTIFICATE, closedSourceTimestamp).close()
            }
        } finally {
            closedSourceTimestamp.close()
        }
    }

    @Test
    fun theSignerCardChainAnchorsTheCollectionBesideTheConfiguredTrust() {
        val anchor = byteArrayOf(CARD_ANCHOR_MARKER)
        var askedFor: ByteArray? = null
        var trustSeen: List<List<Byte>> = emptyList()
        var candidatesSeen: List<List<Byte>> = emptyList()
        val source =
            NetworkQualifiedPdfValidationSource.copyOf(
                dependencies = UNUSED_VALIDATION_DEPENDENCIES,
                signerTrustCertificates = listOf(byteArrayOf(SIGNER_TRUST_MARKER)),
                additionalCandidates = listOf(byteArrayOf(ADDITIONAL_CANDIDATE_MARKER)),
                signerAnchors =
                    SignerAnchorSource { signer ->
                        askedFor = signer
                        listOf(anchor)
                    },
                collector =
                    SigningValidationMaterialCollector { request, _ ->
                        trustSeen = request.signerTrustCertificates.map(ByteArray::toList)
                        candidatesSeen = request.additionalCandidates.map(ByteArray::toList)
                        PdfValidationMaterial.copyOf(emptyList(), emptyList(), emptyList())
                    },
            )
        val signerCertificate = SYNTHETIC_SIGNER_CERTIFICATE.copyOf()
        val timestamp = verifiedToken(SYNTHETIC_DIGEST)
        try {
            source.collect(signerCertificate, timestamp).close()
            assertSame(signerCertificate, askedFor)
            assertEquals(listOf(listOf(SIGNER_TRUST_MARKER), listOf(CARD_ANCHOR_MARKER)), trustSeen)
            assertEquals(listOf(listOf(ADDITIONAL_CANDIDATE_MARKER), listOf(CARD_ANCHOR_MARKER)), candidatesSeen)
            assertAllZero(anchor)
        } finally {
            timestamp.close()
            source.close()
            signerCertificate.fill(CLEARED_BYTE)
        }
    }

    @Test
    fun validationSourcePreservesTypedFailureAndCoarsensNetworkFailure() {
        val typed =
            ValidationMaterialCollectionException(
                kind = ValidationMaterialCollectionFailure.REVOKED,
                pathRole = ValidationPathRole.DOCUMENT_SIGNER,
            )
        val typedSource = validationSourceThrowing(typed)
        val timestamp = verifiedToken(SYNTHETIC_DIGEST)
        try {
            val observed =
                assertThrows(ValidationMaterialCollectionException::class.java) {
                    typedSource.collect(SYNTHETIC_SIGNER_CERTIFICATE, timestamp).close()
                }
            assertSame(typed, observed)
        } finally {
            typedSource.close()
            timestamp.close()
        }

        val networkSource =
            validationSourceThrowing(SigningNetworkException(SigningNetworkFailure.TRANSPORT))
        val networkTimestamp = verifiedToken(SYNTHETIC_DIGEST)
        try {
            assertThrows(QualifiedPdfValidationSourceException::class.java) {
                networkSource.collect(SYNTHETIC_SIGNER_CERTIFICATE, networkTimestamp).close()
            }
        } finally {
            networkSource.close()
            networkTimestamp.close()
        }
    }

    private fun authority(marker: Byte): SigningTimestampAuthority =
        SigningTimestampAuthority.copyOf(
            address = SOLE_AUTHORITY_ADDRESS,
            trustedCertificates = listOf(byteArrayOf(marker)),
        )

    private fun assertAuthorityClosed(authority: SigningTimestampAuthority) {
        val failure =
            assertThrows(TimestampAcquisitionException::class.java) {
                authority.copyTrustedCertificates().forEach { certificate ->
                    certificate.fill(CLEARED_BYTE)
                }
            }
        assertEquals(TimestampAcquisitionFailure.AUTHORITY_CLOSED, failure.kind)
    }

    private fun validationSourceThrowing(failure: Exception): NetworkQualifiedPdfValidationSource =
        NetworkQualifiedPdfValidationSource.copyOf(
            dependencies = UNUSED_VALIDATION_DEPENDENCIES,
            signerTrustCertificates = listOf(byteArrayOf(SIGNER_TRUST_MARKER)),
            additionalCandidates = emptyList(),
            collector = SigningValidationMaterialCollector { _, _ -> throw failure },
        )

    private fun verifiedToken(digest: ByteArray): VerifiedTimestampToken =
        VerifiedTimestampToken(
            ownedEncoding = SYNTHETIC_TIMESTAMP_ENCODING.copyOf(),
            ownedMessageImprint = digest.copyOf(),
            ownedSignerCertificate = SYNTHETIC_TIMESTAMP_CERTIFICATE.copyOf(),
            ownedEmbeddedCertificates = emptyList(),
            ownedCertificatePath =
                VerifiedTimestampCertificatePath(
                    ownedCertificates = emptyList(),
                    ownedTrustAnchor = SYNTHETIC_TIMESTAMP_TRUST.copyOf(),
                ),
            generatedAt = TIMESTAMP_GENERATION_TIME,
        )

    private fun assertAllZero(bytes: ByteArray) {
        assertTrue(bytes.all { byte -> byte == CLEARED_BYTE })
    }

    private companion object {
        const val NO_ATTEMPTS = 0
        const val ATTEMPT_COUNT_INCREMENT = 1
        const val COUNT_INCREMENT = 1
        const val TRANSIENT_FAILURE_COUNT = 8
        const val SUCCESSFUL_ATTEMPT_COUNT = 1
        const val EXPECTED_OWNED_AUTHORITY_COUNT = 2
        const val NO_WAITS = 0
        const val WAIT_COUNT_INCREMENT = 1
        const val REJECTION_STATUS = 2L
        const val SOLE_AUTHORITY_MARKER: Byte = 0x31
        const val FIRST_AUTHORITY_MARKER: Byte = 0x32
        const val SECOND_AUTHORITY_MARKER: Byte = 0x33
        const val THIRD_AUTHORITY_MARKER: Byte = 0x34
        const val TERMINAL_AUTHORITY_MARKER: Byte = 0x35
        const val INTERRUPTED_AUTHORITY_MARKER: Byte = 0x36
        const val EXCESS_AUTHORITY_MARKER: Byte = 0x37
        const val SIGNER_TRUST_MARKER: Byte = 0x41
        const val ADDITIONAL_CANDIDATE_MARKER: Byte = 0x42
        const val CARD_ANCHOR_MARKER: Byte = 0x43
        const val SYNTHETIC_DIGEST_FILL: Byte = 0x51
        const val SYNTHETIC_TIMESTAMP_CERTIFICATE_MARKER: Byte = 0x52
        const val SYNTHETIC_TIMESTAMP_TRUST_MARKER: Byte = 0x53
        const val SYNTHETIC_SIGNER_CERTIFICATE_MARKER: Byte = 0x54
        const val SYNTHETIC_TIMESTAMP_TOKEN_VALUE = 1
        const val FIRST_RETRY_SECONDS = 1L
        const val SECOND_RETRY_SECONDS = 2L
        const val THIRD_RETRY_SECONDS = 4L
        const val FOURTH_RETRY_SECONDS = 8L
        const val FIFTH_RETRY_SECONDS = 16L
        const val SIXTH_RETRY_SECONDS = 32L
        const val CAPPED_RETRY_SECONDS = 60L
        const val CLEARED_BYTE: Byte = 0
        const val SOLE_AUTHORITY_ADDRESS = "https://timestamp.example"
        val SYNTHETIC_DIGEST = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_FILL }
        val SYNTHETIC_TIMESTAMP_CERTIFICATE =
            byteArrayOf(SYNTHETIC_TIMESTAMP_CERTIFICATE_MARKER)
        val SYNTHETIC_TIMESTAMP_TRUST = byteArrayOf(SYNTHETIC_TIMESTAMP_TRUST_MARKER)
        val SYNTHETIC_SIGNER_CERTIFICATE = byteArrayOf(SYNTHETIC_SIGNER_CERTIFICATE_MARKER)
        val SYNTHETIC_TIMESTAMP_ENCODING =
            DerEncoder.sequence(listOf(DerEncoder.integer(SYNTHETIC_TIMESTAMP_TOKEN_VALUE)))
        val TIMESTAMP_GENERATION_TIME: Instant = Instant.parse("2026-08-16T13:00:00Z")
        val EXPECTED_RETRY_DELAYS =
            listOf(
                Duration.ofSeconds(FIRST_RETRY_SECONDS),
                Duration.ofSeconds(SECOND_RETRY_SECONDS),
                Duration.ofSeconds(THIRD_RETRY_SECONDS),
                Duration.ofSeconds(FOURTH_RETRY_SECONDS),
                Duration.ofSeconds(FIFTH_RETRY_SECONDS),
                Duration.ofSeconds(SIXTH_RETRY_SECONDS),
                Duration.ofSeconds(CAPPED_RETRY_SECONDS),
                Duration.ofSeconds(CAPPED_RETRY_SECONDS),
            )
        val UNUSED_VALIDATION_DEPENDENCIES =
            ValidationMaterialCollectorDependencies(
                get =
                    ValidationMaterialGetter { _, _: ValidationMaterialGetResource ->
                        error("validation GET was not expected")
                    },
                post =
                    ValidationMaterialPoster { _, _, _ ->
                        error("validation POST was not expected")
                    },
                now = { TIMESTAMP_GENERATION_TIME },
                random = ValidationSecureRandom { byteCount -> ByteArray(byteCount) },
            )
    }
}
