// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.document.PdfValidationMaterial
import fi.refineid.android.document.PdfValidationMaterialLimits
import fi.refineid.android.document.QualifiedPdfTimestampSource
import fi.refineid.android.document.QualifiedPdfTimestampSourceException
import fi.refineid.android.document.QualifiedPdfValidationSource
import fi.refineid.android.document.QualifiedPdfValidationSourceException
import fi.refineid.android.document.Rfc3161TimestampException
import fi.refineid.android.document.SignerAnchorSource
import fi.refineid.android.document.TimestampTokenVerificationException
import fi.refineid.android.document.ValidationMaterialCollectionException
import fi.refineid.android.document.ValidationMaterialCollectionRequest
import fi.refineid.android.document.ValidationMaterialCollector
import fi.refineid.android.document.ValidationMaterialCollectorDependencies
import fi.refineid.android.document.VerifiedTimestampToken
import java.time.Duration

internal enum class SigningTimestampAttemptOutcome {
    SUCCESS,
    TRANSIENT_FAILURE,
    TERMINAL_FAILURE,
}

internal const val MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT = 1
internal const val MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT = 8

internal fun interface SigningTimestampAcquirer {
    /** Inputs are borrowed; the returned token transfers to the caller. */
    fun acquire(
        digest: ByteArray,
        authority: SigningTimestampAuthority,
    ): VerifiedTimestampToken
}

internal fun interface SigningTimestampRetryWait {
    @Throws(InterruptedException::class)
    fun await(delay: Duration)
}

internal object ThreadSigningTimestampRetryWait : SigningTimestampRetryWait {
    override fun await(delay: Duration) {
        Thread.sleep(delay.toMillis())
    }
}

/** Ordered TSA selection with the Apple-compatible sole-authority retry policy. */
internal class NetworkQualifiedPdfTimestampSource internal constructor(
    ownedAuthorities: List<SigningTimestampAuthority>,
    private val acquirer: SigningTimestampAcquirer,
    private val retryWait: SigningTimestampRetryWait = ThreadSigningTimestampRetryWait,
) : QualifiedPdfTimestampSource,
    AutoCloseable {
    private val ownedAuthorities = takeOwnership(ownedAuthorities)
    private var isClosed = false

    val authorityCount: Int
        get() = ownedAuthorities.size

    override fun acquire(digest: ByteArray): VerifiedTimestampToken {
        requireOpen()
        return if (ownedAuthorities.size == SOLE_AUTHORITY_COUNT) {
            acquireWithTransientRetry(digest, ownedAuthorities.single())
        } else {
            acquireFromFirstAnswer(digest)
        }
    }

    override fun close() {
        if (!isClosed) {
            ownedAuthorities.forEach(SigningTimestampAuthority::close)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NetworkQualifiedPdfTimestampSource(authorities=" + ownedAuthorities.size +
            ", closed=" + isClosed + ")"

    private fun acquireWithTransientRetry(
        digest: ByteArray,
        authority: SigningTimestampAuthority,
    ): VerifiedTimestampToken {
        var failureCount = NO_FAILURES
        while (true) {
            requireNotInterrupted()
            when (val attempt = attempt(digest, authority, FIRST_AUTHORITY_ORDINAL)) {
                is TimestampAttempt.Success -> {
                    return attempt.token
                }

                is TimestampAttempt.Failure -> {
                    if (!attempt.isTransient) {
                        throw QualifiedPdfTimestampSourceException()
                    }
                    if (failureCount < MAXIMUM_TRACKED_FAILURE_COUNT) {
                        failureCount += FAILURE_COUNT_INCREMENT
                    }
                    val delay = retryDelay(afterFailureCount = failureCount)
                    AppTrace.signingTimestampRetryScheduled(delay.seconds)
                    retryWait.await(delay)
                }
            }
        }
    }

    private fun acquireFromFirstAnswer(digest: ByteArray): VerifiedTimestampToken {
        for ((index, authority) in ownedAuthorities.withIndex()) {
            requireNotInterrupted()
            when (
                val attempt =
                    attempt(
                        digest = digest,
                        authority = authority,
                        authorityOrdinal = index + AUTHORITY_ORDINAL_OFFSET,
                    )
            ) {
                is TimestampAttempt.Success -> return attempt.token
                is TimestampAttempt.Failure -> Unit
            }
        }
        throw QualifiedPdfTimestampSourceException()
    }

    private fun attempt(
        digest: ByteArray,
        authority: SigningTimestampAuthority,
        authorityOrdinal: Int,
    ): TimestampAttempt {
        AppTrace.signingTimestampAttemptStarted(
            authorityOrdinal = authorityOrdinal,
            authorityCount = ownedAuthorities.size,
        )
        val attempt =
            try {
                TimestampAttempt.Success(acquirer.acquire(digest, authority))
            } catch (failure: SigningNetworkException) {
                TimestampAttempt.Failure(HttpSigningNetwork.isTransientAuthorityFailure(failure))
            } catch (_: TimestampAcquisitionException) {
                TimestampAttempt.Failure(isTransient = false)
            } catch (_: Rfc3161TimestampException) {
                TimestampAttempt.Failure(isTransient = false)
            } catch (_: TimestampTokenVerificationException) {
                TimestampAttempt.Failure(isTransient = false)
            } catch (_: RuntimeException) {
                TimestampAttempt.Failure(isTransient = false)
            }
        AppTrace.signingTimestampAttemptCompleted(
            authorityOrdinal = authorityOrdinal,
            outcome = attempt.outcome,
        )
        return attempt
    }

    private val TimestampAttempt.outcome: SigningTimestampAttemptOutcome
        get() =
            when (this) {
                is TimestampAttempt.Success -> {
                    SigningTimestampAttemptOutcome.SUCCESS
                }

                is TimestampAttempt.Failure -> {
                    if (isTransient) {
                        SigningTimestampAttemptOutcome.TRANSIENT_FAILURE
                    } else {
                        SigningTimestampAttemptOutcome.TERMINAL_FAILURE
                    }
                }
            }

    private fun requireOpen() {
        if (isClosed) {
            throw QualifiedPdfTimestampSourceException()
        }
    }

    @Throws(InterruptedException::class)
    private fun requireNotInterrupted() {
        if (Thread.currentThread().isInterrupted) {
            throw InterruptedException("timestamp acquisition was interrupted")
        }
    }

    private sealed interface TimestampAttempt {
        data class Success(
            val token: VerifiedTimestampToken,
        ) : TimestampAttempt

        data class Failure(
            val isTransient: Boolean,
        ) : TimestampAttempt
    }

    companion object {
        fun live(
            transport: SigningNetworkTransport,
            ownedAuthorities: List<SigningTimestampAuthority>,
            random: SigningNetworkSecureRandom = SystemSigningNetworkSecureRandom(),
            retryWait: SigningTimestampRetryWait = ThreadSigningTimestampRetryWait,
        ): NetworkQualifiedPdfTimestampSource {
            val client = Rfc3161TimestampClient(transport = transport, random = random)
            return NetworkQualifiedPdfTimestampSource(
                ownedAuthorities = ownedAuthorities,
                acquirer = SigningTimestampAcquirer(client::token),
                retryWait = retryWait,
            )
        }

        internal fun retryDelay(afterFailureCount: Int): Duration {
            require(afterFailureCount >= FIRST_FAILURE_COUNT) {
                "retry delay requires a positive failure count"
            }
            val exponent =
                (afterFailureCount - FAILURE_COUNT_TO_EXPONENT_OFFSET)
                    .coerceIn(MINIMUM_RETRY_EXPONENT, MAXIMUM_RETRY_EXPONENT)
            val seconds =
                (INITIAL_RETRY_SECONDS shl exponent).coerceAtMost(MAXIMUM_RETRY_SECONDS)
            return Duration.ofSeconds(seconds)
        }

        private fun takeOwnership(
            transferredAuthorities: List<SigningTimestampAuthority>,
        ): List<SigningTimestampAuthority> {
            if (
                transferredAuthorities.size !in
                MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT..MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT
            ) {
                transferredAuthorities.forEach(SigningTimestampAuthority::close)
                throw IllegalArgumentException("timestamp-authority count is outside its bound")
            }
            return transferredAuthorities.toList()
        }

        private const val SOLE_AUTHORITY_COUNT = MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT
        private const val FIRST_AUTHORITY_ORDINAL = 1
        private const val AUTHORITY_ORDINAL_OFFSET = 1
        private const val NO_FAILURES = 0
        private const val FAILURE_COUNT_INCREMENT = 1
        private const val FIRST_FAILURE_COUNT = 1
        private const val FAILURE_COUNT_TO_EXPONENT_OFFSET = 1
        private const val MINIMUM_RETRY_EXPONENT = 0
        private const val MAXIMUM_RETRY_EXPONENT = 6
        private const val MAXIMUM_TRACKED_FAILURE_COUNT =
            MAXIMUM_RETRY_EXPONENT + FIRST_FAILURE_COUNT
        private const val INITIAL_RETRY_SECONDS = 1L
        private const val MAXIMUM_RETRY_SECONDS = 60L
    }
}

internal fun interface SigningValidationMaterialCollector {
    fun collect(
        request: ValidationMaterialCollectionRequest,
        dependencies: ValidationMaterialCollectorDependencies,
    ): PdfValidationMaterial
}

/** Exact signer/TSA validation request backed by the bounded signing network. */
internal class NetworkQualifiedPdfValidationSource private constructor(
    private val dependencies: ValidationMaterialCollectorDependencies,
    private val ownedSignerTrustCertificates: List<ByteArray>,
    private val ownedAdditionalCandidates: List<ByteArray>,
    private val signerAnchors: SignerAnchorSource,
    private val collector: SigningValidationMaterialCollector,
) : QualifiedPdfValidationSource,
    AutoCloseable {
    private var isClosed = false

    val signerTrustCertificateCount: Int
        get() = ownedSignerTrustCertificates.size

    val additionalCandidateCount: Int
        get() = ownedAdditionalCandidates.size

    override fun collect(
        signerCertificate: ByteArray,
        signatureTimestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial {
        requireOpen()
        val anchors = cardAnchorsFor(signerCertificate)
        return try {
            collector.collect(
                request =
                    ValidationMaterialCollectionRequest(
                        signerCertificate = signerCertificate,
                        timestampTokens = listOf(signatureTimestamp),
                        signerTrustCertificates = ownedSignerTrustCertificates + anchors,
                        additionalCandidates = ownedAdditionalCandidates + anchors,
                    ),
                dependencies = dependencies,
            )
        } catch (failure: ValidationMaterialCollectionException) {
            throw failure
        } catch (_: SigningNetworkException) {
            throw QualifiedPdfValidationSourceException()
        } catch (_: RuntimeException) {
            throw QualifiedPdfValidationSourceException()
        } finally {
            anchors.clearBytes()
        }
    }

    /**
     * The signer's card chain, within what the request admits: the anchors
     * that fit beside the configured certificates, each within the size bound.
     */
    private fun cardAnchorsFor(signerCertificate: ByteArray): List<ByteArray> {
        val supplied =
            try {
                signerAnchors.copyAnchorsFor(signerCertificate)
            } catch (_: RuntimeException) {
                emptyList()
            }
        val room =
            (
                PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT -
                    maxOf(ownedSignerTrustCertificates.size, ownedAdditionalCandidates.size)
            ).coerceAtLeast(NO_ROOM)
        val kept = mutableListOf<ByteArray>()
        for (anchor in supplied) {
            if (kept.size < room &&
                anchor.isNotEmpty() &&
                anchor.size <= PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
            ) {
                kept += anchor
            } else {
                anchor.fill(CLEARED_BYTE)
            }
        }
        return kept
    }

    override fun close() {
        if (!isClosed) {
            ownedSignerTrustCertificates.clearBytes()
            ownedAdditionalCandidates.clearBytes()
            isClosed = true
        }
    }

    override fun toString(): String =
        "NetworkQualifiedPdfValidationSource(trustCertificates=" +
            ownedSignerTrustCertificates.size +
            ", additionalCandidates=" + ownedAdditionalCandidates.size +
            ", closed=" + isClosed + ")"

    private fun requireOpen() {
        if (isClosed) {
            throw QualifiedPdfValidationSourceException()
        }
    }

    private fun List<ByteArray>.clearBytes() {
        forEach { value -> value.fill(CLEARED_BYTE) }
    }

    companion object {
        fun copyOf(
            dependencies: ValidationMaterialCollectorDependencies,
            signerTrustCertificates: List<ByteArray>,
            additionalCandidates: List<ByteArray>,
            signerAnchors: SignerAnchorSource = SignerAnchorSource.NONE,
            collector: SigningValidationMaterialCollector =
                SigningValidationMaterialCollector(ValidationMaterialCollector::collect),
        ): NetworkQualifiedPdfValidationSource {
            require(
                signerTrustCertificates.isNotEmpty() &&
                    certificatesAreValid(signerTrustCertificates) &&
                    certificatesAreValid(additionalCandidates),
            ) {
                "qualified-PDF validation trust is invalid"
            }
            return NetworkQualifiedPdfValidationSource(
                dependencies = dependencies,
                ownedSignerTrustCertificates = signerTrustCertificates.map(ByteArray::copyOf),
                ownedAdditionalCandidates = additionalCandidates.map(ByteArray::copyOf),
                signerAnchors = signerAnchors,
                collector = collector,
            )
        }

        private fun certificatesAreValid(certificates: List<ByteArray>): Boolean =
            certificates.size <= PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT &&
                certificates.all { certificate ->
                    certificate.isNotEmpty() &&
                        certificate.size <= PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
                }

        private const val CLEARED_BYTE: Byte = 0
        private const val NO_ROOM = 0
    }
}
