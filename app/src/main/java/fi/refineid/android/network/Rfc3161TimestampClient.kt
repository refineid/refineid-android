// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.document.PdfValidationMaterialLimits
import fi.refineid.android.document.Rfc3161Timestamp
import fi.refineid.android.document.TimestampTokenVerifier
import fi.refineid.android.document.VerifiedTimestampToken

internal enum class TimestampAcquisitionFailure {
    AUTHORITY_CLOSED,
    RANDOM_UNAVAILABLE,
}

internal class TimestampAcquisitionException(
    val kind: TimestampAcquisitionFailure,
) : Exception(kind.name)

internal enum class SigningTimestampTrust {
    EXPLICIT_CERTIFICATES,
    TRUSTED_LISTS,
}

/** Owned timestamp-authority trust and optional Basic credentials. */
internal class SigningTimestampAuthority private constructor(
    val address: String,
    val trust: SigningTimestampTrust,
    private val ownedTrustedCertificates: List<ByteArray>,
    private val credentials: SigningNetworkBasicCredentials?,
) : AutoCloseable {
    private var isClosed = false

    val trustedCertificateCount: Int
        get() = ownedTrustedCertificates.size

    val hasCredentials: Boolean
        get() = credentials != null

    fun copyTrustedCertificates(): List<ByteArray> {
        requireOpen()
        return ownedTrustedCertificates.map(ByteArray::copyOf)
    }

    fun credentials(): SigningNetworkBasicCredentials? {
        requireOpen()
        return credentials
    }

    override fun close() {
        if (!isClosed) {
            ownedTrustedCertificates.forEach { certificate -> certificate.fill(CLEARED_BYTE) }
            credentials?.close()
            isClosed = true
        }
    }

    override fun toString(): String =
        "SigningTimestampAuthority(trust=$trust, trustedCertificates=$trustedCertificateCount, " +
            "credentials=$hasCredentials, closed=$isClosed)"

    private fun requireOpen() {
        if (isClosed) {
            throw TimestampAcquisitionException(TimestampAcquisitionFailure.AUTHORITY_CLOSED)
        }
    }

    companion object {
        fun copyOf(
            address: String,
            trustedCertificates: List<ByteArray>,
            username: String? = null,
            password: CharArray? = null,
        ): SigningTimestampAuthority {
            if (
                addressIsInvalid(address, carriesCredentials = username != null) ||
                trustedCertificatesAreInvalid(trustedCertificates) ||
                credentialsAreIncomplete(username, password)
            ) {
                throw IllegalArgumentException("invalid timestamp-authority configuration")
            }
            return SigningTimestampAuthority(
                address = address,
                trust = SigningTimestampTrust.EXPLICIT_CERTIFICATES,
                ownedTrustedCertificates = trustedCertificates.map(ByteArray::copyOf),
                credentials = credentials(username, password),
            )
        }

        /** A holder-configured endpoint whose tokens require EU trusted-list anchors. */
        fun configured(
            address: String,
            username: String? = null,
            password: CharArray? = null,
        ): SigningTimestampAuthority {
            if (
                addressIsInvalid(address, carriesCredentials = username != null) ||
                credentialsAreIncomplete(username, password)
            ) {
                throw IllegalArgumentException("invalid timestamp-authority configuration")
            }
            return SigningTimestampAuthority(
                address = address,
                trust = SigningTimestampTrust.TRUSTED_LISTS,
                ownedTrustedCertificates = emptyList(),
                credentials = credentials(username, password),
            )
        }

        private fun credentials(
            username: String?,
            password: CharArray?,
        ): SigningNetworkBasicCredentials? =
            if (username == null || password == null) {
                null
            } else {
                SigningNetworkBasicCredentials.copyOf(username, password)
            }

        private fun addressIsInvalid(
            address: String,
            carriesCredentials: Boolean,
        ): Boolean =
            try {
                val uri = SigningNetworkPolicy.httpUri(address, SigningNetworkEndpoint.AUTHORITY)
                carriesCredentials && uri.scheme.lowercase() != HTTPS_SCHEME
            } catch (_: SigningNetworkException) {
                true
            }

        private fun trustedCertificatesAreInvalid(certificates: List<ByteArray>): Boolean =
            certificates.isEmpty() ||
                certificates.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_COUNT ||
                certificates.any { certificate ->
                    certificate.isEmpty() ||
                        certificate.size > PdfValidationMaterialLimits.MAXIMUM_CERTIFICATE_BYTES
                }

        private fun credentialsAreIncomplete(
            username: String?,
            password: CharArray?,
        ): Boolean = (username == null) != (password == null)

        private const val CLEARED_BYTE: Byte = 0
        private const val HTTPS_SCHEME = "https"
    }
}

/** Acquires and authenticates one request-bound RFC 3161 SHA-384 token. */
internal class Rfc3161TimestampClient(
    private val transport: SigningNetworkTransport,
    private val random: SigningNetworkSecureRandom = SystemSigningNetworkSecureRandom(),
    private val anchors: TimestampAnchorSource = TrustedListTimestampAnchors(transport),
) {
    fun token(
        digest: ByteArray,
        authority: SigningTimestampAuthority,
    ): VerifiedTimestampToken {
        val ownedDigest = digest.copyOf()
        var nonce: ByteArray? = null
        var request: ByteArray? = null
        var response: ByteArray? = null
        var trustedCertificates: List<ByteArray>? = null
        try {
            val generatedNonce = randomNonce()
            nonce = generatedNonce
            request = Rfc3161Timestamp.request(digest = ownedDigest, nonce = generatedNonce)
            response =
                transport.post(
                    body = request,
                    address = authority.address,
                    contentType = TIMESTAMP_REQUEST_CONTENT_TYPE,
                    credentials = authority.credentials(),
                    maximumResponseBytes = SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            val unverified =
                Rfc3161Timestamp.token(
                    response = response,
                    digest = ownedDigest,
                    nonce = generatedNonce,
                )
            return unverified.use {
                trustedCertificates =
                    when (authority.trust) {
                        SigningTimestampTrust.EXPLICIT_CERTIFICATES -> authority.copyTrustedCertificates()
                        SigningTimestampTrust.TRUSTED_LISTS -> anchors.copyAnchorsAt(unverified.generatedAt)
                    }
                TimestampTokenVerifier.verify(
                    token = unverified,
                    trustedCertificates = checkNotNull(trustedCertificates),
                )
            }
        } finally {
            ownedDigest.fill(CLEARED_BYTE)
            nonce?.fill(CLEARED_BYTE)
            request?.fill(CLEARED_BYTE)
            response?.fill(CLEARED_BYTE)
            trustedCertificates?.forEach { certificate -> certificate.fill(CLEARED_BYTE) }
        }
    }

    private fun randomNonce(): ByteArray {
        val nonce =
            try {
                random.generate(TIMESTAMP_NONCE_BYTE_COUNT)
            } catch (_: Exception) {
                throw TimestampAcquisitionException(TimestampAcquisitionFailure.RANDOM_UNAVAILABLE)
            }
        if (nonce.size != TIMESTAMP_NONCE_BYTE_COUNT) {
            nonce.fill(CLEARED_BYTE)
            throw TimestampAcquisitionException(TimestampAcquisitionFailure.RANDOM_UNAVAILABLE)
        }
        return nonce
    }

    private companion object {
        const val TIMESTAMP_REQUEST_CONTENT_TYPE = "application/timestamp-query"
        const val TIMESTAMP_NONCE_BYTE_COUNT = 32
        const val CLEARED_BYTE: Byte = 0
    }
}
