// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import fi.refineid.android.document.Rfc3161TimestampException
import fi.refineid.android.document.Rfc3161TimestampFailure
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class Rfc3161TimestampClientTest {
    @Test
    fun dispatchesOneBoundedRequestAndClearsTransferredWorkingBytes() {
        val transport = RecordingTimestampTransport()
        val random = RecordingRandom(EXACT_NONCE.copyOf())
        val authority =
            SigningTimestampAuthority.copyOf(
                address = TIMESTAMP_ADDRESS,
                trustedCertificates = listOf(SYNTHETIC_TRUST_CERTIFICATE),
            )
        val digest = SYNTHETIC_DIGEST.copyOf()
        try {
            val failure =
                assertThrows(Rfc3161TimestampException::class.java) {
                    Rfc3161TimestampClient(transport = transport, random = random).token(digest, authority)
                }

            assertEquals(Rfc3161TimestampFailure.RESPONSE_MALFORMED, failure.kind)
            assertEquals(TIMESTAMP_ADDRESS, transport.address)
            assertEquals(TIMESTAMP_REQUEST_CONTENT_TYPE, transport.contentType)
            assertEquals(SigningNetworkLimits.MAXIMUM_SHORT_RESPONSE_BYTES, transport.maximumResponseBytes)
            assertEquals(SigningNetworkEndpoint.AUTHORITY, transport.endpoint)
            assertFalse(transport.carriesCredentials)
            assertTrue(checkNotNull(transport.borrowedRequest).all { byte -> byte == CLEARED_BYTE })
            assertTrue(transport.transferredResponse.all { byte -> byte == CLEARED_BYTE })
            assertTrue(random.transferredNonce.all { byte -> byte == CLEARED_BYTE })
            assertArrayEquals(SYNTHETIC_DIGEST, digest)
        } finally {
            authority.close()
        }
    }

    @Test
    fun refusesWrongLengthRandomWithoutCallingTheAuthority() {
        val wrongLengthNonce = ByteArray(WRONG_NONCE_BYTE_COUNT) { SYNTHETIC_NONCE_BYTE }
        val transport = RecordingTimestampTransport()
        val authority =
            SigningTimestampAuthority.copyOf(
                address = TIMESTAMP_ADDRESS,
                trustedCertificates = listOf(SYNTHETIC_TRUST_CERTIFICATE),
            )
        try {
            val failure =
                assertThrows(TimestampAcquisitionException::class.java) {
                    Rfc3161TimestampClient(
                        transport = transport,
                        random = RecordingRandom(wrongLengthNonce),
                    ).token(SYNTHETIC_DIGEST, authority)
                }

            assertEquals(TimestampAcquisitionFailure.RANDOM_UNAVAILABLE, failure.kind)
            assertEquals(NO_TRANSPORT_CALLS, transport.callCount)
            assertTrue(wrongLengthNonce.all { byte -> byte == CLEARED_BYTE })
        } finally {
            authority.close()
        }
    }

    @Test
    fun authorityOwnsItsConfigurationAndFailsClosedAfterClearing() {
        val inputCertificate = SYNTHETIC_TRUST_CERTIFICATE.copyOf()
        val inputPassword = SYNTHETIC_PASSWORD.copyOf()
        val authority =
            SigningTimestampAuthority.copyOf(
                address = TIMESTAMP_ADDRESS,
                trustedCertificates = listOf(inputCertificate),
                username = SYNTHETIC_USERNAME,
                password = inputPassword,
            )
        inputCertificate[FIRST_BYTE_INDEX] = CHANGED_BYTE
        inputPassword[FIRST_CHARACTER_INDEX] = CHANGED_CHARACTER

        val ownedCertificate = authority.copyTrustedCertificates().single()
        val authorization = checkNotNull(authority.credentials()).authorizationHeader()
        assertEquals(SigningTimestampTrust.EXPLICIT_CERTIFICATES, authority.trust)
        assertArrayEquals(SYNTHETIC_TRUST_CERTIFICATE, ownedCertificate)
        assertEquals(SYNTHETIC_AUTHORIZATION_HEADER, authorization)
        assertFalse(authority.toString().contains(SYNTHETIC_PASSWORD.concatToString()))

        authority.close()

        val failure =
            assertThrows(TimestampAcquisitionException::class.java) {
                authority.copyTrustedCertificates()
            }
        assertEquals(TimestampAcquisitionFailure.AUTHORITY_CLOSED, failure.kind)
    }

    @Test
    fun configuredAuthorityOwnsCredentialsAndRequiresTrustedLists() {
        val password = SYNTHETIC_PASSWORD.copyOf()
        val authority =
            SigningTimestampAuthority.configured(
                address = TIMESTAMP_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = password,
            )
        password[FIRST_CHARACTER_INDEX] = CHANGED_CHARACTER

        assertEquals(SigningTimestampTrust.TRUSTED_LISTS, authority.trust)
        assertEquals(NO_TRUST_CERTIFICATES, authority.trustedCertificateCount)
        assertTrue(authority.copyTrustedCertificates().isEmpty())
        assertEquals(
            SYNTHETIC_AUTHORIZATION_HEADER,
            checkNotNull(authority.credentials()).authorizationHeader(),
        )
        assertFalse(authority.toString().contains(TIMESTAMP_ADDRESS))
        assertFalse(authority.toString().contains(SYNTHETIC_PASSWORD.concatToString()))

        authority.close()
    }

    @Test
    fun authorityConfigurationRejectsUnusableAddressesBeforeNetworkAccess() {
        for (address in UNUSABLE_TIMESTAMP_ADDRESSES) {
            assertThrows(IllegalArgumentException::class.java) {
                SigningTimestampAuthority.configured(address)
            }
            assertThrows(IllegalArgumentException::class.java) {
                SigningTimestampAuthority.copyOf(
                    address = address,
                    trustedCertificates = listOf(SYNTHETIC_TRUST_CERTIFICATE),
                )
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            SigningTimestampAuthority.configured(
                address = PLAIN_TIMESTAMP_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = SYNTHETIC_PASSWORD,
            )
        }
    }

    private class RecordingRandom(
        val transferredNonce: ByteArray,
    ) : SigningNetworkSecureRandom {
        override fun generate(byteCount: Int): ByteArray = transferredNonce
    }

    private class RecordingTimestampTransport : SigningNetworkTransport {
        var callCount = NO_TRANSPORT_CALLS
        var borrowedRequest: ByteArray? = null
        var address: String? = null
        var contentType: String? = null
        var maximumResponseBytes: Int? = null
        var endpoint: SigningNetworkEndpoint? = null
        var carriesCredentials = false
        val transferredResponse = MALFORMED_TIMESTAMP_RESPONSE.copyOf()

        override fun get(
            address: String,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray = throw AssertionError("timestamp client must not GET")

        override fun post(
            body: ByteArray,
            address: String,
            contentType: String,
            credentials: SigningNetworkBasicCredentials?,
            maximumResponseBytes: Int,
            endpoint: SigningNetworkEndpoint,
        ): ByteArray {
            callCount += SINGLE_TRANSPORT_CALL
            borrowedRequest = body
            this.address = address
            this.contentType = contentType
            this.maximumResponseBytes = maximumResponseBytes
            this.endpoint = endpoint
            carriesCredentials = credentials != null
            return transferredResponse
        }

        override fun toString(): String = "RecordingTimestampTransport(body=[redacted], response=[redacted])"
    }

    private companion object {
        const val TIMESTAMP_ADDRESS = "https://tsa.example/timestamp"
        const val PLAIN_TIMESTAMP_ADDRESS = "http://tsa.example/timestamp"
        const val TIMESTAMP_REQUEST_CONTENT_TYPE = "application/timestamp-query"
        const val SYNTHETIC_USERNAME = "synthetic-user"
        val SYNTHETIC_AUTHORIZATION_HEADER =
            "Basic " + Base64.getEncoder().encodeToString("$SYNTHETIC_USERNAME:synthetic-password".toByteArray())
        const val EXACT_NONCE_BYTE_COUNT = 32
        const val WRONG_NONCE_BYTE_COUNT = EXACT_NONCE_BYTE_COUNT - 1
        const val NO_TRANSPORT_CALLS = 0
        const val SINGLE_TRANSPORT_CALL = 1
        const val NO_TRUST_CERTIFICATES = 0
        const val FIRST_BYTE_INDEX = 0
        const val FIRST_CHARACTER_INDEX = 0
        const val SYNTHETIC_DIGEST_BYTE: Byte = 0x31
        const val SYNTHETIC_NONCE_BYTE: Byte = 0x5A
        const val SYNTHETIC_CERTIFICATE_BYTE: Byte = 0x41
        const val MALFORMED_TIMESTAMP_RESPONSE_BYTE: Byte = 0x01
        const val CHANGED_BYTE: Byte = 0x7F
        const val CHANGED_CHARACTER = 'X'
        const val CLEARED_BYTE: Byte = 0
        val SYNTHETIC_DIGEST = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_BYTE }
        val EXACT_NONCE = ByteArray(EXACT_NONCE_BYTE_COUNT) { SYNTHETIC_NONCE_BYTE }
        val SYNTHETIC_TRUST_CERTIFICATE = byteArrayOf(SYNTHETIC_CERTIFICATE_BYTE)
        val SYNTHETIC_PASSWORD = "synthetic-password".toCharArray()
        val MALFORMED_TIMESTAMP_RESPONSE = byteArrayOf(MALFORMED_TIMESTAMP_RESPONSE_BYTE)
        val UNUSABLE_TIMESTAMP_ADDRESSES =
            listOf(
                EMPTY_TIMESTAMP_ADDRESS,
                SCHEMELESS_TIMESTAMP_ADDRESS,
                UNSUPPORTED_SCHEME_TIMESTAMP_ADDRESS,
                USER_INFORMATION_TIMESTAMP_ADDRESS,
            )
        const val EMPTY_TIMESTAMP_ADDRESS = ""
        const val SCHEMELESS_TIMESTAMP_ADDRESS = "timestamp.example"
        const val UNSUPPORTED_SCHEME_TIMESTAMP_ADDRESS = "ftp://timestamp.example"
        const val USER_INFORMATION_TIMESTAMP_ADDRESS = "https://user@timestamp.example"
    }
}
