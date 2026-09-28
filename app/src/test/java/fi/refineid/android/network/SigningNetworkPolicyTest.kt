// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.util.Base64

class SigningNetworkPolicyTest {
    @Test
    fun refusesLookalikeNonNetworkCredentialedPlaintextAndUnsafeCertificateUrls() {
        for (address in BAD_AUTHORITY_ADDRESSES) {
            assertFailure(SigningNetworkFailure.BAD_ADDRESS) {
                SigningNetworkPolicy.postRequest(
                    body = SYNTHETIC_REQUEST,
                    address = address,
                    contentType = TIMESTAMP_CONTENT_TYPE,
                    credentials = null,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            }
        }
        for (address in UNSAFE_CERTIFICATE_ADDRESSES) {
            assertFailure(SigningNetworkFailure.UNSAFE_ADDRESS) {
                SigningNetworkPolicy.getRequest(
                    address = address,
                    endpoint = SigningNetworkEndpoint.CERTIFICATE_MATERIAL,
                )
            }
        }
        SigningNetworkBasicCredentials.copyOf(SYNTHETIC_USERNAME, SYNTHETIC_PASSWORD).use { credentials ->
            assertFailure(SigningNetworkFailure.INSECURE_CREDENTIALS) {
                SigningNetworkPolicy.postRequest(
                    body = SYNTHETIC_REQUEST,
                    address = PLAIN_AUTHORITY_ADDRESS,
                    contentType = TIMESTAMP_CONTENT_TYPE,
                    credentials = credentials,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            }
        }
    }

    @Test
    fun refusesOverlengthAddressHeaderCredentialAndRequestInputs() {
        assertFailure(SigningNetworkFailure.BAD_ADDRESS) {
            SigningNetworkPolicy.getRequest(
                address = OVERLENGTH_AUTHORITY_ADDRESS,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
        assertFailure(SigningNetworkFailure.UNUSABLE_BODY) {
            SigningNetworkPolicy.postRequest(
                body = SYNTHETIC_REQUEST,
                address = PROTECTED_AUTHORITY_ADDRESS,
                contentType = OVERLENGTH_HEADER_VALUE,
                credentials = null,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
        assertFailure(SigningNetworkFailure.UNUSABLE_BODY) {
            SigningNetworkPolicy.postRequest(
                body = OVERLENGTH_REQUEST_BODY,
                address = PROTECTED_AUTHORITY_ADDRESS,
                contentType = TIMESTAMP_CONTENT_TYPE,
                credentials = null,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            SigningNetworkBasicCredentials.copyOf(OVERLENGTH_USERNAME, SYNTHETIC_PASSWORD)
        }
        assertThrows(IllegalArgumentException::class.java) {
            SigningNetworkBasicCredentials.copyOf(SYNTHETIC_USERNAME, OVERLENGTH_PASSWORD)
        }
    }

    @Test
    fun ownsThePostBodyAndCarriesOnlyTheExpectedCredentialHeader() {
        val mutableRequest = SYNTHETIC_REQUEST.copyOf()
        val request =
            SigningNetworkBasicCredentials
                .copyOf(SYNTHETIC_USERNAME, SYNTHETIC_PASSWORD)
                .use { credentials ->
                    SigningNetworkPolicy.postRequest(
                        body = mutableRequest,
                        address = PROTECTED_AUTHORITY_ADDRESS,
                        contentType = TIMESTAMP_CONTENT_TYPE,
                        credentials = credentials,
                        endpoint = SigningNetworkEndpoint.AUTHORITY,
                    )
                }
        mutableRequest.fill(MUTATED_REQUEST_BYTE)

        request.use { owned ->
            assertEquals(SigningNetworkMethod.POST, owned.method)
            assertEquals(PROTECTED_AUTHORITY_URI, owned.logicalUri)
            assertTrue(owned.carriesCredentials)
            assertEquals(SYNTHETIC_AUTHORIZATION_HEADER, owned.authorizationHeader())
            assertArrayEquals(SYNTHETIC_REQUEST, owned.copyBody())
            assertNull(owned.hostHeader)
            assertFalse(owned.toString().contains(SYNTHETIC_USERNAME))
        }
        assertThrows(IllegalStateException::class.java, request::copyBody)
    }

    @Test
    fun basicCredentialsPermitAnEmptyPasswordWithoutLosingTheSeparator() {
        SigningNetworkBasicCredentials
            .copyOf(SYNTHETIC_USERNAME, EMPTY_PASSWORD)
            .use { credentials ->
                assertEquals(EMPTY_PASSWORD_AUTHORIZATION_HEADER, credentials.authorizationHeader())
            }
    }

    @Test
    fun keepsAuthorityRedirectsOnTheirConfiguredOriginOrSameHostUpgrade() {
        for (target in ALLOWED_AUTHORITY_REDIRECTS) {
            assertEquals(
                SigningNetworkRedirectDecision.FOLLOW,
                SigningNetworkPolicy.redirectDecision(
                    initial = PLAIN_AUTHORITY_URI,
                    target = target,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                    carriesCredentials = false,
                    redirectsFollowed = NO_REDIRECTS,
                ),
            )
        }
        for (target in REFUSED_AUTHORITY_REDIRECTS) {
            assertEquals(
                SigningNetworkRedirectDecision.REFUSE,
                SigningNetworkPolicy.redirectDecision(
                    initial = PROTECTED_AUTHORITY_URI,
                    target = target,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                    carriesCredentials = false,
                    redirectsFollowed = NO_REDIRECTS,
                ),
            )
        }
    }

    @Test
    fun credentialedRedirectsStayOnTheExactHttpsOriginAndOneHopBudget() {
        assertEquals(
            SigningNetworkRedirectDecision.FOLLOW,
            credentialedRedirectDecision(SAME_PROTECTED_ORIGIN_REDIRECT, NO_REDIRECTS),
        )
        for (target in REFUSED_CREDENTIALED_REDIRECTS) {
            assertEquals(
                SigningNetworkRedirectDecision.REFUSE,
                credentialedRedirectDecision(target, NO_REDIRECTS),
            )
        }
        assertEquals(
            SigningNetworkRedirectDecision.REFUSE,
            credentialedRedirectDecision(SAME_PROTECTED_ORIGIN_REDIRECT, AUTHORITY_REDIRECT_BUDGET),
        )
    }

    private fun credentialedRedirectDecision(
        target: URI,
        redirectsFollowed: Int,
    ): SigningNetworkRedirectDecision =
        SigningNetworkPolicy.redirectDecision(
            initial = PROTECTED_AUTHORITY_URI,
            target = target,
            endpoint = SigningNetworkEndpoint.AUTHORITY,
            carriesCredentials = true,
            redirectsFollowed = redirectsFollowed,
        )

    private fun assertFailure(
        expected: SigningNetworkFailure,
        operation: () -> Unit,
    ) {
        val failure = assertThrows(SigningNetworkException::class.java, operation)
        assertEquals(expected, failure.kind)
    }

    private companion object {
        const val TIMESTAMP_CONTENT_TYPE = "application/timestamp-query"
        const val SYNTHETIC_USERNAME = "synthetic-account"
        val SYNTHETIC_AUTHORIZATION_HEADER =
            "Basic " + Base64.getEncoder().encodeToString("$SYNTHETIC_USERNAME:synthetic-secret".toByteArray())
        val EMPTY_PASSWORD_AUTHORIZATION_HEADER =
            "Basic " + Base64.getEncoder().encodeToString("$SYNTHETIC_USERNAME:".toByteArray())
        const val PLAIN_AUTHORITY_ADDRESS = "http://timestamp.example/request"
        const val PROTECTED_AUTHORITY_ADDRESS = "https://timestamp.example/request"
        const val MUTATED_REQUEST_BYTE: Byte = 0x5A
        const val NO_REDIRECTS = 0
        const val AUTHORITY_REDIRECT_BUDGET = 1
        const val SINGLE_OVERLIMIT_ELEMENT = 1
        val SYNTHETIC_REQUEST = "synthetic-request".encodeToByteArray()
        val SYNTHETIC_PASSWORD = "synthetic-secret".toCharArray()
        val EMPTY_PASSWORD = CharArray(0)
        val OVERLENGTH_AUTHORITY_ADDRESS =
            PROTECTED_AUTHORITY_ADDRESS +
                "a".repeat(SigningNetworkLimits.MAXIMUM_ADDRESS_CHARACTERS)
        val OVERLENGTH_HEADER_VALUE =
            "h".repeat(SigningNetworkLimits.MAXIMUM_HEADER_VALUE_CHARACTERS + SINGLE_OVERLIMIT_ELEMENT)
        val OVERLENGTH_REQUEST_BODY =
            ByteArray(SigningNetworkLimits.MAXIMUM_REQUEST_BYTES + SINGLE_OVERLIMIT_ELEMENT)
        val OVERLENGTH_USERNAME =
            "u".repeat(SigningNetworkLimits.MAXIMUM_USERNAME_CHARACTERS + SINGLE_OVERLIMIT_ELEMENT)
        val OVERLENGTH_PASSWORD =
            CharArray(SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS + SINGLE_OVERLIMIT_ELEMENT) { 'p' }
        val PLAIN_AUTHORITY_URI = URI(PLAIN_AUTHORITY_ADDRESS)
        val PROTECTED_AUTHORITY_URI = URI(PROTECTED_AUTHORITY_ADDRESS)
        val SAME_PROTECTED_ORIGIN_REDIRECT = URI("https://timestamp.example:443/moved")
        val ALLOWED_AUTHORITY_REDIRECTS =
            listOf(
                URI("http://timestamp.example/moved"),
                URI("https://timestamp.example/moved"),
            )
        val REFUSED_AUTHORITY_REDIRECTS =
            listOf(
                URI("http://timestamp.example/moved"),
                URI("https://other.example/moved"),
            )
        val REFUSED_CREDENTIALED_REDIRECTS =
            listOf(
                URI("http://timestamp.example/moved"),
                URI("https://other.example/moved"),
            )
        val BAD_AUTHORITY_ADDRESSES =
            listOf(
                "httpish://timestamp.example",
                "file:///tmp/timestamp",
                "https:/missing-host",
                "https://user@timestamp.example/request",
                "https://timestamp.example:65536/request",
            )
        val UNSAFE_CERTIFICATE_ADDRESSES =
            listOf(
                "http://localhost/status",
                "http://127.0.0.1/status",
                "http://[::1]/status",
                "http://192.0.2.1/status",
            )
    }
}
