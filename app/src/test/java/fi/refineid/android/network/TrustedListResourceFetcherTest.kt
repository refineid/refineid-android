// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
// https://www.apache.org/licenses/LICENSE-2.0

package fi.refineid.android.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TrustedListResourceFetcherTest {
    @Test
    fun listFetchUsesTheBoundedCertificateMaterialPolicy() {
        val fetcher =
            TrustedListResourceFetcher(
                object : SigningNetworkTransport {
                    override fun get(
                        address: String,
                        maximumResponseBytes: Int,
                        endpoint: SigningNetworkEndpoint,
                    ): ByteArray {
                        assertEquals(ADDRESS, address)
                        assertEquals(MAXIMUM_LIST_BYTES, maximumResponseBytes)
                        assertEquals(SigningNetworkEndpoint.CERTIFICATE_MATERIAL, endpoint)
                        return RESPONSE.copyOf()
                    }

                    override fun post(
                        body: ByteArray,
                        address: String,
                        contentType: String,
                        credentials: SigningNetworkBasicCredentials?,
                        maximumResponseBytes: Int,
                        endpoint: SigningNetworkEndpoint,
                    ): ByteArray = throw AssertionError("unexpected POST")
                },
            )
        assertArrayEquals(RESPONSE, fetcher.get(ADDRESS))
    }

    @Test
    fun unsafeTrustedListLocationReturnsNoTrustMaterial() {
        assertNull(TrustedListResourceFetcher(HttpSigningNetwork()).get("http://127.0.0.1/list.xml"))
    }

    private companion object {
        const val ADDRESS = "https://trusted-list.example/list.xml"
        const val MAXIMUM_LIST_BYTES = 16_777_216
        val RESPONSE = "synthetic signed-list bytes".encodeToByteArray()
    }
}
