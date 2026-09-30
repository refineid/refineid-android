// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class SigningNetworkAddressPolicyTest {
    @Test
    fun rejectsLocalSpecialDocumentationAndEmbeddedPrivateAddresses() {
        for (literal in NON_PUBLIC_ADDRESS_LITERALS) {
            val address =
                checkNotNull(SigningNetworkAddressPolicy.numericAddress(literal)) {
                    "numeric fixture did not parse: $literal"
                }
            assertFalse("non-public fixture was accepted: $literal", SigningNetworkAddressPolicy.isPublic(address))
            assertFalse(
                "non-public host was accepted statically: $literal",
                SigningNetworkAddressPolicy.hostCouldBePublic(literal),
            )
        }
    }

    @Test
    fun rejectsLocalNamesAndAlternateNumericSpellingsBeforeResolution() {
        for (host in NON_PUBLIC_HOST_SPELLINGS) {
            assertFalse(
                "unsafe hostname spelling was accepted: $host",
                SigningNetworkAddressPolicy.hostCouldBePublic(host),
            )
        }
        assertTrue(SigningNetworkAddressPolicy.hostCouldBePublic(PUBLIC_DNS_NAME))
        assertEquals(PUBLIC_DNS_NAME, SigningNetworkAddressPolicy.normalizedHost(PUBLIC_ABSOLUTE_DNS_NAME))
    }

    @Test
    fun refusesNonPublicOrEmptyDnsAnswerSet() {
        assertFailure(SigningNetworkFailure.UNSAFE_ADDRESS) {
            SigningNetworkAddressPolicy.publicResolvedAddresses(
                PUBLIC_DNS_NAME,
                SigningNetworkResolver { listOf(numeric(PRIVATE_IPV4)) },
            )
        }
        assertFailure(SigningNetworkFailure.UNSAFE_ADDRESS) {
            SigningNetworkAddressPolicy.publicResolvedAddresses(
                PUBLIC_DNS_NAME,
                SigningNetworkResolver { emptyList() },
            )
        }
    }

    @Test
    fun refusesAnOversizedDnsAnswerSetWithoutCheckingOnlyAPrefix() {
        val addresses =
            (FIRST_GENERATED_ADDRESS_OCTET until FIRST_GENERATED_ADDRESS_OCTET + OVERSIZED_ADDRESS_COUNT)
                .map { finalOctet ->
                    InetAddress.getByAddress(
                        byteArrayOf(
                            LOOPBACK_TEST_FIRST_OCTET,
                            LOOPBACK_TEST_SECOND_OCTET,
                            LOOPBACK_TEST_THIRD_OCTET,
                            finalOctet.toByte(),
                        ),
                    )
                }

        assertFailure(SigningNetworkFailure.UNSAFE_ADDRESS) {
            SigningNetworkAddressPolicy.publicResolvedAddresses(
                PUBLIC_DNS_NAME,
                SigningNetworkResolver { addresses },
            )
        }
    }

    private fun numeric(literal: String): InetAddress =
        checkNotNull(SigningNetworkAddressPolicy.numericAddress(literal))

    private fun assertFailure(
        expected: SigningNetworkFailure,
        operation: () -> Unit,
    ) {
        val failure = assertThrows(SigningNetworkException::class.java, operation)
        assertEquals(expected, failure.kind)
    }

    private companion object {
        const val PRIVATE_IPV4 = "127.0.0.1"
        const val PUBLIC_DNS_NAME = "ocsp.example"
        const val PUBLIC_ABSOLUTE_DNS_NAME = "$PUBLIC_DNS_NAME."
        const val FIRST_GENERATED_ADDRESS_OCTET = 1
        const val OVERSIZED_ADDRESS_COUNT = 9
        const val LOOPBACK_TEST_FIRST_OCTET: Byte = 127
        const val LOOPBACK_TEST_SECOND_OCTET: Byte = 0
        const val LOOPBACK_TEST_THIRD_OCTET: Byte = 0
        val NON_PUBLIC_ADDRESS_LITERALS =
            listOf(
                "0.0.0.1",
                "10.0.0.1",
                "100.64.0.1",
                "127.0.0.1",
                "169.254.1.1",
                "172.16.0.1",
                "192.0.0.1",
                "192.0.2.1",
                "192.88.99.1",
                "192.168.0.1",
                "198.18.0.1",
                "198.51.100.1",
                "203.0.113.1",
                "224.0.0.1",
                "::",
                "::1",
                "::127.0.0.1",
                "::ffff:127.0.0.1",
                "fc00::1",
                "fe80::1",
                "fec0::1",
                "ff02::1",
                "2001:db8::1",
                "64:ff9b:1::10.0.0.1",
                "64:ff9b::127.0.0.1",
                "100::1",
                "100:0:0:1::1",
                "2001:2::1",
                "2002:7f00:1::",
                "3fff::1",
                "4000::1",
                "5f00::1",
            )
        val NON_PUBLIC_HOST_SPELLINGS =
            listOf(
                "localhost",
                "service.localhost",
                "local",
                "service.local",
                "127.000.000.001",
                "2130706433",
                "0x7f000001",
                "1.2.3",
                "fe80::1%25wlan0",
            )
    }
}
