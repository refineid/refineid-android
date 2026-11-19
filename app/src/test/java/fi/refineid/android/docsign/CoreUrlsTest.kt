// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.refineid_doc_sign_android.HttpFailure
import java.net.URI

class CoreUrlsTest {
    @Test
    fun anIpv4LiteralTakesThePlaceOfTheHostUnbracketed() {
        assertEquals(
            "https://$IPV4/responder?q=1",
            CoreUrls.connectionUri(URI(PUBLISHED), IPV4).toString(),
        )
    }

    @Test
    fun everyLiteralWithAColonIsBracketedIpv4MappedIncluded() {
        assertEquals(
            "https://[$IPV4_MAPPED]/responder?q=1",
            CoreUrls.connectionUri(URI(PUBLISHED), IPV4_MAPPED).toString(),
        )
        assertEquals(
            "https://[$IPV6]:$PORT/responder?q=1",
            CoreUrls.connectionUri(URI(PUBLISHED_WITH_PORT), IPV6).toString(),
        )
    }

    @Test
    fun theHostHeaderBracketsAnIpv6HostAndKeepsAnExplicitPort() {
        assertEquals("[$IPV6]:$PORT", CoreUrls.hostHeader(URI("https://[$IPV6]:$PORT/list")))
        assertEquals("ocsp.example:$PORT", CoreUrls.hostHeader(URI(PUBLISHED_WITH_PORT)))
        assertEquals("ocsp.example", CoreUrls.hostHeader(URI(PUBLISHED)))
        assertEquals("[$IPV6]", CoreUrls.bracketed(IPV6))
        assertEquals("[$IPV6]", CoreUrls.bracketed("[$IPV6]"))
    }

    @Test
    fun aNameIsNotAnAddressLiteral() {
        assertThrows(HttpFailure.BadUrl::class.java) { CoreUrls.literalAddress("ocsp.example") }
    }

    private companion object {
        const val PORT = 8443
        const val PUBLISHED = "https://ocsp.example/responder?q=1"
        const val PUBLISHED_WITH_PORT = "https://ocsp.example:$PORT/responder?q=1"

        // Documentation addresses (RFC 5737, RFC 3849).
        const val IPV4 = "192.0.2.10"
        const val IPV4_MAPPED = "::ffff:192.0.2.10"
        const val IPV6 = "2001:db8::10"
    }
}
