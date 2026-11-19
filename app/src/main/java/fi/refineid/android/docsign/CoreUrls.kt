// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import uniffi.refineid_doc_sign_android.HttpFailure
import java.net.InetAddress
import java.net.URI
import java.net.URISyntaxException
import java.net.UnknownHostException

/** The URLs and addresses of the core's fetches, as [CoreHttpClient] takes and builds them. */
internal object CoreUrls {
    /** [uri] with [address] in place of its host; [uri] itself when null. */
    fun connectionUri(
        uri: URI,
        address: String?,
    ): URI {
        if (address == null) {
            return uri
        }
        literalAddress(address)
        val host = bracketed(address)
        val port = if (uri.port == PORT_UNSPECIFIED) "" else PORT_SEPARATOR + uri.port
        return try {
            URI(
                buildString {
                    append(uri.scheme).append(SCHEME_SEPARATOR).append(host).append(port)
                    append(uri.rawPath.orEmpty())
                    uri.rawQuery?.let { append(QUERY_SEPARATOR).append(it) }
                },
            )
        } catch (_: URISyntaxException) {
            throw HttpFailure.BadUrl()
        }
    }

    /** The `Host` header naming [uri]'s host and explicit port. */
    fun hostHeader(uri: URI): String {
        val host = bracketed(uri.host ?: throw HttpFailure.BadUrl())
        return if (uri.port == PORT_UNSPECIFIED) host else host + PORT_SEPARATOR + uri.port
    }

    /**
     * [host] as it stands in a URL authority or a `Host` header: an IPv6
     * literal, any text with a colon (IPv4-mapped forms included), in
     * brackets (RFC 3986 sec.3.2.2); anything else as it is.
     */
    fun bracketed(host: String): String =
        if (host.contains(IPV6_COMPONENT_SEPARATOR) && !host.startsWith(IPV6_OPEN)) {
            IPV6_OPEN + host + IPV6_CLOSE
        } else {
            host
        }

    /**
     * [text] as an address without asking a resolver: an IPv6 literal, or
     * an IPv4 literal in dotted-quad form. Anything else is refused.
     */
    fun literalAddress(text: String): InetAddress {
        if (!text.contains(IPV6_COMPONENT_SEPARATOR) && !IPV4_LITERAL.matches(text)) {
            throw HttpFailure.BadUrl()
        }
        return try {
            InetAddress.getByName(text)
        } catch (_: UnknownHostException) {
            throw HttpFailure.BadUrl()
        }
    }

    /** Where a redirect from [from] to [location] goes; only `http` or `https` with a host. */
    fun redirectTarget(
        from: URI,
        location: String,
    ): URI {
        if (location.isEmpty()) {
            throw HttpFailure.UnsafeRedirect()
        }
        val target =
            try {
                from.resolve(location)
            } catch (_: IllegalArgumentException) {
                throw HttpFailure.UnsafeRedirect()
            }
        if (target.scheme?.lowercase() !in HTTP_SCHEMES || target.host.isNullOrEmpty()) {
            throw HttpFailure.UnsafeRedirect()
        }
        return target
    }

    /** [url] as an absolute `http` or `https` URI with a host. */
    fun parse(url: String): URI {
        val uri =
            try {
                URI(url)
            } catch (_: URISyntaxException) {
                throw HttpFailure.BadUrl()
            }
        if (uri.scheme?.lowercase() !in HTTP_SCHEMES || uri.host.isNullOrEmpty()) {
            throw HttpFailure.BadUrl()
        }
        return uri
    }

    const val IPV6_OPEN = "["
    const val IPV6_CLOSE = "]"
    private const val SCHEME_HTTP = "http"
    private const val SCHEME_HTTPS = "https"
    private val HTTP_SCHEMES = setOf(SCHEME_HTTP, SCHEME_HTTPS)
    private const val PORT_UNSPECIFIED = -1
    private const val IPV6_COMPONENT_SEPARATOR = ':'
    private val IPV4_LITERAL = Regex("""\d{1,3}(\.\d{1,3}){3}""")
    private const val PORT_SEPARATOR = ":"
    private const val SCHEME_SEPARATOR = "://"
    private const val QUERY_SEPARATOR = '?'
}
