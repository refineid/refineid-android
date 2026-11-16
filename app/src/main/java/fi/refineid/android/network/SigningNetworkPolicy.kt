// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.URISyntaxException

/** Pure URL, credential, DNS-pinning, and redirect policy for signing traffic. */
internal object SigningNetworkPolicy {
    fun postRequest(
        body: ByteArray,
        address: String,
        contentType: String,
        credentials: SigningNetworkBasicCredentials?,
        endpoint: SigningNetworkEndpoint,
    ): SigningNetworkRequest {
        requireBody(body)
        requireHeaderValue(contentType)
        val uri = httpUri(address, endpoint)
        if (credentials != null && uri.scheme.lowercase() != HTTPS_SCHEME) {
            throw SigningNetworkException(SigningNetworkFailure.INSECURE_CREDENTIALS)
        }
        return SigningNetworkRequest(
            initialUri = uri,
            logicalUri = uri,
            connectionUri = uri,
            method = SigningNetworkMethod.POST,
            endpoint = endpoint,
            contentType = contentType,
            ownedBody = body.copyOf(),
            authorization = credentials?.authorizationHeader(),
        )
    }

    fun getRequest(
        address: String,
        endpoint: SigningNetworkEndpoint,
    ): SigningNetworkRequest {
        val uri = httpUri(address, endpoint)
        return SigningNetworkRequest(
            initialUri = uri,
            logicalUri = uri,
            connectionUri = uri,
            method = SigningNetworkMethod.GET,
            endpoint = endpoint,
            contentType = null,
            ownedBody = null,
            authorization = null,
        )
    }

    fun protect(
        request: SigningNetworkRequest,
        resolver: SigningNetworkResolver,
    ): SigningNetworkRequest {
        val host = request.logicalUri.host ?: throw unsafeAddress()
        if (!certificateMaterialUriIsAllowed(request.logicalUri)) {
            throw unsafeAddress()
        }
        if (SigningNetworkAddressPolicy.numericAddress(host) != null) {
            return request.copy()
        }
        val addresses = SigningNetworkAddressPolicy.publicResolvedAddresses(host, resolver)
        val pinned = pinnedUri(request.logicalUri, addresses.first())
        return request.copy(
            connectionUri = pinned,
        )
    }

    fun redirected(
        current: SigningNetworkRequest,
        target: URI,
        redirectsFollowed: Int,
        preservesMethod: Boolean,
        resolver: SigningNetworkResolver,
    ): SigningNetworkRequest {
        val maximumRedirects = maximumRedirects(current.endpoint)
        if (redirectsFollowed >= maximumRedirects) {
            throw SigningNetworkException(SigningNetworkFailure.REDIRECT_LIMIT_EXCEEDED)
        }
        if (
            redirectDecision(
                initial = current.initialUri,
                target = target,
                endpoint = current.endpoint,
                carriesCredentials = current.carriesCredentials,
                redirectsFollowed = redirectsFollowed,
            ) == SigningNetworkRedirectDecision.REFUSE
        ) {
            throw SigningNetworkException(SigningNetworkFailure.UNSAFE_REDIRECT)
        }
        val redirectedMethod =
            if (preservesMethod) {
                current.method
            } else {
                SigningNetworkMethod.GET
            }
        val redirected =
            current.copy(
                logicalUri = target,
                connectionUri = target,
                method = redirectedMethod,
                contentType = if (redirectedMethod == SigningNetworkMethod.POST) current.contentType else null,
            )
        return try {
            protect(redirected, resolver)
        } finally {
            redirected.close()
        }
    }

    fun redirectDecision(
        initial: URI,
        target: URI,
        endpoint: SigningNetworkEndpoint,
        carriesCredentials: Boolean,
        redirectsFollowed: Int,
    ): SigningNetworkRedirectDecision {
        if (redirectsFollowed >= maximumRedirects(endpoint) || !isHttpUri(target)) {
            return SigningNetworkRedirectDecision.REFUSE
        }
        if (
            endpoint == SigningNetworkEndpoint.CERTIFICATE_MATERIAL &&
            !certificateMaterialUriIsAllowed(target)
        ) {
            return SigningNetworkRedirectDecision.REFUSE
        }
        if (carriesCredentials) {
            return if (
                target.scheme.lowercase() == HTTPS_SCHEME &&
                origin(initial) == origin(target)
            ) {
                SigningNetworkRedirectDecision.FOLLOW
            } else {
                SigningNetworkRedirectDecision.REFUSE
            }
        }
        if (endpoint == SigningNetworkEndpoint.CERTIFICATE_MATERIAL) {
            return SigningNetworkRedirectDecision.FOLLOW
        }
        return if (authorityRedirectIsAllowed(initial, target)) {
            SigningNetworkRedirectDecision.FOLLOW
        } else {
            SigningNetworkRedirectDecision.REFUSE
        }
    }

    fun httpUri(
        address: String,
        endpoint: SigningNetworkEndpoint,
    ): URI {
        if (address.isEmpty() || address.length > SigningNetworkLimits.MAXIMUM_ADDRESS_CHARACTERS) {
            throw SigningNetworkException(SigningNetworkFailure.BAD_ADDRESS)
        }
        val uri =
            try {
                URI(address)
            } catch (_: URISyntaxException) {
                throw SigningNetworkException(SigningNetworkFailure.BAD_ADDRESS)
            }
        if (!isHttpUri(uri)) {
            throw SigningNetworkException(SigningNetworkFailure.BAD_ADDRESS)
        }
        if (
            endpoint == SigningNetworkEndpoint.CERTIFICATE_MATERIAL &&
            !certificateMaterialUriIsAllowed(uri)
        ) {
            throw unsafeAddress()
        }
        return uri
    }

    fun isHttpUri(uri: URI): Boolean {
        val scheme = uri.scheme?.lowercase() ?: return false
        val host = uri.host ?: return false
        return scheme in HTTP_SCHEMES &&
            host.isNotEmpty() &&
            uri.toString().length <= SigningNetworkLimits.MAXIMUM_ADDRESS_CHARACTERS &&
            uri.rawUserInfo == null &&
            (uri.port == URI_PORT_UNSPECIFIED || uri.port in MINIMUM_PORT..MAXIMUM_PORT) &&
            !uri.isOpaque
    }

    fun certificateMaterialUriIsAllowed(uri: URI): Boolean {
        val host = uri.host ?: return false
        return isHttpUri(uri) && SigningNetworkAddressPolicy.hostCouldBePublic(host)
    }

    private fun pinnedUri(
        logical: URI,
        address: InetAddress,
    ): URI {
        val addressText = address.hostAddress ?: throw unsafeAddress()
        val host =
            if (address is Inet6Address) {
                addressText.substringBefore(IPV6_ZONE_SEPARATOR)
            } else {
                addressText
            }
        val authority =
            (if (address is Inet6Address) "[$host]" else host) +
                if (logical.port == URI_PORT_UNSPECIFIED) {
                    ""
                } else {
                    PORT_SEPARATOR.toString() + logical.port
                }
        val encoded =
            buildString {
                append(logical.scheme)
                append(SCHEME_SEPARATOR)
                append(authority)
                append(logical.rawPath.orEmpty())
                logical.rawQuery?.let { query -> append(QUERY_SEPARATOR).append(query) }
                logical.rawFragment?.let { fragment -> append(FRAGMENT_SEPARATOR).append(fragment) }
            }
        return try {
            URI(encoded)
        } catch (_: URISyntaxException) {
            throw unsafeAddress()
        }
    }

    private fun authorityRedirectIsAllowed(
        initial: URI,
        target: URI,
    ): Boolean {
        if (origin(initial) == origin(target)) {
            return true
        }
        val initialScheme = initial.scheme?.lowercase() ?: return false
        val targetScheme = target.scheme?.lowercase() ?: return false
        val initialHost = initial.host ?: return false
        val targetHost = target.host ?: return false
        return initialScheme == HTTP_SCHEME &&
            targetScheme == HTTPS_SCHEME &&
            SigningNetworkAddressPolicy.normalizedHost(initialHost) ==
            SigningNetworkAddressPolicy.normalizedHost(targetHost)
    }

    private fun origin(uri: URI): Origin? {
        if (!isHttpUri(uri)) {
            return null
        }
        val scheme = uri.scheme.lowercase()
        val port =
            if (uri.port == URI_PORT_UNSPECIFIED) {
                if (scheme == HTTPS_SCHEME) DEFAULT_HTTPS_PORT else DEFAULT_HTTP_PORT
            } else {
                uri.port
            }
        return Origin(
            scheme = scheme,
            host = SigningNetworkAddressPolicy.normalizedHost(uri.host),
            port = port,
        )
    }

    private fun maximumRedirects(endpoint: SigningNetworkEndpoint): Int =
        when (endpoint) {
            SigningNetworkEndpoint.AUTHORITY -> MAXIMUM_AUTHORITY_REDIRECTS
            SigningNetworkEndpoint.CERTIFICATE_MATERIAL -> MAXIMUM_CERTIFICATE_MATERIAL_REDIRECTS
        }

    private fun requireBody(body: ByteArray) {
        if (body.isEmpty() || body.size > SigningNetworkLimits.MAXIMUM_REQUEST_BYTES) {
            throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
        }
    }

    private fun requireHeaderValue(value: String) {
        if (
            value.isEmpty() ||
            value.length > SigningNetworkLimits.MAXIMUM_HEADER_VALUE_CHARACTERS ||
            value.any(FORBIDDEN_HEADER_CHARACTERS::contains)
        ) {
            throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
        }
    }

    private fun unsafeAddress(): SigningNetworkException = SigningNetworkException(SigningNetworkFailure.UNSAFE_ADDRESS)

    private data class Origin(
        val scheme: String,
        val host: String,
        val port: Int,
    )

    private const val HTTP_SCHEME = "http"
    private const val HTTPS_SCHEME = "https"
    private val HTTP_SCHEMES = setOf(HTTP_SCHEME, HTTPS_SCHEME)
    private const val DEFAULT_HTTP_PORT = 80
    private const val DEFAULT_HTTPS_PORT = 443
    private const val MINIMUM_PORT = 1
    private const val MAXIMUM_PORT = 65_535
    private const val URI_PORT_UNSPECIFIED = -1
    private const val MAXIMUM_AUTHORITY_REDIRECTS = 1
    private const val MAXIMUM_CERTIFICATE_MATERIAL_REDIRECTS = 2
    private const val IPV6_COMPONENT_SEPARATOR = ':'
    private const val IPV6_ZONE_SEPARATOR = "%"
    private const val PORT_SEPARATOR = ':'
    private const val SCHEME_SEPARATOR = "://"
    private const val QUERY_SEPARATOR = '?'
    private const val FRAGMENT_SEPARATOR = '#'
    private const val CARRIAGE_RETURN = '\r'
    private const val LINE_FEED = '\n'
    private const val NULL_CHARACTER = '\u0000'
    private val FORBIDDEN_HEADER_CHARACTERS = setOf(CARRIAGE_RETURN, LINE_FEED, NULL_CHARACTER)
}

internal enum class SigningNetworkRedirectDecision {
    FOLLOW,
    REFUSE,
}
