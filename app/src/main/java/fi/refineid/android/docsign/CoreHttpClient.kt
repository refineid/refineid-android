// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import uniffi.refineid_doc_sign_android.HttpClient
import uniffi.refineid_doc_sign_android.HttpFailure
import uniffi.refineid_doc_sign_android.authorityRedirectOk
import uniffi.refineid_doc_sign_android.vetDestination
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

/** Opens the connection for one URI; the system's URL handlers by default. */
internal fun interface ConnectionFactory {
    fun open(uri: URI): HttpURLConnection
}

internal object SystemConnectionFactory : ConnectionFactory {
    override fun open(uri: URI): HttpURLConnection = uri.toURL().openConnection() as HttpURLConnection
}

/**
 * The app's HTTP client as the core's transport for timestamps, chain and
 * revocation fetches.
 *
 * The core vets every certificate-published host and hands over the
 * addresses it checked. A request connects to those addresses in order,
 * never resolving the name again, and carries the name in `Host`. Over
 * HTTPS the platform's connection goes to the address literal, the TLS
 * handshake names the host (SNI) and the server's certificate is checked
 * against the host name by [hostnameVerifier]. Over HTTP the request goes
 * over a socket to the address ([PlainHttpExchange]), since the
 * platform's HTTP stack refuses cleartext to an address literal. A
 * redirect of a certificate-published URL connects only to what [vet]
 * returns for its target. A timestamp authority is trusted as configured
 * and connects by name; its redirect is followed only when
 * [authorityRedirect] allows it.
 */
internal class CoreHttpClient(
    private val connectionFactory: ConnectionFactory = SystemConnectionFactory,
    private val vet: (String) -> List<String> = ::vetDestination,
    private val authorityRedirect: (String, String) -> Boolean = ::authorityRedirectOk,
    private val hostnameVerifier: HostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier(),
    private val plainHttp: PlainHttpExchange = PlainHttpExchange(timeoutMilliseconds = EXCHANGE_TIMEOUT_MILLISECONDS),
) : HttpClient {
    override fun resolve(host: String): List<String> = boundary { resolveName(host) }

    private fun resolveName(host: String): List<String> =
        try {
            InetAddress.getAllByName(host).mapNotNull { address ->
                address.hostAddress?.substringBefore(IPV6_ZONE_SEPARATOR)
            }
        } catch (_: UnknownHostException) {
            throw HttpFailure.Transport(retryable = true)
        } catch (_: SecurityException) {
            throw HttpFailure.Transport(retryable = false)
        }

    override fun get(
        url: String,
        addresses: List<String>,
        maxBytes: ULong,
    ): ByteArray =
        boundary {
            exchange(
                Request(CoreUrls.parse(url), Destination.Vetted.of(addresses), METHOD_GET, null, null, null),
                maxBytes,
                MAXIMUM_CERTIFICATE_REDIRECTS,
            ) { target -> Destination.Vetted.of(vet(target.toString())) }
        }

    override fun post(
        url: String,
        addresses: List<String>,
        contentType: String,
        body: ByteArray,
        maxBytes: ULong,
    ): ByteArray =
        boundary {
            exchange(
                Request(CoreUrls.parse(url), Destination.Vetted.of(addresses), METHOD_POST, contentType, body, null),
                maxBytes,
                MAXIMUM_CERTIFICATE_REDIRECTS,
            ) { target -> Destination.Vetted.of(vet(target.toString())) }
        }

    override fun postAuthority(
        url: String,
        contentType: String,
        body: ByteArray,
        maxBytes: ULong,
        authorization: String?,
    ): ByteArray =
        boundary {
            val first = CoreUrls.parse(url)
            exchange(
                Request(first, Destination.Configured, METHOD_POST, contentType, body, authorization),
                maxBytes,
                MAXIMUM_AUTHORITY_REDIRECTS,
            ) { target ->
                if (authorityRedirect(first.toString(), target.toString())) {
                    Destination.Configured
                } else {
                    throw HttpFailure.UnsafeRedirect()
                }
            }
        }

    /**
     * Where a request may connect. A certificate-published URL goes only to
     * the addresses the core vetted, never fewer than one; the configured
     * timestamp authority, trusted as configured, connects by name.
     */
    private sealed interface Destination {
        class Vetted private constructor(
            val addresses: List<String>,
        ) : Destination {
            companion object {
                fun of(addresses: List<String>): Vetted =
                    if (addresses.isEmpty()) throw HttpFailure.UnsafeDestination() else Vetted(addresses)
            }
        }

        data object Configured : Destination
    }

    private class Request(
        val uri: URI,
        val destination: Destination,
        val method: String,
        val contentType: String?,
        val body: ByteArray?,
        val authorization: String?,
    ) {
        fun redirected(
            target: URI,
            destination: Destination,
            preservesMethod: Boolean,
        ): Request =
            if (preservesMethod) {
                Request(target, destination, method, contentType, body, authorization)
            } else {
                Request(target, destination, METHOD_GET, null, null, authorization)
            }
    }

    private sealed interface Answer {
        class Body(
            val bytes: ByteArray,
        ) : Answer

        class Redirect(
            val location: String,
            val preservesMethod: Boolean,
        ) : Answer
    }

    /** [request] and up to [maximumRedirects] hops, each resolved by [follow]. */
    private fun exchange(
        request: Request,
        maxBytes: ULong,
        maximumRedirects: Int,
        follow: (URI) -> Destination,
    ): ByteArray {
        var current = request
        var redirects = 0
        while (true) {
            when (val answer = once(current, maxBytes)) {
                is Answer.Body -> {
                    return answer.bytes
                }

                is Answer.Redirect -> {
                    if (redirects >= maximumRedirects) {
                        throw HttpFailure.UnsafeRedirect()
                    }
                    val target = CoreUrls.redirectTarget(current.uri, answer.location)
                    current = current.redirected(target, follow(target), answer.preservesMethod)
                    redirects += 1
                }
            }
        }
    }

    private fun once(
        request: Request,
        maxBytes: ULong,
    ): Answer =
        if (request.uri.scheme.lowercase() == SCHEME_HTTPS) {
            secureOnce(request, maxBytes)
        } else {
            plainOnce(request, maxBytes)
        }

    /**
     * A cleartext [request] over a socket to the first of its addresses that
     * accepts the connection; a timestamp authority's name is resolved here,
     * as it is trusted as configured.
     */
    private fun plainOnce(
        request: Request,
        maxBytes: ULong,
    ): Answer {
        val host = request.uri.host ?: throw HttpFailure.BadUrl()
        val port = if (request.uri.port == PORT_UNSPECIFIED) DEFAULT_HTTP_PORT else request.uri.port
        val targets =
            when (val destination = request.destination) {
                is Destination.Vetted -> destination.addresses.map(CoreUrls::literalAddress)
                Destination.Configured -> resolveName(host).map(CoreUrls::literalAddress)
            }
        var refused: IOException? = null
        for (address in targets) {
            val socket =
                try {
                    plainHttp.connect(InetSocketAddress(address, port))
                } catch (failure: IOException) {
                    refused = failure
                    continue
                }
            val answer =
                try {
                    plainHttp.exchange(
                        socket = socket,
                        uri = request.uri,
                        method = request.method,
                        headers = plainHeaders(request),
                        body = request.body,
                        maxBytes = bound(maxBytes),
                    )
                } catch (failure: IOException) {
                    throw transportFailure(failure)
                }
            return when {
                answer.status in SUCCESS_STATUSES -> {
                    Answer.Body(checkNotNull(answer.body))
                }

                answer.status in REDIRECT_STATUSES -> {
                    Answer.Redirect(
                        location = answer.location ?: throw HttpFailure.UnsafeRedirect(),
                        preservesMethod = answer.status in METHOD_PRESERVING_REDIRECT_STATUSES,
                    )
                }

                else -> {
                    throw HttpFailure.Status(answer.status.toUShort())
                }
            }
        }
        throw refused?.let(::transportFailure) ?: HttpFailure.Transport(retryable = true)
    }

    private fun plainHeaders(request: Request): List<Pair<String, String>> =
        buildList {
            add(HOST_HEADER to CoreUrls.hostHeader(request.uri))
            add(USER_AGENT_HEADER to USER_AGENT)
            add(ACCEPT_HEADER to ACCEPT_ANY_MEDIA_TYPE)
            request.contentType?.let { add(CONTENT_TYPE_HEADER to it) }
            request.authorization?.let { add(AUTHORIZATION_HEADER to it) }
        }

    /** An HTTPS [request] over the first of its addresses that accepts the connection. */
    private fun secureOnce(
        request: Request,
        maxBytes: ULong,
    ): Answer {
        val targets =
            when (val destination = request.destination) {
                is Destination.Vetted -> destination.addresses
                Destination.Configured -> listOf(null)
            }
        var refused: IOException? = null
        for (address in targets) {
            val connection = open(request, address)
            try {
                connection.connect()
            } catch (failure: IOException) {
                connection.disconnect()
                refused = failure
                continue
            }
            return exchange(connection, request, maxBytes)
        }
        throw transportFailure(checkNotNull(refused))
    }

    /** The connection for [request] to [address], by name when null, configured before it connects. */
    private fun open(
        request: Request,
        address: String?,
    ): HttpURLConnection {
        val connection =
            try {
                connectionFactory.open(CoreUrls.connectionUri(request.uri, address))
            } catch (failure: IOException) {
                throw transportFailure(failure)
            }
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        connection.connectTimeout = EXCHANGE_TIMEOUT_MILLISECONDS
        connection.readTimeout = EXCHANGE_TIMEOUT_MILLISECONDS
        connection.requestMethod = request.method
        connection.setRequestProperty(USER_AGENT_HEADER, USER_AGENT)
        connection.setRequestProperty(ACCEPT_HEADER, ACCEPT_ANY_MEDIA_TYPE)
        request.contentType?.let { connection.setRequestProperty(CONTENT_TYPE_HEADER, it) }
        request.authorization?.let { connection.setRequestProperty(AUTHORIZATION_HEADER, it) }
        request.body?.let { body ->
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(body.size)
        }
        if (address != null) {
            connection.setRequestProperty(HOST_HEADER, CoreUrls.hostHeader(request.uri))
            nameTheHost(
                connection,
                request.uri.host
                    .removePrefix(CoreUrls.IPV6_OPEN)
                    .removeSuffix(CoreUrls.IPV6_CLOSE),
            )
        }
        return connection
    }

    /**
     * An HTTPS connection to an address literal that still speaks to [host]:
     * the handshake carries the name, and the certificate must match it.
     */
    private fun nameTheHost(
        connection: HttpURLConnection,
        host: String,
    ) {
        if (connection !is HttpsURLConnection) {
            throw HttpFailure.Transport(retryable = false)
        }
        connection.sslSocketFactory = NamedHostSocketFactory(connection.sslSocketFactory, host)
        connection.hostnameVerifier = HostnameVerifier { _, session -> hostnameVerifier.verify(host, session) }
    }

    private fun exchange(
        connection: HttpURLConnection,
        request: Request,
        maxBytes: ULong,
    ): Answer {
        try {
            request.body?.let { body -> connection.outputStream.use { output -> output.write(body) } }
            val status = connection.responseCode
            return when {
                status in SUCCESS_STATUSES -> {
                    Answer.Body(readBounded(connection, maxBytes))
                }

                status in REDIRECT_STATUSES -> {
                    Answer.Redirect(
                        location = connection.getHeaderField(LOCATION_HEADER) ?: throw HttpFailure.UnsafeRedirect(),
                        preservesMethod = status in METHOD_PRESERVING_REDIRECT_STATUSES,
                    )
                }

                else -> {
                    throw HttpFailure.Status(status.toUShort())
                }
            }
        } catch (failure: IOException) {
            throw transportFailure(failure)
        } finally {
            try {
                connection.errorStream?.close()
            } catch (_: IOException) {
                // Closing the error stream is best-effort cleanup.
            }
            connection.disconnect()
        }
    }

    private fun bound(maxBytes: ULong): Int = maxBytes.coerceAtMost(Int.MAX_VALUE.toULong()).toInt()

    private fun readBounded(
        connection: HttpURLConnection,
        maxBytes: ULong,
    ): ByteArray {
        val bound = bound(maxBytes)
        if (connection.contentLengthLong > bound) {
            throw HttpFailure.BodyTooLarge()
        }
        val body = ByteArrayOutputStream()
        val chunk = ByteArray(RESPONSE_CHUNK_LENGTH_BYTES)
        connection.inputStream.use { input ->
            while (true) {
                val read = input.read(chunk)
                if (read == END_OF_STREAM) {
                    break
                }
                if (body.size() + read > bound) {
                    throw HttpFailure.BodyTooLarge()
                }
                body.write(chunk, 0, read)
            }
        }
        return body.toByteArray()
    }

    private fun transportFailure(failure: IOException): HttpFailure =
        HttpFailure.Transport(
            retryable =
                failure is SocketTimeoutException ||
                    failure is UnknownHostException ||
                    failure is ConnectException ||
                    failure is NoRouteToHostException ||
                    failure is SocketException,
        )

    internal companion object {
        const val USER_AGENT = "RefineID"
        private const val SCHEME_HTTPS = "https"
        private const val METHOD_GET = "GET"
        private const val METHOD_POST = "POST"
        private const val SUCCESS_STATUS_FLOOR = 200
        private const val SUCCESS_STATUS_CEILING = 299
        private val SUCCESS_STATUSES = SUCCESS_STATUS_FLOOR..SUCCESS_STATUS_CEILING
        private const val MOVED_PERMANENTLY_STATUS = 301
        private const val FOUND_STATUS = 302
        private const val SEE_OTHER_STATUS = 303
        private const val TEMPORARY_REDIRECT_STATUS = 307
        private const val PERMANENT_REDIRECT_STATUS = 308
        private val REDIRECT_STATUSES =
            setOf(
                MOVED_PERMANENTLY_STATUS,
                FOUND_STATUS,
                SEE_OTHER_STATUS,
                TEMPORARY_REDIRECT_STATUS,
                PERMANENT_REDIRECT_STATUS,
            )
        private val METHOD_PRESERVING_REDIRECT_STATUSES = setOf(TEMPORARY_REDIRECT_STATUS, PERMANENT_REDIRECT_STATUS)

        /** Hops a certificate-published URL may take, as the core's own transports allow. */
        private const val MAXIMUM_CERTIFICATE_REDIRECTS = 2

        /** Hops a timestamp authority may take: one, within its origin. */
        private const val MAXIMUM_AUTHORITY_REDIRECTS = 1
        private const val EXCHANGE_TIMEOUT_MILLISECONDS = 30_000
        private const val RESPONSE_CHUNK_LENGTH_BYTES = 8_192
        private const val END_OF_STREAM = -1
        private const val PORT_UNSPECIFIED = -1
        private const val DEFAULT_HTTP_PORT = 80
        private const val USER_AGENT_HEADER = "User-Agent"
        private const val ACCEPT_HEADER = "Accept"
        private const val ACCEPT_ANY_MEDIA_TYPE = "*/*"
        private const val HOST_HEADER = "Host"
        private const val CONTENT_TYPE_HEADER = "Content-Type"
        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val LOCATION_HEADER = "Location"
        private const val IPV6_ZONE_SEPARATOR = "%"
    }
}

/**
 * [operation] as the core's callback: every failure leaves as an
 * [HttpFailure], since an unchecked exception must not cross into the
 * core.
 */
private inline fun <T> boundary(operation: () -> T): T =
    try {
        operation()
    } catch (failure: HttpFailure) {
        throw failure
    } catch (_: RuntimeException) {
        throw HttpFailure.Transport(retryable = false)
    }
