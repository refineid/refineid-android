// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.Proxy
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit

/** Bounded, manually redirected HTTP transport for public signing services. */
internal class HttpSigningNetwork(
    private val resolver: SigningNetworkResolver = SystemSigningNetworkResolver,
    private val client: OkHttpClient = signingHttpClient,
) : SigningNetworkTransport {
    override fun get(
        address: String,
        maximumResponseBytes: Int,
        endpoint: SigningNetworkEndpoint,
    ): ByteArray {
        requireResponseLimit(maximumResponseBytes)
        val initial = SigningNetworkPolicy.getRequest(address, endpoint)
        return perform(initial, maximumResponseBytes)
    }

    override fun post(
        body: ByteArray,
        address: String,
        contentType: String,
        credentials: SigningNetworkBasicCredentials?,
        maximumResponseBytes: Int,
        endpoint: SigningNetworkEndpoint,
    ): ByteArray {
        requireResponseLimit(maximumResponseBytes)
        val initial =
            SigningNetworkPolicy.postRequest(
                body = body,
                address = address,
                contentType = contentType,
                credentials = credentials,
                endpoint = endpoint,
            )
        return perform(initial, maximumResponseBytes)
    }

    private fun perform(
        initial: SigningNetworkRequest,
        maximumResponseBytes: Int,
    ): ByteArray {
        var current: SigningNetworkRequest? = initial
        var redirectsFollowed = NO_REDIRECTS_FOLLOWED
        try {
            current = replaceWithProtected(checkNotNull(current))
            while (true) {
                when (val response = exchange(checkNotNull(current), maximumResponseBytes)) {
                    is ExchangeResult.Body -> {
                        return response.bytes
                    }

                    is ExchangeResult.Redirect -> {
                        val target = redirectTarget(checkNotNull(current), response.location)
                        val redirected =
                            SigningNetworkPolicy.redirected(
                                current = checkNotNull(current),
                                target = target,
                                redirectsFollowed = redirectsFollowed,
                                preservesMethod = response.preservesMethod,
                                resolver = resolver,
                            )
                        current.close()
                        current = redirected
                        redirectsFollowed += REDIRECT_COUNT_STEP
                    }
                }
            }
        } catch (failure: SigningNetworkException) {
            throw failure
        } catch (failure: IOException) {
            throw transportFailure(failure)
        } catch (_: RuntimeException) {
            throw SigningNetworkException(SigningNetworkFailure.TRANSPORT)
        } finally {
            current?.close()
        }
    }

    private fun replaceWithProtected(request: SigningNetworkRequest): SigningNetworkRequest {
        val protected = SigningNetworkPolicy.protect(request, resolver)
        request.close()
        return protected
    }

    private fun exchange(
        request: SigningNetworkRequest,
        maximumResponseBytes: Int,
    ): ExchangeResult {
        val pinnedAddress =
            SigningNetworkAddressPolicy.numericAddress(request.connectionUri.host)
                ?: throw SigningNetworkException(SigningNetworkFailure.UNSAFE_ADDRESS)
        val pinnedClient =
            client
                .newBuilder()
                .dns { listOf(pinnedAddress) }
                .proxy(Proxy.NO_PROXY)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .cache(null)
                .build()
        val body = request.copyBody()
        return try {
            val outgoing = Request.Builder().url(request.logicalUri.toString())
            outgoing.header(ACCEPT_HEADER, ACCEPT_ANY_MEDIA_TYPE)
            request.contentType?.let { outgoing.header(CONTENT_TYPE_HEADER, it) }
            request.authorizationHeader()?.let { outgoing.header(AUTHORIZATION_HEADER, it) }
            outgoing.method(request.method.name, body?.toRequestBody())
            pinnedClient.newCall(outgoing.build()).execute().use { response ->
                when {
                    response.code in SUCCESS_STATUS_FLOOR..SUCCESS_STATUS_CEILING -> {
                        ExchangeResult.Body(readResponse(response, maximumResponseBytes))
                    }

                    response.code in REDIRECT_STATUSES -> {
                        val location =
                            response.header(LOCATION_HEADER)
                                ?: throw SigningNetworkException(SigningNetworkFailure.UNSAFE_REDIRECT)
                        ExchangeResult.Redirect(
                            location = location,
                            preservesMethod = response.code in METHOD_PRESERVING_REDIRECT_STATUSES,
                        )
                    }

                    else -> {
                        throw SigningNetworkException(SigningNetworkFailure.HTTP_STATUS, response.code)
                    }
                }
            }
        } finally {
            body?.fill(CLEARED_BYTE)
        }
    }

    private fun readResponse(
        response: Response,
        maximumResponseBytes: Int,
    ): ByteArray {
        val responseBody = response.body
        if (responseBody.contentLength() > maximumResponseBytes) {
            throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
        }
        val body = SigningNetworkResponseBody(maximumResponseBytes)
        responseBody.byteStream().use { input -> readBounded(input, body) }
        if (body.size == EMPTY_BODY_LENGTH) {
            throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
        }
        return body.toByteArray()
    }

    private fun readBounded(
        input: InputStream,
        body: SigningNetworkResponseBody,
    ) {
        val chunk = ByteArray(RESPONSE_CHUNK_LENGTH_BYTES)
        var emptyReads = NO_EMPTY_READS
        while (true) {
            val read = input.read(chunk)
            when {
                read == END_OF_STREAM -> {
                    return
                }

                read == EMPTY_READ_LENGTH -> {
                    emptyReads += EMPTY_READ_COUNT_STEP
                    if (emptyReads > MAXIMUM_CONSECUTIVE_EMPTY_READS) {
                        throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
                    }
                }

                !body.append(chunk, read) -> {
                    throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
                }

                else -> {
                    emptyReads = NO_EMPTY_READS
                }
            }
        }
    }

    private fun redirectTarget(
        current: SigningNetworkRequest,
        location: String,
    ): URI {
        if (location.isEmpty() || location.length > SigningNetworkLimits.MAXIMUM_ADDRESS_CHARACTERS) {
            throw SigningNetworkException(SigningNetworkFailure.UNSAFE_REDIRECT)
        }
        return try {
            current.logicalUri.resolve(location)
        } catch (_: IllegalArgumentException) {
            throw SigningNetworkException(SigningNetworkFailure.UNSAFE_REDIRECT)
        }
    }

    private fun requireResponseLimit(maximumResponseBytes: Int) {
        if (maximumResponseBytes !in MINIMUM_RESPONSE_BYTES..SigningNetworkLimits.MAXIMUM_RESPONSE_BYTES) {
            throw SigningNetworkException(SigningNetworkFailure.UNUSABLE_BODY)
        }
    }

    private fun transportFailure(failure: IOException): SigningNetworkException {
        val transient =
            failure is SocketTimeoutException ||
                failure is UnknownHostException ||
                failure is ConnectException ||
                failure is NoRouteToHostException ||
                failure is SocketException
        return SigningNetworkException(
            if (transient) {
                SigningNetworkFailure.TRANSIENT_TRANSPORT
            } else {
                SigningNetworkFailure.TRANSPORT
            },
        )
    }

    private sealed interface ExchangeResult {
        data class Body(
            val bytes: ByteArray,
        ) : ExchangeResult

        data class Redirect(
            val location: String,
            val preservesMethod: Boolean,
        ) : ExchangeResult
    }

    internal companion object {
        private const val NO_IDLE_CONNECTIONS = 0
        private const val CONNECTION_KEEP_ALIVE_SECONDS = 1L
        private val signingHttpClient =
            OkHttpClient
                .Builder()
                .connectTimeout(EXCHANGE_TIMEOUT_MILLISECONDS.toLong(), TimeUnit.MILLISECONDS)
                .readTimeout(EXCHANGE_TIMEOUT_MILLISECONDS.toLong(), TimeUnit.MILLISECONDS)
                .callTimeout(EXCHANGE_TIMEOUT_MILLISECONDS.toLong(), TimeUnit.MILLISECONDS)
                .connectionPool(ConnectionPool(NO_IDLE_CONNECTIONS, CONNECTION_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS))
                .build()

        fun isTransientAuthorityFailure(failure: Throwable): Boolean {
            if (failure !is SigningNetworkException) {
                return false
            }
            if (failure.kind == SigningNetworkFailure.TRANSIENT_TRANSPORT) {
                return true
            }
            return failure.kind == SigningNetworkFailure.HTTP_STATUS &&
                failure.httpStatus in TRANSIENT_AUTHORITY_STATUSES
        }

        private const val SUCCESS_STATUS_FLOOR = 200
        private const val SUCCESS_STATUS_CEILING = 299
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
        private val METHOD_PRESERVING_REDIRECT_STATUSES =
            setOf(
                TEMPORARY_REDIRECT_STATUS,
                PERMANENT_REDIRECT_STATUS,
            )
        private const val REQUEST_TIMEOUT_STATUS = 408
        private const val TOO_EARLY_STATUS = 425
        private const val TOO_MANY_REQUESTS_STATUS = 429
        private const val INTERNAL_SERVER_ERROR_STATUS = 500
        private const val BAD_GATEWAY_STATUS = 502
        private const val SERVICE_UNAVAILABLE_STATUS = 503
        private const val GATEWAY_TIMEOUT_STATUS = 504
        private val TRANSIENT_AUTHORITY_STATUSES =
            setOf(
                REQUEST_TIMEOUT_STATUS,
                TOO_EARLY_STATUS,
                TOO_MANY_REQUESTS_STATUS,
                INTERNAL_SERVER_ERROR_STATUS,
                BAD_GATEWAY_STATUS,
                SERVICE_UNAVAILABLE_STATUS,
                GATEWAY_TIMEOUT_STATUS,
            )
        private const val LOCATION_HEADER = "Location"
        private const val ACCEPT_HEADER = "Accept"
        private const val CONTENT_TYPE_HEADER = "Content-Type"
        private const val AUTHORIZATION_HEADER = "Authorization"
        private const val ACCEPT_ANY_MEDIA_TYPE = "*/*"
        private const val EXCHANGE_TIMEOUT_MILLISECONDS = 30_000
        private const val RESPONSE_CHUNK_LENGTH_BYTES = 8_192
        private const val MINIMUM_RESPONSE_BYTES = 1
        private const val EMPTY_BODY_LENGTH = 0
        private const val END_OF_STREAM = -1
        private const val EMPTY_READ_LENGTH = 0
        private const val NO_EMPTY_READS = 0
        private const val EMPTY_READ_COUNT_STEP = 1
        private const val MAXIMUM_CONSECUTIVE_EMPTY_READS = 8
        private const val NO_REDIRECTS_FOLLOWED = 0
        private const val REDIRECT_COUNT_STEP = 1
        private const val CLEARED_BYTE: Byte = 0
    }
}
