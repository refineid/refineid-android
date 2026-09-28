// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.atomic.AtomicReference

class HttpSigningNetworkTest {
    private lateinit var server: HttpServer
    private lateinit var authorityRoot: String
    private val receivedContentType = AtomicReference<String?>()
    private val receivedMethod = AtomicReference<String?>()
    private val receivedBody = AtomicReference<ByteArray?>()

    @Before
    fun startServer() {
        server =
            HttpServer.create(
                InetSocketAddress(InetAddress.getLoopbackAddress(), EPHEMERAL_PORT),
                DEFAULT_CONNECTION_BACKLOG,
            )
        server.createContext(SUCCESS_PATH) { exchange ->
            exchange.respond(SUCCESS_STATUS, SYNTHETIC_RESPONSE)
        }
        server.createContext(REDIRECT_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, REQUEST_INSPECTION_PATH)
            exchange.sendResponseHeaders(TEMPORARY_REDIRECT_STATUS, NO_RESPONSE_BODY_LENGTH)
            exchange.close()
        }
        server.createContext(SEE_OTHER_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, REQUEST_INSPECTION_PATH)
            exchange.sendResponseHeaders(SEE_OTHER_STATUS, NO_RESPONSE_BODY_LENGTH)
            exchange.close()
        }
        server.createContext(REQUEST_INSPECTION_PATH) { exchange ->
            receivedContentType.set(exchange.requestHeaders.getFirst(CONTENT_TYPE_HEADER))
            receivedMethod.set(exchange.requestMethod)
            receivedBody.set(exchange.requestBody.use { input -> input.readBytes() })
            exchange.respond(SUCCESS_STATUS, SYNTHETIC_RESPONSE)
        }
        server.createContext(OVERSIZED_PATH) { exchange ->
            exchange.respond(SUCCESS_STATUS, OVERSIZED_RESPONSE)
        }
        server.createContext(EMPTY_PATH) { exchange ->
            exchange.sendResponseHeaders(SUCCESS_STATUS, NO_RESPONSE_BODY_LENGTH)
            exchange.close()
        }
        server.createContext(UNAVAILABLE_PATH) { exchange ->
            exchange.respond(SERVICE_UNAVAILABLE_STATUS, SYNTHETIC_ERROR_BODY)
        }
        server.createContext(REDIRECT_LOOP_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, REDIRECT_LOOP_PATH)
            exchange.sendResponseHeaders(TEMPORARY_REDIRECT_STATUS, NO_RESPONSE_BODY_LENGTH)
            exchange.close()
        }
        server.createContext(EMPTY_REDIRECT_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, EMPTY_REDIRECT_LOCATION)
            exchange.sendResponseHeaders(TEMPORARY_REDIRECT_STATUS, NO_RESPONSE_BODY_LENGTH)
            exchange.close()
        }
        server.start()
        authorityRoot = "http://localhost:${server.address.port}"
    }

    @After
    fun stopServer() {
        server.stop(IMMEDIATE_SERVER_STOP_DELAY_SECONDS)
    }

    @Test
    fun returnsOneBoundedSuccessfulBody() {
        val response =
            HttpSigningNetwork().get(
                address = authorityRoot + SUCCESS_PATH,
                maximumResponseBytes = SYNTHETIC_RESPONSE.size,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )

        assertArrayEquals(SYNTHETIC_RESPONSE, response)
    }

    @Test
    fun preservesPostBodyAndContentTypeAcrossTheOneSafeRedirect() {
        val response =
            HttpSigningNetwork().post(
                body = SYNTHETIC_REQUEST,
                address = authorityRoot + REDIRECT_PATH,
                contentType = SYNTHETIC_CONTENT_TYPE,
                credentials = null,
                maximumResponseBytes = SYNTHETIC_REQUEST.size,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )

        assertArrayEquals(SYNTHETIC_RESPONSE, response)
        assertEquals(SYNTHETIC_CONTENT_TYPE, receivedContentType.get())
        assertEquals(POST_METHOD, receivedMethod.get())
        assertArrayEquals(SYNTHETIC_REQUEST, checkNotNull(receivedBody.get()))
    }

    @Test
    fun followsSeeOtherAsABodylessGet() {
        val response =
            HttpSigningNetwork().post(
                body = SYNTHETIC_REQUEST,
                address = authorityRoot + SEE_OTHER_PATH,
                contentType = SYNTHETIC_CONTENT_TYPE,
                credentials = null,
                maximumResponseBytes = SYNTHETIC_RESPONSE.size,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )

        assertArrayEquals(SYNTHETIC_RESPONSE, response)
        assertEquals(GET_METHOD, receivedMethod.get())
        assertNull(receivedContentType.get())
        assertArrayEquals(EMPTY_REQUEST, checkNotNull(receivedBody.get()))
    }

    @Test
    fun refusesDeclaredOverflowAndAnEmptySuccessBody() {
        assertFailure(SigningNetworkFailure.UNUSABLE_BODY) {
            HttpSigningNetwork().get(
                address = authorityRoot + OVERSIZED_PATH,
                maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
        assertFailure(SigningNetworkFailure.UNUSABLE_BODY) {
            HttpSigningNetwork().get(
                address = authorityRoot + EMPTY_PATH,
                maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
    }

    @Test
    fun retainsTheStatusWithoutReadingOrReturningItsBody() {
        val failure =
            assertFailure(SigningNetworkFailure.HTTP_STATUS) {
                HttpSigningNetwork().get(
                    address = authorityRoot + UNAVAILABLE_PATH,
                    maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            }

        assertEquals(SERVICE_UNAVAILABLE_STATUS, failure.httpStatus)
        assertTrue(HttpSigningNetwork.isTransientAuthorityFailure(failure))
        assertFalse(
            HttpSigningNetwork.isTransientAuthorityFailure(
                SigningNetworkException(
                    kind = SigningNetworkFailure.HTTP_STATUS,
                    httpStatus = PERMANENT_CLIENT_FAILURE_STATUS,
                ),
            ),
        )
    }

    @Test
    fun stopsAtTheAuthorityRedirectBudget() {
        assertFailure(SigningNetworkFailure.REDIRECT_LIMIT_EXCEEDED) {
            HttpSigningNetwork().get(
                address = authorityRoot + REDIRECT_LOOP_PATH,
                maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
    }

    @Test
    fun refusesAnEmptyRedirectLocation() {
        assertFailure(SigningNetworkFailure.UNSAFE_REDIRECT) {
            HttpSigningNetwork().get(
                address = authorityRoot + EMPTY_REDIRECT_PATH,
                maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                endpoint = SigningNetworkEndpoint.AUTHORITY,
            )
        }
    }

    @Test
    fun responseAccumulatorNeverRetainsTheLimitPlusOneByte() {
        val body = SigningNetworkResponseBody(MAXIMUM_ACCEPTED_TEST_BODY_BYTES)

        assertTrue(body.append(BOUNDARY_RESPONSE, BOUNDARY_RESPONSE.size))
        assertFalse(body.append(EXCESS_RESPONSE, EXCESS_RESPONSE.size))
        assertArrayEquals(BOUNDARY_RESPONSE, body.toByteArray())
    }

    @Test
    fun classifiesSocketTimeoutAsTransientAndDisconnects() {
        val connection = TimeoutHttpConnection(URL(AUTHORITY_TIMEOUT_ADDRESS))
        val network =
            HttpSigningNetwork(
                connectionFactory = SigningNetworkConnectionFactory { connection },
            )

        val failure =
            assertFailure(SigningNetworkFailure.TRANSIENT_TRANSPORT) {
                network.get(
                    address = AUTHORITY_TIMEOUT_ADDRESS,
                    maximumResponseBytes = MAXIMUM_ACCEPTED_TEST_BODY_BYTES,
                    endpoint = SigningNetworkEndpoint.AUTHORITY,
                )
            }

        assertTrue(HttpSigningNetwork.isTransientAuthorityFailure(failure))
        assertTrue(connection.wasDisconnected)
    }

    private fun HttpExchange.respond(
        status: Int,
        body: ByteArray,
    ) {
        sendResponseHeaders(status, body.size.toLong())
        responseBody.use { output -> output.write(body) }
        close()
    }

    private fun assertFailure(
        expected: SigningNetworkFailure,
        operation: () -> Unit,
    ): SigningNetworkException {
        val failure = assertThrows(SigningNetworkException::class.java, operation)
        assertEquals(expected, failure.kind)
        return failure
    }

    private open class SyntheticHttpConnection(
        url: URL,
    ) : HttpURLConnection(url) {
        var wasDisconnected = false

        override fun connect() = Unit

        override fun disconnect() {
            wasDisconnected = true
        }

        override fun usingProxy(): Boolean = false

        override fun getResponseCode(): Int = SUCCESS_STATUS

        override fun getContentLengthLong(): Long = SYNTHETIC_RESPONSE.size.toLong()

        override fun getInputStream() = ByteArrayInputStream(SYNTHETIC_RESPONSE)
    }

    private class TimeoutHttpConnection(
        url: URL,
    ) : SyntheticHttpConnection(url) {
        override fun getResponseCode(): Int = throw SocketTimeoutException("synthetic timeout")
    }

    private companion object {
        const val EPHEMERAL_PORT = 0
        const val DEFAULT_CONNECTION_BACKLOG = 0
        const val IMMEDIATE_SERVER_STOP_DELAY_SECONDS = 0
        const val SUCCESS_STATUS = 200
        const val SEE_OTHER_STATUS = 303
        const val TEMPORARY_REDIRECT_STATUS = 307
        const val SERVICE_UNAVAILABLE_STATUS = 503
        const val PERMANENT_CLIENT_FAILURE_STATUS = 400
        const val NO_RESPONSE_BODY_LENGTH = -1L
        const val MAXIMUM_ACCEPTED_TEST_BODY_BYTES = 4
        const val LOCATION_HEADER = "Location"
        const val CONTENT_TYPE_HEADER = "Content-Type"
        const val SUCCESS_PATH = "/success"
        const val REDIRECT_PATH = "/redirect"
        const val SEE_OTHER_PATH = "/see-other"
        const val REQUEST_INSPECTION_PATH = "/inspect-request"
        const val OVERSIZED_PATH = "/oversized"
        const val EMPTY_PATH = "/empty"
        const val UNAVAILABLE_PATH = "/unavailable"
        const val REDIRECT_LOOP_PATH = "/redirect-loop"
        const val EMPTY_REDIRECT_PATH = "/empty-redirect"
        const val EMPTY_REDIRECT_LOCATION = ""
        const val SYNTHETIC_CONTENT_TYPE = "application/synthetic-request"
        const val POST_METHOD = "POST"
        const val GET_METHOD = "GET"
        const val AUTHORITY_TIMEOUT_ADDRESS = "https://timestamp.example/timeout"
        val SYNTHETIC_REQUEST = "request".encodeToByteArray()
        val SYNTHETIC_RESPONSE = "okay".encodeToByteArray()
        val OVERSIZED_RESPONSE = "large".encodeToByteArray()
        val SYNTHETIC_ERROR_BODY = "not returned".encodeToByteArray()
        val BOUNDARY_RESPONSE = "1234".encodeToByteArray()
        val EXCESS_RESPONSE = "5".encodeToByteArray()
        val EMPTY_REQUEST = byteArrayOf()
    }
}
