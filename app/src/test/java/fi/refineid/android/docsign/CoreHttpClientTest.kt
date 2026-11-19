// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.refineid_doc_sign_android.HttpFailure
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference

class CoreHttpClientTest {
    private lateinit var server: HttpServer
    private lateinit var root: String
    private lateinit var loopback: String
    private val seenHost = AtomicReference<String?>()
    private val seenUserAgent = AtomicReference<String?>()
    private val seenAuthorization = AtomicReference<String?>()
    private val seenContentType = AtomicReference<String?>()
    private val seenMethod = AtomicReference<String?>()
    private val seenBody = AtomicReference<ByteArray?>()
    private val vetted = mutableListOf<String>()

    @Before
    fun startServer() {
        server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), EPHEMERAL_PORT), DEFAULT_BACKLOG)
        server.createContext(INSPECT_PATH) { exchange ->
            seenHost.set(exchange.requestHeaders.getFirst(HOST_HEADER))
            seenUserAgent.set(exchange.requestHeaders.getFirst(USER_AGENT_HEADER))
            seenAuthorization.set(exchange.requestHeaders.getFirst(AUTHORIZATION_HEADER))
            seenContentType.set(exchange.requestHeaders.getFirst(CONTENT_TYPE_HEADER))
            seenMethod.set(exchange.requestMethod)
            seenBody.set(exchange.requestBody.use { it.readBytes() })
            exchange.respond(OK_STATUS, RESPONSE)
        }
        server.createContext(REDIRECT_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, INSPECT_PATH)
            exchange.sendResponseHeaders(TEMPORARY_REDIRECT_STATUS, NO_BODY)
            exchange.close()
        }
        server.createContext(SEE_OTHER_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, INSPECT_PATH)
            exchange.sendResponseHeaders(SEE_OTHER_STATUS, NO_BODY)
            exchange.close()
        }
        server.createContext(LOOP_PATH) { exchange ->
            exchange.responseHeaders.add(LOCATION_HEADER, LOOP_PATH)
            exchange.sendResponseHeaders(TEMPORARY_REDIRECT_STATUS, NO_BODY)
            exchange.close()
        }
        server.createContext(UNAVAILABLE_PATH) { exchange -> exchange.respond(UNAVAILABLE_STATUS, RESPONSE) }
        server.start()
        loopback = checkNotNull(InetAddress.getLoopbackAddress().hostAddress)
        root = "http://localhost:${server.address.port}"
    }

    @After
    fun stopServer() {
        server.stop(STOP_AT_ONCE)
    }

    private fun client(authorityRedirect: Boolean = true) =
        CoreHttpClient(
            vet = { target ->
                vetted += target
                listOf(loopback)
            },
            authorityRedirect = { _, _ -> authorityRedirect },
        )

    @Test
    fun getConnectsToTheVettedAddressAndNamesTheHostAndItself() {
        val body = client().get(root + INSPECT_PATH, listOf(loopback), BOUND)

        assertArrayEquals(RESPONSE, body)
        assertEquals("localhost:${server.address.port}", seenHost.get())
        assertEquals(CoreHttpClient.USER_AGENT, seenUserAgent.get())
        assertEquals(GET, seenMethod.get())
        assertTrue(vetted.isEmpty())
    }

    @Test
    fun postCarriesBodyAndTypeAcrossAVettedRedirect() {
        val body = client().post(root + REDIRECT_PATH, listOf(loopback), CONTENT_TYPE, REQUEST, BOUND)

        assertArrayEquals(RESPONSE, body)
        assertEquals(POST, seenMethod.get())
        assertEquals(CONTENT_TYPE, seenContentType.get())
        assertArrayEquals(REQUEST, seenBody.get())
        assertEquals(listOf(root + INSPECT_PATH), vetted)
    }

    @Test
    fun seeOtherBecomesABodylessGet() {
        client().post(root + SEE_OTHER_PATH, listOf(loopback), CONTENT_TYPE, REQUEST, BOUND)

        assertEquals(GET, seenMethod.get())
        assertArrayEquals(byteArrayOf(), seenBody.get())
    }

    @Test
    fun anAuthorityPostCarriesTheAuthorizationAndObeysTheRedirectRule() {
        client().postAuthority(root + INSPECT_PATH, CONTENT_TYPE, REQUEST, BOUND, AUTHORIZATION)
        assertEquals(AUTHORIZATION, seenAuthorization.get())

        client(authorityRedirect = true).postAuthority(root + REDIRECT_PATH, CONTENT_TYPE, REQUEST, BOUND, null)
        assertEquals(POST, seenMethod.get())

        assertThrows(HttpFailure.UnsafeRedirect::class.java) {
            client(authorityRedirect = false).postAuthority(root + REDIRECT_PATH, CONTENT_TYPE, REQUEST, BOUND, null)
        }
    }

    @Test
    fun aRedirectBudgetAStatusAndAnOversizedBodyAreRefusedByName() {
        assertThrows(HttpFailure.UnsafeRedirect::class.java) {
            client().get(root + LOOP_PATH, listOf(loopback), BOUND)
        }
        val status =
            assertThrows(HttpFailure.Status::class.java) {
                client().get(root + UNAVAILABLE_PATH, listOf(loopback), BOUND)
            }
        assertEquals(UNAVAILABLE_STATUS.toUShort(), status.code)
        assertThrows(HttpFailure.BodyTooLarge::class.java) {
            client().get(root + INSPECT_PATH, listOf(loopback), (RESPONSE.size - 1).toULong())
        }
    }

    @Test
    fun aBadUrlAndAnUnreachableAddressAreRefusedByName() {
        assertThrows(HttpFailure.BadUrl::class.java) { client().get(NOT_HTTP, listOf(loopback), BOUND) }
        val transport =
            assertThrows(HttpFailure.Transport::class.java) {
                client().get(UNREACHABLE, listOf(loopback), BOUND)
            }
        assertTrue(transport.retryable)
    }

    @Test
    fun resolveAnswersAddressLiteralsAsText() {
        assertEquals(listOf(loopback), client().resolve(loopback))
    }

    private fun HttpExchange.respond(
        status: Int,
        body: ByteArray,
    ) {
        sendResponseHeaders(status, body.size.toLong())
        responseBody.use { it.write(body) }
        close()
    }

    private companion object {
        const val EPHEMERAL_PORT = 0
        const val DEFAULT_BACKLOG = 0
        const val STOP_AT_ONCE = 0
        const val OK_STATUS = 200
        const val SEE_OTHER_STATUS = 303
        const val TEMPORARY_REDIRECT_STATUS = 307
        const val UNAVAILABLE_STATUS = 503
        const val NO_BODY = -1L
        const val BOUND = 64UL
        const val INSPECT_PATH = "/inspect"
        const val REDIRECT_PATH = "/redirect"
        const val SEE_OTHER_PATH = "/see-other"
        const val LOOP_PATH = "/loop"
        const val UNAVAILABLE_PATH = "/unavailable"
        const val HOST_HEADER = "Host"
        const val USER_AGENT_HEADER = "User-Agent"
        const val AUTHORIZATION_HEADER = "Authorization"
        const val CONTENT_TYPE_HEADER = "Content-Type"
        const val LOCATION_HEADER = "Location"
        const val GET = "GET"
        const val POST = "POST"
        const val CONTENT_TYPE = "application/synthetic-request"
        const val AUTHORIZATION = "Basic c3ludGhldGljOnNlY3JldA=="
        const val NOT_HTTP = "ftp://example.invalid/"
        const val UNREACHABLE = "http://127.0.0.1:1/"
        val REQUEST = "request".encodeToByteArray()
        val RESPONSE = "okay".encodeToByteArray()
    }
}
