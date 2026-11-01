// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_doc_sign_android.HttpFailure
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** The cleartext exchange against a server that answers with scripted bytes. */
class PlainHttpExchangeTest {
    private val server = ServerSocket(EPHEMERAL_PORT, BACKLOG, InetAddress.getLoopbackAddress())
    private val request = AtomicReference<String>()

    @After
    fun stop() {
        server.close()
    }

    /** One exchange against a server that answers [answer] whole. */
    private fun exchange(
        answer: String,
        body: ByteArray? = null,
        maxBytes: Int = BOUND,
    ): PlainHttpAnswer {
        val serving =
            thread {
                server.accept().use { socket ->
                    val head = StringBuilder()
                    val input = socket.getInputStream()
                    while (!head.endsWith(HEAD_END)) {
                        head.append(input.read().toChar())
                    }
                    body?.let { input.readNBytes(it.size) }
                    request.set(head.toString())
                    socket.getOutputStream().write(answer.toByteArray(Charsets.ISO_8859_1))
                }
            }
        try {
            val exchange = PlainHttpExchange(timeoutMilliseconds = TIMEOUT_MILLISECONDS)
            val socket = exchange.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort))
            return exchange.exchange(
                socket = socket,
                uri = URI(URL),
                method = if (body == null) GET else POST,
                headers = listOf(HOST_HEADER to HOST, CONTENT_TYPE_HEADER to CONTENT_TYPE),
                body = body,
                maxBytes = maxBytes,
            )
        } finally {
            serving.join()
        }
    }

    @Test
    fun theRequestNamesTheHostThePathAndTheBodyLength() {
        val answer = exchange(ok(contentLength(PAYLOAD)) + PAYLOAD, body = REQUEST_BODY)

        assertArrayEquals(PAYLOAD.toByteArray(), answer.body)
        val head = request.get()
        assertTrue(head.startsWith("$POST $PATH_AND_QUERY $HTTP_VERSION$CRLF"))
        assertTrue(head.contains("$HOST_HEADER: $HOST$CRLF"))
        assertTrue(head.contains("Content-Length: ${REQUEST_BODY.size}$CRLF"))
        assertTrue(head.contains("Connection: close$CRLF"))
    }

    @Test
    fun aChunkedBodyIsJoinedAndAnInterimAnswerSkipped() {
        val chunked =
            "$HTTP_VERSION 100 Continue$CRLF$CRLF" +
                "$HTTP_VERSION 200 OK${CRLF}Transfer-Encoding: chunked$CRLF$CRLF" +
                chunk(FIRST_CHUNK) + chunk(SECOND_CHUNK) + "0$CRLF$CRLF"

        val answer = exchange(chunked)

        assertEquals(OK_STATUS, answer.status)
        assertArrayEquals((FIRST_CHUNK + SECOND_CHUNK).toByteArray(), answer.body)
    }

    @Test
    fun aBodyToTheEndOfTheStreamIsRead() {
        assertArrayEquals(PAYLOAD.toByteArray(), exchange(ok("") + PAYLOAD).body)
    }

    @Test
    fun aRedirectCarriesItsLocationAndNoBody() {
        val answer = exchange("$HTTP_VERSION 307 Temporary${CRLF}Location: $REDIRECT$CRLF$CRLF")

        assertEquals(TEMPORARY_REDIRECT_STATUS, answer.status)
        assertEquals(REDIRECT, answer.location)
        assertNull(answer.body)
    }

    @Test
    fun anOversizedBodyIsRefusedByEveryFraming() {
        assertThrows(HttpFailure.BodyTooLarge::class.java) {
            exchange(ok(contentLength(PAYLOAD)) + PAYLOAD, maxBytes = PAYLOAD.length - 1)
        }
        assertThrows(HttpFailure.BodyTooLarge::class.java) {
            exchange(
                ok("Transfer-Encoding: chunked$CRLF") + chunk(PAYLOAD) + "0$CRLF$CRLF",
                maxBytes =
                    PAYLOAD.length - 1,
            )
        }
        assertThrows(HttpFailure.BodyTooLarge::class.java) {
            exchange(ok("") + PAYLOAD, maxBytes = PAYLOAD.length - 1)
        }
    }

    @Test
    fun malformedAnswersAreRefusedAsTransportFailures() {
        listOf(
            "SMTP/1.0 200 OK$CRLF$CRLF",
            "$HTTP_VERSION 2xx OK$CRLF$CRLF",
            "$HTTP_VERSION 200 OK${CRLF}no separator$CRLF$CRLF",
            ok("Content-Length: minus$CRLF"),
            ok("Transfer-Encoding: gzip$CRLF"),
            ok("Transfer-Encoding: chunked$CRLF") + "zz$CRLF",
        ).forEach { answer ->
            val failure = assertThrows(HttpFailure.Transport::class.java) { exchange(answer) }
            assertEquals(false, failure.retryable)
        }
    }

    @Test
    fun aTruncatedAnswerBreaksOff() {
        assertThrows(IOException::class.java) { exchange("$HTTP_VERSION 200 OK$CRLF") }
        assertThrows(IOException::class.java) { exchange(ok("Content-Length: ${PAYLOAD.length + 1}$CRLF") + PAYLOAD) }
    }

    @Test
    fun aLineBreakInAHeaderIsRefusedBeforeSending() {
        val exchange = PlainHttpExchange(timeoutMilliseconds = TIMEOUT_MILLISECONDS)
        val socket = Socket()
        assertThrows(HttpFailure.BadUrl::class.java) {
            exchange.exchange(socket, URI(URL), GET, listOf(HOST_HEADER to "$HOST${CRLF}Injected: yes"), null, BOUND)
        }
    }

    private fun ok(headers: String): String = "$HTTP_VERSION 200 OK$CRLF$headers$CRLF"

    private fun contentLength(body: String): String = "Content-Length: ${body.length}$CRLF"

    private fun chunk(text: String): String = Integer.toHexString(text.length) + CRLF + text + CRLF

    private companion object {
        const val EPHEMERAL_PORT = 0
        const val BACKLOG = 1
        const val TIMEOUT_MILLISECONDS = 5_000
        const val BOUND = 64
        const val OK_STATUS = 200
        const val TEMPORARY_REDIRECT_STATUS = 307
        const val HTTP_VERSION = "HTTP/1.1"
        const val CRLF = "\r\n"
        const val HEAD_END = "\r\n\r\n"
        const val GET = "GET"
        const val POST = "POST"
        const val HOST = "ocsp.example"
        const val HOST_HEADER = "Host"
        const val CONTENT_TYPE_HEADER = "Content-Type"
        const val CONTENT_TYPE = "application/synthetic-request"
        const val PATH_AND_QUERY = "/responder?q=1"
        const val URL = "http://$HOST$PATH_AND_QUERY"
        const val REDIRECT = "http://crl.example/list"
        const val PAYLOAD = "answer"
        const val FIRST_CHUNK = "ans"
        const val SECOND_CHUNK = "wer"
        val REQUEST_BODY = "request".toByteArray()
    }
}
