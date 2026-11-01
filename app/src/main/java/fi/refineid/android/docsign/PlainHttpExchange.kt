// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import uniffi.refineid_doc_sign_android.HttpFailure
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import javax.net.SocketFactory

/** What one plain HTTP exchange answered: a status, its `Location`, and the body of a success. */
internal class PlainHttpAnswer(
    val status: Int,
    val location: String?,
    val body: ByteArray?,
)

/**
 * HTTP/1.1 over a plain socket to one address, for the core's cleartext
 * fetches: the timestamp authority and the chain and revocation addresses
 * certificates publish over `http`. The platform's HTTP stack resolves the
 * name itself and refuses cleartext to an address literal, so a request
 * to a vetted address goes over a socket connected to that address, with
 * the name in `Host`. One request per connection (`Connection: close`);
 * the answer's status line, headers and body are bounded and parsed
 * strictly, and anything else is a transport failure.
 */
internal class PlainHttpExchange(
    private val socketFactory: SocketFactory = SocketFactory.getDefault(),
    private val timeoutMilliseconds: Int,
) {
    /**
     * A socket connected to [target].
     *
     * @throws IOException when the connection is refused or times out.
     */
    fun connect(target: InetSocketAddress): Socket {
        val socket = socketFactory.createSocket()
        try {
            socket.soTimeout = timeoutMilliseconds
            socket.connect(target, timeoutMilliseconds)
        } catch (failure: IOException) {
            socket.close()
            throw failure
        }
        return socket
    }

    /**
     * Send [method] for [uri] with [headers] and [body] over [socket], read
     * the answer and close the socket. A success's body is read up to
     * [maxBytes].
     *
     * @throws IOException when the exchange breaks off.
     * @throws HttpFailure when the answer is malformed or the body too large.
     */
    fun exchange(
        socket: Socket,
        uri: URI,
        method: String,
        headers: List<Pair<String, String>>,
        body: ByteArray?,
        maxBytes: Int,
    ): PlainHttpAnswer =
        socket.use {
            val head = requestHead(uri, method, headers, body).toByteArray(StandardCharsets.US_ASCII)
            socket.getOutputStream().let { output ->
                output.write(head)
                body?.let(output::write)
                output.flush()
            }
            readAnswer(BufferedInputStream(socket.getInputStream()), method, maxBytes)
        }

    private fun requestHead(
        uri: URI,
        method: String,
        headers: List<Pair<String, String>>,
        body: ByteArray?,
    ): String =
        buildString {
            val target =
                uri.rawPath.orEmpty().ifEmpty { ROOT_PATH } + (uri.rawQuery?.let { QUERY_SEPARATOR + it } ?: "")
            requireHeaderText(target)
            append(method)
                .append(SPACE)
                .append(target)
                .append(SPACE)
                .append(HTTP_VERSION)
                .append(CRLF)
            headers.forEach { (name, value) ->
                requireHeaderText(name)
                requireHeaderText(value)
                append(name).append(HEADER_SEPARATOR).append(value).append(CRLF)
            }
            if (body != null) {
                append(CONTENT_LENGTH_HEADER).append(HEADER_SEPARATOR).append(body.size).append(CRLF)
            }
            append(CONNECTION_HEADER).append(HEADER_SEPARATOR).append(CONNECTION_CLOSE).append(CRLF)
            append(CRLF)
        }

    private fun readAnswer(
        input: InputStream,
        method: String,
        maxBytes: Int,
    ): PlainHttpAnswer {
        var interim = 0
        while (true) {
            val status = statusOf(readLine(input))
            val headers = readHeaders(input)
            if (status in INFORMATIONAL_STATUSES) {
                interim += 1
                if (interim > MAXIMUM_INTERIM_ANSWERS) {
                    throw malformed()
                }
                continue
            }
            val location = headers[LOCATION_HEADER_KEY]
            if (status !in SUCCESS_STATUSES) {
                return PlainHttpAnswer(status, location, null)
            }
            val body =
                if (method == METHOD_HEAD || status in BODYLESS_STATUSES) {
                    ByteArray(0)
                } else {
                    readBody(input, headers, maxBytes)
                }
            return PlainHttpAnswer(status, location, body)
        }
    }

    /** The status code of an `HTTP/1.x` status line. */
    private fun statusOf(line: String): Int {
        if (!line.startsWith(HTTP_VERSION_PREFIX)) {
            throw malformed()
        }
        val parts = line.split(SPACE, limit = STATUS_LINE_PARTS)
        val code = parts.getOrNull(STATUS_CODE_PART) ?: throw malformed()
        if (code.length != STATUS_CODE_DIGITS || !code.all(Char::isDigit)) {
            throw malformed()
        }
        return code.toInt()
    }

    /** The header block, keyed by lower-case name; a repeated name keeps its values joined. */
    private fun readHeaders(input: InputStream): Map<String, String> {
        val headers = mutableMapOf<String, String>()
        repeat(MAXIMUM_HEADER_LINES) {
            val line = readLine(input)
            if (line.isEmpty()) {
                return headers
            }
            val separator = line.indexOf(HEADER_NAME_END)
            if (separator <= 0) {
                throw malformed()
            }
            val name = line.substring(0, separator).trim().lowercase()
            val value = line.substring(separator + 1).trim()
            headers[name] = headers[name]?.let { it + LIST_SEPARATOR + value } ?: value
        }
        throw malformed()
    }

    private fun readBody(
        input: InputStream,
        headers: Map<String, String>,
        maxBytes: Int,
    ): ByteArray {
        val encoding = headers[TRANSFER_ENCODING_HEADER_KEY]
        if (encoding != null) {
            if (encoding
                    .lowercase()
                    .split(LIST_SEPARATOR)
                    .map(String::trim)
                    .last() != CHUNKED
            ) {
                throw malformed()
            }
            return readChunked(input, maxBytes)
        }
        val length = headers[CONTENT_LENGTH_HEADER_KEY]
        if (length != null) {
            val declared = length.toLongOrNull()?.takeIf { it >= 0 } ?: throw malformed()
            if (declared > maxBytes) {
                throw HttpFailure.BodyTooLarge()
            }
            return readExactly(input, declared.toInt())
        }
        return readToEnd(input, maxBytes)
    }

    private fun readChunked(
        input: InputStream,
        maxBytes: Int,
    ): ByteArray {
        val body = ByteArrayOutputStream()
        while (true) {
            val sizeText = readLine(input).substringBefore(CHUNK_EXTENSION_SEPARATOR).trim()
            if (sizeText.isEmpty() || sizeText.length > MAXIMUM_CHUNK_SIZE_DIGITS) {
                throw malformed()
            }
            val size = sizeText.toLongOrNull(HEXADECIMAL_RADIX)?.takeIf { it >= 0 } ?: throw malformed()
            if (size == 0L) {
                readHeaders(input)
                return body.toByteArray()
            }
            if (body.size() + size > maxBytes) {
                throw HttpFailure.BodyTooLarge()
            }
            body.write(readExactly(input, size.toInt()))
            if (readLine(input).isNotEmpty()) {
                throw malformed()
            }
        }
    }

    private fun readExactly(
        input: InputStream,
        length: Int,
    ): ByteArray {
        val bytes = input.readNBytes(length)
        if (bytes.size != length) {
            throw IOException("the answer ended inside its body")
        }
        return bytes
    }

    private fun readToEnd(
        input: InputStream,
        maxBytes: Int,
    ): ByteArray {
        val bytes = input.readNBytes(maxBytes)
        if (input.read() != END_OF_STREAM) {
            throw HttpFailure.BodyTooLarge()
        }
        return bytes
    }

    /** One header-block line without its line ending, at most [MAXIMUM_LINE_BYTES] long. */
    private fun readLine(input: InputStream): String {
        val line = ByteArrayOutputStream()
        while (true) {
            val next = input.read()
            when (next) {
                END_OF_STREAM -> {
                    throw IOException("the answer ended inside its head")
                }

                LINE_FEED -> {
                    val bytes = line.toByteArray()
                    val length = if (bytes.lastOrNull() == CARRIAGE_RETURN) bytes.size - 1 else bytes.size
                    return String(bytes, 0, length, StandardCharsets.ISO_8859_1)
                }

                else -> {
                    if (line.size() >= MAXIMUM_LINE_BYTES) {
                        throw malformed()
                    }
                    line.write(next)
                }
            }
        }
    }

    private fun requireHeaderText(text: String) {
        if (text.any { it == CR_CHARACTER || it == LF_CHARACTER || it == NUL_CHARACTER || it.code > ASCII_MAXIMUM }) {
            throw HttpFailure.BadUrl()
        }
    }

    private fun malformed(): HttpFailure = HttpFailure.Transport(retryable = false)

    private companion object {
        const val HTTP_VERSION = "HTTP/1.1"
        const val HTTP_VERSION_PREFIX = "HTTP/1."
        const val METHOD_HEAD = "HEAD"
        const val ROOT_PATH = "/"
        const val QUERY_SEPARATOR = "?"
        const val SPACE = " "
        const val CRLF = "\r\n"
        const val HEADER_SEPARATOR = ": "
        const val HEADER_NAME_END = ':'
        const val LIST_SEPARATOR = ","
        const val CHUNK_EXTENSION_SEPARATOR = ';'
        const val CHUNKED = "chunked"
        const val CONTENT_LENGTH_HEADER = "Content-Length"
        const val CONNECTION_HEADER = "Connection"
        const val CONNECTION_CLOSE = "close"
        const val CONTENT_LENGTH_HEADER_KEY = "content-length"
        const val TRANSFER_ENCODING_HEADER_KEY = "transfer-encoding"
        const val LOCATION_HEADER_KEY = "location"
        const val STATUS_LINE_PARTS = 3
        const val STATUS_CODE_PART = 1
        const val STATUS_CODE_DIGITS = 3
        const val INFORMATIONAL_FLOOR = 100
        const val INFORMATIONAL_CEILING = 199
        val INFORMATIONAL_STATUSES = INFORMATIONAL_FLOOR..INFORMATIONAL_CEILING
        const val SUCCESS_FLOOR = 200
        const val SUCCESS_CEILING = 299
        val SUCCESS_STATUSES = SUCCESS_FLOOR..SUCCESS_CEILING
        const val NO_CONTENT_STATUS = 204
        const val RESET_CONTENT_STATUS = 205
        val BODYLESS_STATUSES = setOf(NO_CONTENT_STATUS, RESET_CONTENT_STATUS)

        /** Interim (1xx) answers tolerated before the final one. */
        const val MAXIMUM_INTERIM_ANSWERS = 4

        /** Lines in one header block, the blank line included. */
        const val MAXIMUM_HEADER_LINES = 128

        /** Bytes in one status, header or chunk-size line. */
        const val MAXIMUM_LINE_BYTES = 8_192

        /** Hexadecimal digits of a chunk size; more cannot fit a body bound. */
        const val MAXIMUM_CHUNK_SIZE_DIGITS = 8
        const val HEXADECIMAL_RADIX = 16
        const val END_OF_STREAM = -1
        const val LINE_FEED = '\n'.code
        const val CARRIAGE_RETURN = '\r'.code.toByte()
        const val CR_CHARACTER = '\r'
        const val LF_CHARACTER = '\n'
        const val NUL_CHARACTER = '\u0000'

        // The last printable ASCII character.
        const val ASCII_MAXIMUM = '~'.code
    }
}
