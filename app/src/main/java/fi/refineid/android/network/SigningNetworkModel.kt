// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import java.net.URI
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Why one bounded signing-network exchange was refused. */
internal enum class SigningNetworkFailure {
    BAD_ADDRESS,
    HTTP_STATUS,
    INSECURE_CREDENTIALS,
    REDIRECT_LIMIT_EXCEEDED,
    TRANSIENT_TRANSPORT,
    TRANSPORT,
    UNSAFE_ADDRESS,
    UNSAFE_REDIRECT,
    UNUSABLE_BODY,
}

internal class SigningNetworkException(
    val kind: SigningNetworkFailure,
    val httpStatus: Int? = null,
) : Exception(if (httpStatus == null) kind.name else kind.name + ":" + httpStatus) {
    init {
        require((kind == SigningNetworkFailure.HTTP_STATUS) == (httpStatus != null)) {
            "an HTTP status belongs only to an HTTP-status failure"
        }
    }
}

/** The trust relationship of a network address used during document signing. */
internal enum class SigningNetworkEndpoint {
    /** Holder-configured timestamp authority. */
    AUTHORITY,

    /** Untrusted AIA, OCSP, or CRL address copied from a certificate. */
    CERTIFICATE_MATERIAL,
}

internal enum class SigningNetworkMethod {
    GET,
    POST,
}

/** HTTP Basic credentials whose password storage can be cleared by the caller. */
internal class SigningNetworkBasicCredentials private constructor(
    val username: String,
    private val ownedPassword: CharArray,
) : AutoCloseable {
    private var isClosed = false

    fun authorizationHeader(): String {
        check(!isClosed) {
            "signing-network credentials are closed"
        }
        val plainCharacters =
            CharArray(username.length + BASIC_CREDENTIAL_SEPARATOR_LENGTH + ownedPassword.size)
        username.toCharArray().copyInto(plainCharacters)
        plainCharacters[username.length] = BASIC_CREDENTIAL_SEPARATOR
        ownedPassword.copyInto(
            destination = plainCharacters,
            destinationOffset = username.length + BASIC_CREDENTIAL_SEPARATOR_LENGTH,
        )
        val encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(plainCharacters))
        val plain = ByteArray(encoded.remaining())
        encoded.get(plain)
        return try {
            BASIC_AUTHORIZATION_PREFIX + Base64.getEncoder().encodeToString(plain)
        } finally {
            plainCharacters.fill(CLEARED_CHARACTER)
            plain.fill(CLEARED_BYTE)
            if (encoded.hasArray()) {
                encoded.array().fill(CLEARED_BYTE)
            }
        }
    }

    override fun close() {
        if (!isClosed) {
            ownedPassword.fill(CLEARED_CHARACTER)
            isClosed = true
        }
    }

    override fun toString(): String = "SigningNetworkBasicCredentials([redacted], closed=$isClosed)"

    companion object {
        fun copyOf(
            username: String,
            password: CharArray,
        ): SigningNetworkBasicCredentials {
            if (usernameIsInvalid(username) || passwordIsInvalid(password)) {
                throw IllegalArgumentException("invalid signing-network credentials")
            }
            return SigningNetworkBasicCredentials(username, password.copyOf())
        }

        private fun usernameIsInvalid(username: String): Boolean =
            username.isEmpty() ||
                username.length > SigningNetworkLimits.MAXIMUM_USERNAME_CHARACTERS ||
                username.contains(BASIC_CREDENTIAL_SEPARATOR) ||
                username.any(::isForbiddenHeaderCharacter)

        private fun passwordIsInvalid(password: CharArray): Boolean =
            password.size > SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS ||
                password.any(::isForbiddenHeaderCharacter)

        private fun isForbiddenHeaderCharacter(character: Char): Boolean =
            character == CARRIAGE_RETURN || character == LINE_FEED || character == NULL_CHARACTER

        private const val BASIC_AUTHORIZATION_PREFIX = "Basic "
        private const val BASIC_CREDENTIAL_SEPARATOR = ':'
        private const val BASIC_CREDENTIAL_SEPARATOR_LENGTH = 1
        private const val CARRIAGE_RETURN = '\r'
        private const val LINE_FEED = '\n'
        private const val NULL_CHARACTER = '\u0000'
        private const val CLEARED_CHARACTER = '\u0000'
        private const val CLEARED_BYTE: Byte = 0
    }
}

/** One request after endpoint policy and DNS pinning have been applied. */
internal class SigningNetworkRequest internal constructor(
    val initialUri: URI,
    val logicalUri: URI,
    val connectionUri: URI,
    val method: SigningNetworkMethod,
    val endpoint: SigningNetworkEndpoint,
    val contentType: String?,
    private val ownedBody: ByteArray?,
    private val authorization: String?,
) : AutoCloseable {
    private var isClosed = false

    val carriesCredentials: Boolean
        get() = authorization != null

    val bodyLength: Int
        get() = ownedBody?.size ?: NO_BODY_LENGTH

    fun copyBody(): ByteArray? {
        requireOpen()
        return ownedBody?.copyOf()
    }

    fun authorizationHeader(): String? {
        requireOpen()
        return authorization
    }

    fun copy(
        initialUri: URI = this.initialUri,
        logicalUri: URI = this.logicalUri,
        connectionUri: URI = this.connectionUri,
        method: SigningNetworkMethod = this.method,
        contentType: String? = this.contentType,
    ): SigningNetworkRequest {
        requireOpen()
        return SigningNetworkRequest(
            initialUri = initialUri,
            logicalUri = logicalUri,
            connectionUri = connectionUri,
            method = method,
            endpoint = endpoint,
            contentType = contentType,
            ownedBody = if (method == SigningNetworkMethod.POST) ownedBody?.copyOf() else null,
            authorization = authorization,
        )
    }

    override fun close() {
        if (!isClosed) {
            ownedBody?.fill(CLEARED_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String =
        "SigningNetworkRequest(method=$method, endpoint=$endpoint, bodyLength=$bodyLength, " +
            "credentials=$carriesCredentials, closed=$isClosed)"

    private fun requireOpen() {
        check(!isClosed) {
            "signing-network request is closed"
        }
    }

    private companion object {
        const val NO_BODY_LENGTH = 0
        const val CLEARED_BYTE: Byte = 0
    }
}

/** Network dependency shared by timestamp and validation-material orchestration. */
internal interface SigningNetworkTransport {
    fun get(
        address: String,
        maximumResponseBytes: Int,
        endpoint: SigningNetworkEndpoint,
    ): ByteArray

    fun post(
        body: ByteArray,
        address: String,
        contentType: String,
        credentials: SigningNetworkBasicCredentials?,
        maximumResponseBytes: Int,
        endpoint: SigningNetworkEndpoint,
    ): ByteArray
}

internal object SigningNetworkLimits {
    const val MAXIMUM_ADDRESS_CHARACTERS = 8_192
    const val MAXIMUM_HEADER_VALUE_CHARACTERS = 1_024
    const val MAXIMUM_USERNAME_CHARACTERS = 256
    const val MAXIMUM_PASSWORD_CHARACTERS = 1_024
    const val MAXIMUM_SHORT_RESPONSE_BYTES = 65_536
    const val MAXIMUM_REQUEST_BYTES = 65_536
    const val MAXIMUM_RESPONSE_BYTES = 67_108_864
}
