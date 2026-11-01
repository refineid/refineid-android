// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import java.net.URI
import java.net.URISyntaxException

/** The fewest timestamp authorities a configuration holds. */
internal const val MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT = 1

/** The most timestamp authorities a configuration holds. */
internal const val MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT = 8

/** Bounds of one configured timestamp authority's fields. */
internal object TimestampAuthorityLimits {
    const val MAXIMUM_ADDRESS_CHARACTERS = 8_192
    const val MAXIMUM_USERNAME_CHARACTERS = 256
    const val MAXIMUM_PASSWORD_CHARACTERS = 1_024
}

/**
 * What a configured timestamp authority must be: an absolute `http` or
 * `https` URL with a host, no user information and a valid port; a
 * login, when given, complete, sent over HTTPS only, with a user name
 * that can stand in an HTTP Basic credential.
 */
internal object TimestampAuthorityRules {
    fun accepts(
        address: String,
        username: String?,
        password: CharArray?,
    ): Boolean {
        val uri = authorityUri(address) ?: return false
        if ((username == null) != (password == null)) {
            return false
        }
        if (username == null || password == null) {
            return true
        }
        return uri.scheme.lowercase() == HTTPS_SCHEME && usernameIsUsable(username) && passwordIsUsable(password)
    }

    private fun authorityUri(address: String): URI? {
        if (address.isEmpty() || address.length > TimestampAuthorityLimits.MAXIMUM_ADDRESS_CHARACTERS) {
            return null
        }
        val uri =
            try {
                URI(address)
            } catch (_: URISyntaxException) {
                return null
            }
        val scheme = uri.scheme?.lowercase() ?: return null
        val host = uri.host ?: return null
        val portIsValid = uri.port == PORT_UNSPECIFIED || uri.port in MINIMUM_PORT..MAXIMUM_PORT
        return uri.takeIf {
            scheme in HTTP_SCHEMES && host.isNotEmpty() && uri.rawUserInfo == null && portIsValid && !uri.isOpaque
        }
    }

    private fun usernameIsUsable(username: String): Boolean =
        username.isNotEmpty() &&
            username.length <= TimestampAuthorityLimits.MAXIMUM_USERNAME_CHARACTERS &&
            !username.contains(BASIC_CREDENTIAL_SEPARATOR) &&
            username.none(::isForbiddenHeaderCharacter)

    private fun passwordIsUsable(password: CharArray): Boolean =
        password.size <= TimestampAuthorityLimits.MAXIMUM_PASSWORD_CHARACTERS &&
            password.none(::isForbiddenHeaderCharacter)

    private fun isForbiddenHeaderCharacter(character: Char): Boolean =
        character == CARRIAGE_RETURN || character == LINE_FEED || character == NULL_CHARACTER

    private const val HTTP_SCHEME = "http"
    private const val HTTPS_SCHEME = "https"
    private val HTTP_SCHEMES = setOf(HTTP_SCHEME, HTTPS_SCHEME)
    private const val PORT_UNSPECIFIED = -1
    private const val MINIMUM_PORT = 1
    private const val MAXIMUM_PORT = 65_535
    private const val BASIC_CREDENTIAL_SEPARATOR = ':'
    private const val CARRIAGE_RETURN = '\r'
    private const val LINE_FEED = '\n'
    private const val NULL_CHARACTER = '\u0000'
}
