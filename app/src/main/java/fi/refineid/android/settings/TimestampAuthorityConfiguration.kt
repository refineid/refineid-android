// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import uniffi.refineid_doc_sign_android.TimestampAuthority
import uniffi.refineid_doc_sign_android.TimestampLogin
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets

/** One holder-configured authority with an owned, clearable Basic-auth password. */
internal class TimestampAuthorityConfiguration private constructor(
    val address: String,
    val username: String?,
    private val ownedPassword: CharArray?,
) : AutoCloseable {
    private var isClosed = false

    val hasCredentials: Boolean
        get() = username != null

    fun copyPassword(): CharArray? {
        requireOpen()
        return ownedPassword?.copyOf()
    }

    fun copyOwned(): TimestampAuthorityConfiguration {
        requireOpen()
        return copyOf(address = address, username = username, password = ownedPassword)
    }

    /**
     * This authority as the core takes it. The login's password is a fresh
     * UTF-8 copy the caller clears once the core has it.
     */
    fun coreAuthority(): TimestampAuthority {
        requireOpen()
        val login =
            username?.let { name ->
                TimestampLogin(username = name, password = utf8(checkNotNull(ownedPassword)))
            }
        return TimestampAuthority(url = address, login = login)
    }

    override fun close() {
        if (!isClosed) {
            ownedPassword?.fill(CLEARED_CHARACTER)
            isClosed = true
        }
    }

    override fun toString(): String = "TimestampAuthorityConfiguration(credentials=$hasCredentials, closed=$isClosed)"

    private fun requireOpen() {
        check(!isClosed) {
            "timestamp-authority configuration is closed"
        }
    }

    companion object {
        const val SHIPPED_AUTHORITY_ADDRESS = "https://timestamp.sectigo.com/qualified"

        fun shipped(): TimestampAuthorityConfiguration =
            copyOf(
                address = SHIPPED_AUTHORITY_ADDRESS,
                username = null,
                password = null,
            )

        fun copyOf(
            address: String,
            username: String?,
            password: CharArray?,
        ): TimestampAuthorityConfiguration {
            require(TimestampAuthorityRules.accepts(address, username, password)) {
                "invalid timestamp-authority configuration"
            }
            return TimestampAuthorityConfiguration(
                address = address,
                username = username,
                ownedPassword = password?.copyOf(),
            )
        }

        private fun utf8(password: CharArray): ByteArray {
            val encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password))
            val bytes = ByteArray(encoded.remaining())
            encoded.get(bytes)
            if (encoded.hasArray()) {
                encoded.array().fill(CLEARED_BYTE)
            }
            return bytes
        }

        private const val CLEARED_CHARACTER = '\u0000'
        private const val CLEARED_BYTE: Byte = 0
    }
}
