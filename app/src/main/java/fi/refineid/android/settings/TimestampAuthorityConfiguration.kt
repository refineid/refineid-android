// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import fi.refineid.android.network.SigningTimestampAuthority

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

    fun copySigningAuthority(): SigningTimestampAuthority {
        requireOpen()
        val password = ownedPassword?.copyOf()
        return try {
            SigningTimestampAuthority.configured(
                address = address,
                username = username,
                password = password,
            )
        } finally {
            password?.fill(CLEARED_CHARACTER)
        }
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
            val checked =
                SigningTimestampAuthority.configured(
                    address = address,
                    username = username,
                    password = password,
                )
            checked.close()
            return TimestampAuthorityConfiguration(
                address = address,
                username = username,
                ownedPassword = password?.copyOf(),
            )
        }

        private const val CLEARED_CHARACTER = '\u0000'
    }
}
