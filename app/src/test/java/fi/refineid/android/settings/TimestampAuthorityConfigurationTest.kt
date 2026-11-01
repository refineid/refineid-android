// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TimestampAuthorityConfigurationTest {
    @Test
    fun shippedConfigurationUsesHttpsWithoutCredentials() {
        val configuration = TimestampAuthorityConfiguration.shipped()
        try {
            assertEquals(SHIPPED_AUTHORITY_ADDRESS, configuration.address)
            assertNull(configuration.username)
            assertFalse(configuration.hasCredentials)
            assertNull(configuration.copyPassword())
        } finally {
            configuration.close()
        }
    }

    @Test
    fun configurationOwnsPasswordAndHandsTheCoreItsLogin() {
        val inputPassword = SYNTHETIC_PASSWORD.copyOf()
        val configuration =
            TimestampAuthorityConfiguration.copyOf(
                address = PROTECTED_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = inputPassword,
            )
        inputPassword[FIRST_CHARACTER_INDEX] = CHANGED_CHARACTER

        val copiedPassword = checkNotNull(configuration.copyPassword())
        val authority = configuration.coreAuthority()
        val login = checkNotNull(authority.login)
        try {
            assertTrue(copiedPassword.contentEquals(SYNTHETIC_PASSWORD))
            assertEquals(PROTECTED_AUTHORITY_ADDRESS, authority.url)
            assertEquals(SYNTHETIC_USERNAME, login.username)
            assertArrayEquals(SYNTHETIC_PASSWORD.concatToString().encodeToByteArray(), login.password)
            assertFalse(configuration.toString().contains(PROTECTED_AUTHORITY_ADDRESS))
            assertFalse(configuration.toString().contains(SYNTHETIC_USERNAME))
            assertFalse(configuration.toString().contains(SYNTHETIC_PASSWORD.concatToString()))
        } finally {
            copiedPassword.fill(CLEARED_CHARACTER)
            login.password.fill(CLEARED_BYTE)
            configuration.close()
        }

        assertThrows(IllegalStateException::class.java, configuration::copyPassword)
    }

    @Test
    fun emptyPasswordIsACompleteCredentialAndPlaintextCredentialsAreRefused() {
        val configuration =
            TimestampAuthorityConfiguration.copyOf(
                address = PROTECTED_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = EMPTY_PASSWORD,
            )
        try {
            assertTrue(configuration.hasCredentials)
            assertEquals(0, checkNotNull(configuration.coreAuthority().login).password.size)
        } finally {
            configuration.close()
        }

        assertThrows(IllegalArgumentException::class.java) {
            TimestampAuthorityConfiguration.copyOf(
                address = PLAIN_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = SYNTHETIC_PASSWORD,
            )
        }
    }

    @Test
    fun anAuthorityWithoutALoginHandsTheCoreNone() {
        val configuration = TimestampAuthorityConfiguration.shipped()
        try {
            val authority = configuration.coreAuthority()
            assertEquals(SHIPPED_AUTHORITY_ADDRESS, authority.url)
            assertNull(authority.login)
        } finally {
            configuration.close()
        }
    }

    @Test
    fun malformedAuthoritiesAndHalfLoginsAreRefused() {
        listOf(NOT_A_URL, USER_INFO_ADDRESS, OTHER_SCHEME_ADDRESS).forEach { address ->
            assertThrows(IllegalArgumentException::class.java) {
                TimestampAuthorityConfiguration.copyOf(address = address, username = null, password = null)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            TimestampAuthorityConfiguration.copyOf(
                address = PROTECTED_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = null,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            TimestampAuthorityConfiguration.copyOf(
                address = PROTECTED_AUTHORITY_ADDRESS,
                username = SEPARATOR_USERNAME,
                password = SYNTHETIC_PASSWORD,
            )
        }
    }

    private companion object {
        const val NOT_A_URL = "not a url"
        const val USER_INFO_ADDRESS = "https://someone@timestamp.example/request"
        const val OTHER_SCHEME_ADDRESS = "ftp://timestamp.example/request"
        const val SEPARATOR_USERNAME = "synthetic:account"
        const val SHIPPED_AUTHORITY_ADDRESS = "https://timestamp.sectigo.com/qualified"
        const val PROTECTED_AUTHORITY_ADDRESS = "https://timestamp.example/request"
        const val PLAIN_AUTHORITY_ADDRESS = "http://timestamp.example/request"
        const val SYNTHETIC_USERNAME = "synthetic-account"
        const val FIRST_CHARACTER_INDEX = 0
        const val CHANGED_CHARACTER = 'X'
        const val CLEARED_CHARACTER = '\u0000'
        const val CLEARED_BYTE: Byte = 0
        val SYNTHETIC_PASSWORD = "synthetic-password".toCharArray()
        val EMPTY_PASSWORD = CharArray(0)
    }
}
