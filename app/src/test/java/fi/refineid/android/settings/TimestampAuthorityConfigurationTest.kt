// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import fi.refineid.android.network.SigningTimestampTrust
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

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
    fun configurationOwnsPasswordAndCreatesConfiguredTrust() {
        val inputPassword = SYNTHETIC_PASSWORD.copyOf()
        val configuration =
            TimestampAuthorityConfiguration.copyOf(
                address = PROTECTED_AUTHORITY_ADDRESS,
                username = SYNTHETIC_USERNAME,
                password = inputPassword,
            )
        inputPassword[FIRST_CHARACTER_INDEX] = CHANGED_CHARACTER

        val copiedPassword = checkNotNull(configuration.copyPassword())
        val authority = configuration.copySigningAuthority()
        try {
            assertTrue(copiedPassword.contentEquals(SYNTHETIC_PASSWORD))
            assertEquals(SigningTimestampTrust.TRUSTED_LISTS, authority.trust)
            assertEquals(SYNTHETIC_AUTHORIZATION_HEADER, authority.credentials()?.authorizationHeader())
            assertFalse(configuration.toString().contains(PROTECTED_AUTHORITY_ADDRESS))
            assertFalse(configuration.toString().contains(SYNTHETIC_USERNAME))
            assertFalse(configuration.toString().contains(SYNTHETIC_PASSWORD.concatToString()))
        } finally {
            copiedPassword.fill(CLEARED_CHARACTER)
            authority.close()
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
        val authority = configuration.copySigningAuthority()
        try {
            assertTrue(configuration.hasCredentials)
            assertEquals(EMPTY_PASSWORD_AUTHORIZATION_HEADER, authority.credentials()?.authorizationHeader())
        } finally {
            authority.close()
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

    private companion object {
        const val SHIPPED_AUTHORITY_ADDRESS = "https://timestamp.sectigo.com/qualified"
        const val PROTECTED_AUTHORITY_ADDRESS = "https://timestamp.example/request"
        const val PLAIN_AUTHORITY_ADDRESS = "http://timestamp.example/request"
        const val SYNTHETIC_USERNAME = "synthetic-account"
        val SYNTHETIC_AUTHORIZATION_HEADER =
            "Basic " + Base64.getEncoder().encodeToString("$SYNTHETIC_USERNAME:synthetic-password".toByteArray())
        val EMPTY_PASSWORD_AUTHORIZATION_HEADER =
            "Basic " + Base64.getEncoder().encodeToString("$SYNTHETIC_USERNAME:".toByteArray())
        const val FIRST_CHARACTER_INDEX = 0
        const val CHANGED_CHARACTER = 'X'
        const val CLEARED_CHARACTER = '\u0000'
        val SYNTHETIC_PASSWORD = "synthetic-password".toCharArray()
        val EMPTY_PASSWORD = CharArray(0)
    }
}
