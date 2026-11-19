// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import android.content.Context

internal enum class TimestampAuthorityStoreFailure {
    MALFORMED,
    UNAVAILABLE,
}

internal class TimestampAuthorityStoreException(
    val kind: TimestampAuthorityStoreFailure,
) : Exception(kind.name)

/**
 * Blocking timestamp-authority persistence.
 *
 * [load] transfers owned configurations to the caller. [save] borrows its configurations only for
 * the duration of the call.
 */
internal interface TimestampAuthorityRepository {
    fun load(): List<TimestampAuthorityConfiguration>

    fun save(authorities: List<TimestampAuthorityConfiguration>)

    fun restoreDefaults()
}

/**
 * Ordered public configuration plus Keystore-protected per-authority passwords.
 *
 * Every call performs blocking persistence or Keystore work and must run away from the main thread.
 */
internal class TimestampAuthorityStore(
    context: Context,
    private val passwordVault: TimestampAuthorityPasswordVault =
        AndroidKeystoreTimestampAuthorityPasswordVault(context),
    preferenceName: String = DEFAULT_PUBLIC_PREFERENCE_NAME,
) : TimestampAuthorityRepository {
    private val preferences =
        context.applicationContext.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)

    @Synchronized
    override fun load(): List<TimestampAuthorityConfiguration> {
        if (!preferences.contains(AUTHORITY_COUNT_KEY)) {
            return listOf(TimestampAuthorityConfiguration.shipped())
        }
        val loaded = mutableListOf<TimestampAuthorityConfiguration>()
        try {
            val count = preferences.getInt(AUTHORITY_COUNT_KEY, MISSING_AUTHORITY_COUNT)
            if (
                count !in
                MINIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT..MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT
            ) {
                throw malformed()
            }
            repeat(count) { index ->
                val address = preferences.getString(addressKey(index), null) ?: throw malformed()
                val username = preferences.getString(usernameKey(index), null)
                val password = if (username == null) null else passwordVault.read(address) ?: throw malformed()
                try {
                    loaded +=
                        TimestampAuthorityConfiguration.copyOf(
                            address = address,
                            username = username,
                            password = password,
                        )
                } finally {
                    password?.fill(CLEARED_CHARACTER)
                }
            }
            requireDistinctAddresses(loaded)
            return loaded
        } catch (failure: TimestampAuthorityStoreException) {
            loaded.closeAll()
            throw failure
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            loaded.closeAll()
            throw vaultFailure(failure)
        } catch (_: IllegalArgumentException) {
            loaded.closeAll()
            throw malformed()
        } catch (_: ClassCastException) {
            loaded.closeAll()
            throw malformed()
        } catch (_: RuntimeException) {
            loaded.closeAll()
            throw unavailable()
        }
    }

    @Synchronized
    override fun save(authorities: List<TimestampAuthorityConfiguration>) {
        if (authorities.isEmpty()) {
            restoreDefaults()
            return
        }
        val owned = mutableListOf<TimestampAuthorityConfiguration>()
        try {
            if (authorities.size > MAXIMUM_SIGNING_TIMESTAMP_AUTHORITY_COUNT) {
                throw malformed()
            }
            authorities.mapTo(owned, TimestampAuthorityConfiguration::copyOwned)
            requireDistinctAddresses(owned)
            val credentialedAddresses = mutableSetOf<String>()
            for (authority in owned) {
                val password = authority.copyPassword()
                if (password != null) {
                    try {
                        passwordVault.write(authority.address, password)
                        credentialedAddresses += authority.address
                    } finally {
                        password.fill(CLEARED_CHARACTER)
                    }
                }
            }
            val editor = preferences.edit().clear()
            if (!owned.isShippedSet()) {
                editor.putInt(AUTHORITY_COUNT_KEY, owned.size)
                owned.forEachIndexed { index, authority ->
                    editor.putString(addressKey(index), authority.address)
                    authority.username?.let { username ->
                        editor.putString(usernameKey(index), username)
                    }
                }
            }
            if (!editor.commit()) {
                throw unavailable()
            }
            passwordVault.retain(credentialedAddresses)
        } catch (failure: TimestampAuthorityStoreException) {
            throw failure
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw vaultFailure(failure)
        } catch (_: IllegalArgumentException) {
            throw malformed()
        } catch (_: RuntimeException) {
            throw unavailable()
        } finally {
            owned.closeAll()
        }
    }

    @Synchronized
    override fun restoreDefaults() {
        try {
            val editor = preferences.edit()
            editor.clear()
            if (!editor.commit()) {
                throw unavailable()
            }
            passwordVault.clear()
        } catch (failure: TimestampAuthorityStoreException) {
            throw failure
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw vaultFailure(failure)
        } catch (_: RuntimeException) {
            throw unavailable()
        }
    }

    private fun requireDistinctAddresses(authorities: List<TimestampAuthorityConfiguration>) {
        if (authorities.map(TimestampAuthorityConfiguration::address).distinct().size != authorities.size) {
            throw malformed()
        }
    }

    private fun List<TimestampAuthorityConfiguration>.isShippedSet(): Boolean =
        size == SHIPPED_AUTHORITY_COUNT &&
            single().address == TimestampAuthorityConfiguration.SHIPPED_AUTHORITY_ADDRESS &&
            !single().hasCredentials

    private fun MutableList<TimestampAuthorityConfiguration>.closeAll() {
        forEach(TimestampAuthorityConfiguration::close)
        clear()
    }

    private fun addressKey(index: Int): String = AUTHORITY_KEY_PREFIX + index + ADDRESS_KEY_SUFFIX

    private fun usernameKey(index: Int): String = AUTHORITY_KEY_PREFIX + index + USERNAME_KEY_SUFFIX

    private fun vaultFailure(failure: TimestampAuthorityPasswordVaultException): TimestampAuthorityStoreException =
        when (failure.kind) {
            TimestampAuthorityPasswordVaultFailure.MALFORMED -> malformed()
            TimestampAuthorityPasswordVaultFailure.UNAVAILABLE -> unavailable()
        }

    private fun malformed(): TimestampAuthorityStoreException =
        TimestampAuthorityStoreException(TimestampAuthorityStoreFailure.MALFORMED)

    private fun unavailable(): TimestampAuthorityStoreException =
        TimestampAuthorityStoreException(TimestampAuthorityStoreFailure.UNAVAILABLE)

    private companion object {
        const val DEFAULT_PUBLIC_PREFERENCE_NAME = "timestamp-authorities"
        const val AUTHORITY_COUNT_KEY = "authority.count"
        const val AUTHORITY_KEY_PREFIX = "authority."
        const val ADDRESS_KEY_SUFFIX = ".address"
        const val USERNAME_KEY_SUFFIX = ".username"
        const val MISSING_AUTHORITY_COUNT = -1
        const val SHIPPED_AUTHORITY_COUNT = 1
        const val CLEARED_CHARACTER = '\u0000'
    }
}
