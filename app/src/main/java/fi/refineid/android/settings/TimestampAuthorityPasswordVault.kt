// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.settings

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import fi.refineid.android.network.SigningNetworkLimits
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class TimestampAuthorityPasswordVaultFailure {
    MALFORMED,
    UNAVAILABLE,
}

internal class TimestampAuthorityPasswordVaultException(
    val kind: TimestampAuthorityPasswordVaultFailure,
) : Exception(kind.name)

/** Blocking password custody; every call must run away from the main thread. */
internal interface TimestampAuthorityPasswordVault {
    fun read(address: String): CharArray?

    fun write(
        address: String,
        password: CharArray,
    )

    fun retain(addresses: Set<String>)

    fun clear()
}

/** App-private ciphertext protected by one non-exportable Android Keystore key. */
internal class AndroidKeystoreTimestampAuthorityPasswordVault(
    context: Context,
    private val preferenceName: String = DEFAULT_PASSWORD_PREFERENCE_NAME,
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) : TimestampAuthorityPasswordVault {
    private val preferences =
        context.applicationContext.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)

    @Synchronized
    override fun read(address: String): CharArray? {
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        var plaintext: ByteArray? = null
        var addressBytes: ByteArray? = null
        try {
            val entry = entryName(address)
            val encodedIv = preferences.getString(entry + IV_SUFFIX, null)
            val encodedCiphertext = preferences.getString(entry + CIPHERTEXT_SUFFIX, null)
            if (encodedIv == null && encodedCiphertext == null) {
                return null
            }
            if (encodedIv == null || encodedCiphertext == null) {
                throw malformed()
            }
            iv = decodeBase64(encodedIv)
            ciphertext = decodeBase64(encodedCiphertext)
            requireEncryptedShape(iv, ciphertext)
            addressBytes = address.encodeToByteArray()
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                decryptionKey(),
                // nosemgrep: kotlin.lang.security.gcm-detection.gcm-detection
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv),
            )
            cipher.updateAAD(addressBytes)
            plaintext = cipher.doFinal(ciphertext)
            return decodePassword(plaintext)
        } catch (_: AEADBadTagException) {
            throw malformed()
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw failure
        } catch (_: IllegalArgumentException) {
            throw malformed()
        } catch (_: ClassCastException) {
            throw malformed()
        } catch (_: GeneralSecurityException) {
            throw unavailable()
        } catch (_: IOException) {
            throw unavailable()
        } catch (_: RuntimeException) {
            throw unavailable()
        } finally {
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
            plaintext?.fill(CLEARED_BYTE)
            addressBytes?.fill(CLEARED_BYTE)
        }
    }

    @Synchronized
    override fun write(
        address: String,
        password: CharArray,
    ) {
        val plaintext = encodePassword(password)
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        var addressBytes: ByteArray? = null
        try {
            addressBytes = address.encodeToByteArray()
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
            cipher.updateAAD(addressBytes)
            ciphertext = cipher.doFinal(plaintext)
            iv = cipher.iv
            requireEncryptedShape(iv, ciphertext)
            val entry = entryName(address)
            val committed =
                preferences
                    .edit()
                    .putString(entry + IV_SUFFIX, Base64.getEncoder().encodeToString(iv))
                    .putString(
                        entry + CIPHERTEXT_SUFFIX,
                        Base64.getEncoder().encodeToString(ciphertext),
                    ).commit()
            if (!committed) {
                throw unavailable()
            }
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw failure
        } catch (_: IllegalArgumentException) {
            throw malformed()
        } catch (_: GeneralSecurityException) {
            throw unavailable()
        } catch (_: IOException) {
            throw unavailable()
        } catch (_: RuntimeException) {
            throw unavailable()
        } finally {
            plaintext.fill(CLEARED_BYTE)
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
            addressBytes?.fill(CLEARED_BYTE)
        }
    }

    @Synchronized
    override fun retain(addresses: Set<String>) {
        try {
            val retained =
                addresses.flatMapTo(mutableSetOf()) { address ->
                    val entry = entryName(address)
                    listOf(entry + IV_SUFFIX, entry + CIPHERTEXT_SUFFIX)
                }
            val editor = preferences.edit()
            var changed = false
            for (stored in preferences.all.keys) {
                if (stored !in retained) {
                    editor.remove(stored)
                    changed = true
                }
            }
            if (changed && !editor.commit()) {
                throw unavailable()
            }
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw failure
        } catch (_: GeneralSecurityException) {
            throw unavailable()
        } catch (_: RuntimeException) {
            throw unavailable()
        }
    }

    @Synchronized
    override fun clear() {
        try {
            val editor = preferences.edit()
            editor.clear()
            if (!editor.commit()) {
                throw unavailable()
            }
        } catch (failure: TimestampAuthorityPasswordVaultException) {
            throw failure
        } catch (_: RuntimeException) {
            throw unavailable()
        }
    }

    private fun encryptionKey(): SecretKey =
        synchronized(KEYSTORE_LOCK) {
            existingKey() ?: generateKey()
        }

    private fun decryptionKey(): SecretKey =
        synchronized(KEYSTORE_LOCK) {
            existingKey() ?: throw unavailable()
        }

    private fun existingKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)
        val key = keyStore.getKey(keyAlias, null) ?: return null
        return key as? SecretKey ?: throw unavailable()
    }

    private fun generateKey(): SecretKey {
        val generator =
            KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE_PROVIDER,
            )
        generator.init(
            KeyGenParameterSpec
                .Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AES_KEY_SIZE_BITS)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun entryName(address: String): String {
        val addressBytes = address.encodeToByteArray()
        var digest: ByteArray? = null
        return try {
            digest = MessageDigest.getInstance(SHA256_DIGEST_NAME).digest(addressBytes)
            Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        } finally {
            addressBytes.fill(CLEARED_BYTE)
            digest?.fill(CLEARED_BYTE)
        }
    }

    private fun encodePassword(password: CharArray): ByteArray {
        if (password.size > SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS) {
            throw malformed()
        }
        val encoded = ByteArray(password.size * UTF16_CODE_UNIT_BYTES)
        for (index in password.indices) {
            val value = password[index].code
            val offset = index * UTF16_CODE_UNIT_BYTES
            encoded[offset] = (value ushr HIGH_BYTE_SHIFT).toByte()
            encoded[offset + LOW_BYTE_OFFSET] = (value and UNSIGNED_BYTE_MASK).toByte()
        }
        return encoded
    }

    private fun decodePassword(encoded: ByteArray): CharArray {
        if (
            encoded.size % UTF16_CODE_UNIT_BYTES != NO_REMAINDER ||
            encoded.size / UTF16_CODE_UNIT_BYTES > SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS
        ) {
            throw malformed()
        }
        return CharArray(encoded.size / UTF16_CODE_UNIT_BYTES) { index ->
            val offset = index * UTF16_CODE_UNIT_BYTES
            val high = encoded[offset].toUByte().toInt() shl HIGH_BYTE_SHIFT
            val low = encoded[offset + LOW_BYTE_OFFSET].toUByte().toInt()
            (high or low).toChar()
        }
    }

    private fun requireEncryptedShape(
        iv: ByteArray,
        ciphertext: ByteArray,
    ) {
        if (
            iv.size != GCM_IV_LENGTH_BYTES ||
            ciphertext.size !in GCM_TAG_LENGTH_BYTES..MAXIMUM_CIPHERTEXT_BYTES
        ) {
            throw malformed()
        }
    }

    private fun decodeBase64(encoded: String): ByteArray =
        try {
            Base64.getDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw malformed()
        }

    private fun malformed(): TimestampAuthorityPasswordVaultException =
        TimestampAuthorityPasswordVaultException(TimestampAuthorityPasswordVaultFailure.MALFORMED)

    private fun unavailable(): TimestampAuthorityPasswordVaultException =
        TimestampAuthorityPasswordVaultException(TimestampAuthorityPasswordVaultFailure.UNAVAILABLE)

    private companion object {
        const val DEFAULT_PASSWORD_PREFERENCE_NAME = "timestamp-authority-passwords"
        const val DEFAULT_KEY_ALIAS = "fi.refineid.timestamp-authority-passwords.v1"
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val SHA256_DIGEST_NAME = "SHA-256"
        const val IV_SUFFIX = ".iv"
        const val CIPHERTEXT_SUFFIX = ".ciphertext"
        const val AES_KEY_SIZE_BITS = 256
        const val GCM_TAG_LENGTH_BITS = 128
        const val BITS_PER_BYTE = 8
        const val GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / BITS_PER_BYTE
        const val GCM_IV_LENGTH_BYTES = 12
        const val UTF16_CODE_UNIT_BYTES = 2
        const val HIGH_BYTE_SHIFT = 8
        const val LOW_BYTE_OFFSET = 1
        const val UNSIGNED_BYTE_MASK = 0xFF
        const val NO_REMAINDER = 0
        const val MAXIMUM_PASSWORD_BYTES =
            SigningNetworkLimits.MAXIMUM_PASSWORD_CHARACTERS * UTF16_CODE_UNIT_BYTES
        const val MAXIMUM_CIPHERTEXT_BYTES = MAXIMUM_PASSWORD_BYTES + GCM_TAG_LENGTH_BYTES
        const val CLEARED_BYTE: Byte = 0
        val KEYSTORE_LOCK = Any()
    }
}
