// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** AES-GCM sealing as `[IV][ciphertext and tag]`, under the key [key] supplies. */
internal class AesGcmJournalSealer(
    private val key: () -> SecretKey,
) : RappJournalSealer {
    override fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val iv = cipher.iv
        if (iv.size != IV_BYTES) throw GeneralSecurityException("unexpected IV length")
        return iv + cipher.doFinal(plaintext)
    }

    override fun open(sealed: ByteArray): ByteArray {
        if (sealed.size < IV_BYTES + TAG_BYTES) throw GeneralSecurityException("truncated entry")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(),
            GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES),
        )
        return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
    }

    companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
        const val TAG_BYTES = TAG_BITS / Byte.SIZE_BITS
        const val KEY_BITS = 256
    }
}

/** The device-bound journal key, created in the Android Keystore on first use. */
internal object RappJournalKeystoreKey {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "fi.refineid.rapp.journal.v1"

    @Synchronized
    fun get(): SecretKey {
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(
            KeyGenParameterSpec
                .Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AesGcmJournalSealer.KEY_BITS)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }
}
