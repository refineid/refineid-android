package fi.refineid.android.prime

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.DIGIT_NINE_BYTE
import fi.refineid.android.core.DIGIT_ZERO_BYTE
import fi.refineid.android.core.PIN1_MAXIMUM_LENGTH
import fi.refineid.android.core.PIN1_MINIMUM_LENGTH
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Blocking custody of the primed card's access number and verified PIN1,
 * mirroring the Apple reference: priming once lets every later tap reopen
 * the card without re-entry, and allows unattended browser authentication
 * via remote RAPP. Digits rest only as app-private ciphertext under one
 * non-exportable Android Keystore key, and a read that fails to decrypt
 * clears the prime instead of surfacing broken state. Every call must run
 * away from the main thread.
 */
internal class PrimedCanStore(
    context: Context,
    private val preferenceName: String = DEFAULT_PREFERENCE_NAME,
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
) {
    private val preferences =
        context.applicationContext.getSharedPreferences(preferenceName, Context.MODE_PRIVATE)

    /** Whether digits are stored, without decrypting them. */
    @Synchronized
    fun isPrimed(): Boolean =
        preferences.contains(ENTRY_NAME + IV_SUFFIX) &&
            preferences.contains(ENTRY_NAME + CIPHERTEXT_SUFFIX)

    /** Decrypted CAN digits owned by the caller, or null when unprimed. */
    @Synchronized
    fun read(): ByteArray? {
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            val encodedIv = preferences.getString(ENTRY_NAME + IV_SUFFIX, null)
            val encodedCiphertext = preferences.getString(ENTRY_NAME + CIPHERTEXT_SUFFIX, null)
            if (encodedIv == null || encodedCiphertext == null) {
                return null
            }
            iv = decodeBase64(encodedIv)
            ciphertext = decodeBase64(encodedCiphertext)
            if (
                iv == null ||
                ciphertext == null ||
                iv.size != GCM_IV_LENGTH_BYTES ||
                ciphertext.size != PRIMED_CIPHERTEXT_BYTES
            ) {
                clear()
                return null
            }
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                existingKey() ?: run {
                    clear()
                    return null
                },
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv),
            )
            cipher.updateAAD(ENTRY_NAME.encodeToByteArray())
            val plaintext = cipher.doFinal(ciphertext)
            if (plaintext.size != CanSubmission.CAN_DIGITS) {
                plaintext.fill(CLEARED_BYTE)
                clear()
                return null
            }
            return plaintext
        } catch (_: GeneralSecurityException) {
            clear()
            return null
        } catch (_: IOException) {
            return null
        } catch (_: RuntimeException) {
            return null
        } finally {
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
        }
    }

    /** Encrypt and persist the digits, taking ownership of the input. */
    @Synchronized
    fun write(can: ByteArray) {
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            if (can.size != CanSubmission.CAN_DIGITS) {
                return
            }
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, existingKey() ?: generateKey())
            cipher.updateAAD(ENTRY_NAME.encodeToByteArray())
            ciphertext = cipher.doFinal(can)
            iv = cipher.iv
            val committed =
                preferences
                    .edit()
                    .putString(ENTRY_NAME + IV_SUFFIX, Base64.getEncoder().encodeToString(iv))
                    .putString(
                        ENTRY_NAME + CIPHERTEXT_SUFFIX,
                        Base64.getEncoder().encodeToString(ciphertext),
                    ).commit()
            if (!committed) {
                // An unprimed store is the safe failure mode.
            }
        } catch (_: GeneralSecurityException) {
            // An unprimed store is the safe failure mode.
        } catch (_: IOException) {
            // An unprimed store is the safe failure mode.
        } catch (_: RuntimeException) {
            // An unprimed store is the safe failure mode.
        } finally {
            can.fill(CLEARED_BYTE)
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
        }
    }

    @Synchronized
    fun readHolderName(): String? = preferences.getString(ENTRY_HOLDER_NAME, null)

    @Synchronized
    fun writeHolderName(name: String?) {
        preferences.edit {
            if (name != null) {
                putString(ENTRY_HOLDER_NAME, name)
            } else {
                remove(ENTRY_HOLDER_NAME)
            }
        }
    }

    @Synchronized
    fun readAuthCertificateDer(): ByteArray? {
        val b64 = preferences.getString(ENTRY_AUTH_CERT, null) ?: return null
        return decodeBase64(b64)
    }

    @Synchronized
    fun writeAuthCertificateDer(der: ByteArray?) {
        preferences.edit {
            if (der != null) {
                putString(ENTRY_AUTH_CERT, Base64.getEncoder().encodeToString(der))
            } else {
                remove(ENTRY_AUTH_CERT)
            }
        }
    }

    /** Whether PIN 1 digits are stored, without decrypting them. */
    @Synchronized
    fun hasPin1(): Boolean =
        preferences.contains(ENTRY_PIN1 + IV_SUFFIX) &&
            preferences.contains(ENTRY_PIN1 + CIPHERTEXT_SUFFIX)

    /** Decrypted PIN 1 digits owned by the caller, or null when absent/corrupt. */
    @Synchronized
    fun readPin1(): ByteArray? {
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            val encodedIv = preferences.getString(ENTRY_PIN1 + IV_SUFFIX, null)
            val encodedCiphertext = preferences.getString(ENTRY_PIN1 + CIPHERTEXT_SUFFIX, null)
            if (encodedIv == null || encodedCiphertext == null) {
                return null
            }
            iv = decodeBase64(encodedIv)
            ciphertext = decodeBase64(encodedCiphertext)
            if (iv == null || ciphertext == null) {
                forgetPin1()
                return null
            }
            if (
                iv.size != GCM_IV_LENGTH_BYTES ||
                ciphertext.size !in PIN1_MIN_CIPHERTEXT_BYTES..PIN1_MAX_CIPHERTEXT_BYTES
            ) {
                forgetPin1()
                return null
            }
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                existingKey() ?: run {
                    forgetPin1()
                    return null
                },
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv),
            )
            cipher.updateAAD(ENTRY_PIN1.encodeToByteArray())
            val plaintext = cipher.doFinal(ciphertext)
            if (
                plaintext.size !in PIN1_MINIMUM_LENGTH..PIN1_MAXIMUM_LENGTH ||
                plaintext.any { it !in DIGIT_ZERO_BYTE..DIGIT_NINE_BYTE }
            ) {
                plaintext.fill(CLEARED_BYTE)
                forgetPin1()
                return null
            }
            return plaintext
        } catch (_: GeneralSecurityException) {
            forgetPin1()
            return null
        } catch (_: IOException) {
            return null
        } catch (_: RuntimeException) {
            return null
        } finally {
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
        }
    }

    /** Encrypt and persist PIN 1 digits, taking ownership of the input. */
    @Synchronized
    fun writePin1(pin1: ByteArray) {
        var iv: ByteArray? = null
        var ciphertext: ByteArray? = null
        try {
            if (
                pin1.size !in PIN1_MINIMUM_LENGTH..PIN1_MAXIMUM_LENGTH ||
                pin1.any { it !in DIGIT_ZERO_BYTE..DIGIT_NINE_BYTE }
            ) {
                return
            }
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, existingKey() ?: generateKey())
            cipher.updateAAD(ENTRY_PIN1.encodeToByteArray())
            ciphertext = cipher.doFinal(pin1)
            iv = cipher.iv
            val committed =
                preferences
                    .edit()
                    .putString(ENTRY_PIN1 + IV_SUFFIX, Base64.getEncoder().encodeToString(iv))
                    .putString(
                        ENTRY_PIN1 + CIPHERTEXT_SUFFIX,
                        Base64.getEncoder().encodeToString(ciphertext),
                    ).commit()
            if (!committed) {
                // An unstored PIN is the safe failure mode.
            }
        } catch (_: GeneralSecurityException) {
            // An unstored PIN is the safe failure mode.
        } catch (_: IOException) {
            // An unstored PIN is the safe failure mode.
        } catch (_: RuntimeException) {
            // An unstored PIN is the safe failure mode.
        } finally {
            pin1.fill(CLEARED_BYTE)
            iv?.fill(CLEARED_BYTE)
            ciphertext?.fill(CLEARED_BYTE)
        }
    }

    /** Remove stored PIN 1 ciphertext without clearing CAN. */
    @Synchronized
    fun forgetPin1() {
        preferences.edit {
            remove(ENTRY_PIN1 + IV_SUFFIX)
            remove(ENTRY_PIN1 + CIPHERTEXT_SUFFIX)
        }
    }

    @Synchronized
    fun clear() {
        val cleared = preferences.edit().clear().commit()
        if (!cleared) {
            // Stale ciphertext without a matching key self-heals on read.
        }
    }

    private fun existingKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)
        return keyStore.getKey(keyAlias, null) as? SecretKey
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

    private fun decodeBase64(encoded: String): ByteArray? =
        try {
            Base64.getDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            null
        }

    private companion object {
        const val DEFAULT_PREFERENCE_NAME = "primed-card"
        const val DEFAULT_KEY_ALIAS = "fi.refineid.primed-card.v1"
        const val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val ENTRY_NAME = "can"
        const val ENTRY_PIN1 = "pin1"
        const val ENTRY_HOLDER_NAME = "holder_name"
        const val ENTRY_AUTH_CERT = "auth_cert_der"
        const val IV_SUFFIX = ".iv"
        const val CIPHERTEXT_SUFFIX = ".ciphertext"
        const val AES_KEY_SIZE_BITS = 256
        const val GCM_TAG_LENGTH_BITS = 128
        const val BITS_PER_BYTE = 8
        const val GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / BITS_PER_BYTE
        const val GCM_IV_LENGTH_BYTES = 12
        const val PRIMED_CIPHERTEXT_BYTES = CanSubmission.CAN_DIGITS + GCM_TAG_LENGTH_BYTES
        const val PIN1_MIN_CIPHERTEXT_BYTES = PIN1_MINIMUM_LENGTH + GCM_TAG_LENGTH_BYTES
        const val PIN1_MAX_CIPHERTEXT_BYTES = PIN1_MAXIMUM_LENGTH + GCM_TAG_LENGTH_BYTES
        const val CLEARED_BYTE: Byte = 0
    }
}
