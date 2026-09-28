package fi.refineid.android.rapp

import java.security.SecureRandom

/** Generates, formats, and validates 6-digit numeric pairing codes for RAPP pairing. */
internal object RappPairingCode {
    const val CODE_LENGTH = 6
    const val GROUP_SIZE = 3
    const val DEFAULT_LIFETIME_MS: Long = 180_000L
    private const val ALPHABET = "0123456789"

    fun generate(): String {
        val random = SecureRandom()
        val chars = CharArray(CODE_LENGTH)
        for (i in 0 until CODE_LENGTH) {
            chars[i] = ALPHABET[random.nextInt(ALPHABET.length)]
        }
        return String(chars)
    }

    fun normalize(input: String): String {
        return input.filter { it in '0'..'9' }.take(CODE_LENGTH)
    }

    fun formatted(input: String): String {
        val digits = normalize(input)
        return if (digits.length >= GROUP_SIZE) {
            val first = digits.substring(0, GROUP_SIZE)
            val second = digits.substring(GROUP_SIZE)
            if (second.isEmpty()) "$first " else "$first $second"
        } else {
            digits
        }
    }

    fun isValid(code: String): Boolean {
        return normalize(code).length == CODE_LENGTH
    }
}
