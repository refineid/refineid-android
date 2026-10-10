package fi.refineid.android.rapp

import java.security.SecureRandom
import java.text.Normalizer

/** Generates, formats, and validates 6-character Crockford Base32 pairing codes for RAPP v26.10.1. */
internal object RappPairingCode {
    const val CODE_LENGTH = 6
    const val GROUP_SIZE = 2

    /** Offer lifetime both peers bind into the offer hash (RAPP v26.10.1 section 3.3). */
    const val DEFAULT_LIFETIME_MS: Long = 60_000L

    /** Crockford Base32 alphabet (32 symbols, excluding I, L, O, U). */
    const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    fun generate(): String {
        val random = SecureRandom()
        val chars = CharArray(CODE_LENGTH)
        for (i in 0 until CODE_LENGTH) {
            chars[i] = ALPHABET[random.nextInt(ALPHABET.length)]
        }
        return String(chars)
    }

    /**
     * Applies the Crockford Base32 canonicalization pipeline:
     * 1. Unicode NFKC normalization
     * 2. ASCII lowercase to uppercase
     * 3. Strip whitespace and hyphens
     * 4. Apply Crockford decode aliases (I, L -> 1; O -> 0; reject U)
     * 5. Filter valid Crockford characters up to CODE_LENGTH
     */
    fun normalize(input: String): String {
        val nfkc = Normalizer.normalize(input, Normalizer.Form.NFKC)
        val filtered = nfkc.uppercase().filter { !it.isWhitespace() && it != '-' }
        val sb = StringBuilder()
        for (c in filtered) {
            when (c) {
                'I', 'L' -> sb.append('1')

                'O' -> sb.append('0')

                'U' -> return ""

                // U is explicitly rejected per RAPP v26.10.1 §3.1
                in ALPHABET -> sb.append(c)

                else -> return "" // Non-Crockford characters reject the code
            }
        }
        return sb.take(CODE_LENGTH).toString()
    }

    /** Formats a pairing code into two-character clusters: "XX XX XX" (e.g., "7K X4 M9"). */
    fun formatted(input: String): String {
        val normalized = normalize(input)
        return when {
            normalized.length <= GROUP_SIZE -> {
                normalized
            }

            normalized.length <= GROUP_SIZE * 2 -> {
                val g1 = normalized.substring(0, GROUP_SIZE)
                val g2 = normalized.substring(GROUP_SIZE)
                "$g1 $g2"
            }

            else -> {
                val g1 = normalized.substring(0, GROUP_SIZE)
                val g2 = normalized.substring(GROUP_SIZE, GROUP_SIZE * 2)
                val g3 = normalized.substring(GROUP_SIZE * 2)
                "$g1 $g2 $g3"
            }
        }
    }

    fun isValid(code: String): Boolean {
        val normalized = normalize(code)
        return normalized.length == CODE_LENGTH && normalized.all { it in ALPHABET }
    }
}
