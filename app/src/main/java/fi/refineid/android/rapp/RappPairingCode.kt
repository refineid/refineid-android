package fi.refineid.android.rapp

import java.security.SecureRandom
import java.text.Normalizer

/** Generates, formats, and validates 6-character Crockford Base32 pairing codes for RAPP v26.10.10. */
internal object RappPairingCode {
    const val CODE_LENGTH = 6
    const val GROUP_SIZE = 2

    /** Offer lifetime both peers bind into the offer hash (RAPP v26.10.10 section 3.3). */
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

    /** ASCII whitespace (SPACE, TAB, LF, VT, FF, CR) and the hyphen, removed by step 4. */
    private const val STRIPPED_CHARS = " \t\n\u000B\u000C\r-"

    /**
     * Applies the Crockford Base32 canonicalization pipeline per RAPP v26.10.10 section 3.1.
     *
     * NFKC first, then ASCII-only uppercasing, removal of ASCII whitespace
     * and hyphens, and the Crockford decode aliases (I and L to 1, O to 0).
     * Returns the canonical string, which may be shorter or longer than a
     * code, or an empty string when any character is outside the alphabet
     * or is the rejected U. [isValid] decides the exact length.
     */
    fun normalize(input: String): String {
        val nfkc = Normalizer.normalize(input, Normalizer.Form.NFKC)
        val sb = StringBuilder()
        for (c in nfkc) {
            if (c in STRIPPED_CHARS) continue
            when (val upper = if (c in 'a'..'z') c - ('a' - 'A') else c) {
                'I', 'L' -> sb.append('1')
                'O' -> sb.append('0')
                in ALPHABET -> sb.append(upper)
                else -> return ""
            }
        }
        return sb.toString()
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
