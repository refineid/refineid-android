package fi.refineid.android.rapp

import java.security.SecureRandom

/** Generates, formats, and validates 6-character Crockford Base32 pairing codes for RAPP v26.10.21. */
internal object RappPairingCode {
    const val CODE_LENGTH = 6
    const val GROUP_SIZE = 2

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

    /** The separators typed between the displayed groups, which entry ignores. */
    private const val SEPARATORS = " -"

    /**
     * Applies the entry rule of RAPP v26.10.21 section 3.1: the 32 alphabet
     * characters, an ASCII lowercase letter folded to its uppercase form, and
     * spaces and hyphens ignored. Returns the canonical string, which may be
     * shorter or longer than a code, or an empty string when any other
     * character appears, the excluded letters I, L, O and U among them.
     * [isValid] decides the exact length.
     */
    fun normalize(input: String): String {
        val sb = StringBuilder()
        for (c in input) {
            if (c in SEPARATORS) continue
            when (val upper = if (c in 'a'..'z') c - ('a' - 'A') else c) {
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
