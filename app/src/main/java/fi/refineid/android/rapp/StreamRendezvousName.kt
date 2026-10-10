package fi.refineid.android.rapp

import uniffi.refineid_rapp.rappDiscoveryHint
import java.security.SecureRandom

/**
 * Discovery records the custodian publishes (RAPP discovery hierarchy
 * section 4.2-4.3).
 *
 * The instance name is a fresh random value on every advertising start and
 * the TXT record carries the version, the mode, and in session mode the
 * rotating discovery hints of section 4.3. A hint is an HMAC over the
 * current 15-minute window keyed from a rendezvous token, so nothing that
 * stays the same across windows, and no token, is ever published.
 */
internal object StreamRendezvousName {
    private const val PREFIX = "refineid-"
    private const val RANDOM_BYTE_COUNT = 4
    const val ATTRIBUTE_VERSION = "v"
    const val ATTRIBUTE_MODE = "mode"
    const val VERSION = "1"
    const val MODE_PAIRING = "pairing"
    const val MODE_SESSION = "session"
    const val ATTRIBUTE_HINTS = "hints"

    /** Hints one session record carries at most (section 4.3). */
    const val MAX_HINTS = 4

    /** Length of one hint window in seconds (section 4.3). */
    const val HINT_WINDOW_SECONDS = 900L

    /** The hint of [token] for the window containing [unixSeconds]. */
    val coreHint: (ByteArray, Long) -> ByteArray = { token, unixSeconds ->
        rappDiscoveryHint(token, unixSeconds.toULong())
    }

    /** How a session record's hints relate to one stored pairing. */
    enum class HintMatch {
        /** A hint names the pairing in the current or an adjacent window. */
        NAMED,

        /** The record publishes no hints. */
        UNHINTED,

        /** The record publishes hints, none of them for the pairing. */
        OTHER,
    }

    /** A fresh `refineid-<8 hex>` instance name. */
    fun ephemeralName(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(RANDOM_BYTE_COUNT).also(random::nextBytes)
        return PREFIX + bytes.joinToString("") { "%02x".format(it) }
    }

    /** The TXT attributes of the given discovery mode. */
    fun attributes(mode: String): Map<String, String> = mapOf(ATTRIBUTE_VERSION to VERSION, ATTRIBUTE_MODE to mode)

    /**
     * Session-mode TXT attributes with the hints of up to [MAX_HINTS] stored
     * pairings for the window containing [unixSeconds].
     */
    fun sessionAttributes(
        tokens: List<ByteArray>,
        unixSeconds: Long,
        hint: (ByteArray, Long) -> ByteArray = coreHint,
    ): Map<String, String> {
        val base = attributes(MODE_SESSION)
        if (tokens.isEmpty()) return base
        val hints = tokens.take(MAX_HINTS).joinToString(",") { token -> hint(token, unixSeconds).toHex() }
        return base + (ATTRIBUTE_HINTS to hints)
    }

    /**
     * Whether a session record's hints name the pairing of [token], checking
     * the current and both adjacent windows to absorb clock skew.
     */
    fun hintMatch(
        attributes: Map<String, ByteArray?>,
        token: ByteArray,
        unixSeconds: Long,
        hint: (ByteArray, Long) -> ByteArray = coreHint,
    ): HintMatch {
        val published =
            attributes[ATTRIBUTE_HINTS]
                ?.decodeToString()
                ?.split(',')
                ?.map(String::trim)
                ?.filter(String::isNotEmpty)
                .orEmpty()
        if (published.isEmpty()) return HintMatch.UNHINTED
        val named =
            (-1L..1L).any { offset ->
                hint(token, unixSeconds + offset * HINT_WINDOW_SECONDS).toHex() in published
            }
        return if (named) HintMatch.NAMED else HintMatch.OTHER
    }

    /** Milliseconds until the hint window after the one containing [unixMillis]. */
    fun millisUntilNextWindow(unixMillis: Long): Long {
        val windowMillis = HINT_WINDOW_SECONDS * MILLIS_PER_SECOND
        return windowMillis - Math.floorMod(unixMillis, windowMillis)
    }

    /** The wall clock in whole seconds, which hint windows count. */
    fun nowUnixSeconds(): Long = System.currentTimeMillis() / MILLIS_PER_SECOND

    private const val MILLIS_PER_SECOND = 1_000L

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /** Whether resolved TXT attributes advertise the given mode. */
    fun matches(
        attributes: Map<String, ByteArray?>,
        mode: String,
    ): Boolean =
        attributes[ATTRIBUTE_VERSION]?.decodeToString() == VERSION &&
            attributes[ATTRIBUTE_MODE]?.decodeToString() == mode
}
