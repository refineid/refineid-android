package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappTxtEntry
import java.security.SecureRandom

/**
 * Discovery records the custodian publishes (RAPP discovery hierarchy
 * section 4.2-4.3).
 *
 * The instance name is a fresh random value on every advertising start.
 * The TXT record carries the version and the mode, and in session mode the
 * rotating discovery hints of the most recently used pairings. A hint is an
 * HMAC over the current 15-minute window keyed from the pairing's static
 * agreement, so nothing that stays the same across windows is published.
 * The core builds and matches every hinted record; this object only names
 * the instance and reads the version and mode.
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

    /** Length of one hint window in seconds (section 4.3). */
    const val HINT_WINDOW_SECONDS = 900L

    /** A fresh `refineid-<8 hex>` instance name. */
    fun ephemeralName(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(RANDOM_BYTE_COUNT).also(random::nextBytes)
        return PREFIX + bytes.joinToString("") { "%02x".format(it) }
    }

    /** The TXT attributes of the given discovery mode, without hints. */
    fun attributes(mode: String): Map<String, String> = mapOf(ATTRIBUTE_VERSION to VERSION, ATTRIBUTE_MODE to mode)

    /** TXT entries the core built, as the attributes a registration takes. */
    fun attributes(entries: List<RappTxtEntry>): Map<String, String> = entries.associate { it.key to it.value }

    /** Resolved TXT attributes as the entries the core matches. */
    fun entries(attributes: Map<String, ByteArray?>): List<RappTxtEntry> =
        attributes.map { (key, value) -> RappTxtEntry(key, value?.decodeToString().orEmpty()) }

    /** Whether resolved TXT attributes publish any discovery hints. */
    fun hasHints(attributes: Map<String, ByteArray?>): Boolean =
        attributes.any { (key, value) ->
            key.equals(ATTRIBUTE_HINTS, ignoreCase = true) && !value?.decodeToString().isNullOrBlank()
        }

    /** Milliseconds until the hint window after the one containing [unixMillis]. */
    fun millisUntilNextWindow(unixMillis: Long): Long {
        val windowMillis = HINT_WINDOW_SECONDS * MILLIS_PER_SECOND
        return windowMillis - Math.floorMod(unixMillis, windowMillis)
    }

    /** The wall clock in whole seconds, which hint windows count. */
    fun nowUnixSeconds(): Long = System.currentTimeMillis() / MILLIS_PER_SECOND

    private const val MILLIS_PER_SECOND = 1_000L

    /**
     * Whether resolved TXT attributes advertise the given mode. Keys compare
     * without regard to case (RFC 6763 section 6.4); values are exact.
     */
    fun matches(
        attributes: Map<String, ByteArray?>,
        mode: String,
    ): Boolean {
        fun value(key: String): String? =
            attributes.entries
                .firstOrNull { it.key.equals(key, ignoreCase = true) }
                ?.value
                ?.decodeToString()
        return value(ATTRIBUTE_VERSION) == VERSION && value(ATTRIBUTE_MODE) == mode
    }
}
