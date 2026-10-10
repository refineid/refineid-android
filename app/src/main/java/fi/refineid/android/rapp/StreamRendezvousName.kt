package fi.refineid.android.rapp

import java.security.SecureRandom

/**
 * Discovery records the custodian publishes (RAPP discovery hierarchy
 * section 4.2-4.3).
 *
 * The instance name is a fresh random value on every advertising start and
 * the TXT record carries only the version and mode, so nothing derived from
 * a pairing code, an offer, or a rendezvous token is ever published.
 */
internal object StreamRendezvousName {
    private const val PREFIX = "refineid-"
    private const val RANDOM_BYTE_COUNT = 4
    const val ATTRIBUTE_VERSION = "v"
    const val ATTRIBUTE_MODE = "mode"
    const val VERSION = "1"
    const val MODE_PAIRING = "pairing"
    const val MODE_SESSION = "session"

    /** A fresh `refineid-<8 hex>` instance name. */
    fun ephemeralName(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(RANDOM_BYTE_COUNT).also(random::nextBytes)
        return PREFIX + bytes.joinToString("") { "%02x".format(it) }
    }

    /** The TXT attributes of the given discovery mode. */
    fun attributes(mode: String): Map<String, String> = mapOf(ATTRIBUTE_VERSION to VERSION, ATTRIBUTE_MODE to mode)

    /** Whether resolved TXT attributes advertise the given mode. */
    fun matches(
        attributes: Map<String, ByteArray?>,
        mode: String,
    ): Boolean =
        attributes[ATTRIBUTE_VERSION]?.decodeToString() == VERSION &&
            attributes[ATTRIBUTE_MODE]?.decodeToString() == mode
}
