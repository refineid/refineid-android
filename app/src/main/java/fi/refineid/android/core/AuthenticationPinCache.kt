package fi.refineid.android.core

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Process-lifetime PIN1 custody for repeated authentication.
 *
 * A positively verified PIN1 is held only in scrubbed memory for an
 * idle-session window (refreshed on each use), so a running app signs
 * repeatedly without re-prompting; the value never touches storage and
 * is zeroized on expiry, replacement, or clear. A card-rejected PIN1 is
 * remembered as a keyed fingerprint under fresh process-local random
 * material and refused locally thereafter, so a known-bad value can
 * never burn a second card retry. Raw rejected bytes are never kept.
 *
 * Mirrors the refineid-core pin-cache policy: fifteen-minute idle PIN1
 * lifetime, plus a process-lifetime negative cache. Time is injected so
 * the window is testable without a clock.
 */
internal class AuthenticationPinCache(
    private val lifetimeMillis: Long? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val lock = Any()
    private val fingerprintKey = ByteArray(FINGERPRINT_KEY_BYTES).also { SecureRandom().nextBytes(it) }
    private val rejected = HashSet<String>()

    private var heldPin: ByteArray? = null
    private var heldFingerprint: String? = null
    private var expiresAtMillis: Long = 0

    /** True when a valid PIN1 is currently held in cache. */
    val hasPin: Boolean
        get() = synchronized(lock) { heldPin != null }

    /** A cached, unexpired PIN1 as a fresh submission, or null. */
    fun take(): Pin1Submission? =
        synchronized(lock) {
            val held = heldPin ?: return null
            if (lifetimeMillis != null) {
                if (clock() >= expiresAtMillis) {
                    clearHeldLocked()
                    return null
                }
                expiresAtMillis = clock() + lifetimeMillis
            }
            Pin1Submission.fromOwnedBytes(held.copyOf())
        }

    /** True when these digits were already card-rejected this process. */
    fun isRejected(pinBytes: ByteArray): Boolean {
        val fingerprint = fingerprintOf(pinBytes)
        return synchronized(lock) { fingerprint in rejected }
    }

    /** Retain PIN1 digits the card accepted, taking ownership of them. */
    fun recordVerified(pinBytes: ByteArray) {
        val fingerprint = fingerprintOf(pinBytes)
        synchronized(lock) {
            clearHeldLocked()
            heldPin = pinBytes
            heldFingerprint = fingerprint
            if (lifetimeMillis != null) {
                expiresAtMillis = clock() + lifetimeMillis
            }
            rejected.remove(fingerprint)
        }
    }

    /** Remember PIN1 digits the card rejected, taking ownership of them. */
    fun recordRejected(pinBytes: ByteArray) {
        val fingerprint = fingerprintOf(pinBytes)
        pinBytes.fill(0)
        synchronized(lock) {
            rejected.add(fingerprint)
            if (heldFingerprint == fingerprint) {
                clearHeldLocked()
            }
        }
    }

    fun clear() {
        synchronized(lock) { clearHeldLocked() }
    }

    private fun clearHeldLocked() {
        heldPin?.fill(0)
        heldPin = null
        heldFingerprint = null
        expiresAtMillis = 0
    }

    private fun fingerprintOf(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance(DIGEST_NAME)
        digest.update(fingerprintKey)
        digest.update(bytes)
        return digest.digest().joinToString(separator = "") { byte ->
            (byte.toInt() and UNSIGNED_BYTE_MASK).toString(HEX_RADIX).padStart(HEX_WIDTH, '0')
        }
    }

    private companion object {
        const val FINGERPRINT_KEY_BYTES = 32
        const val DIGEST_NAME = "SHA-256"
        const val UNSIGNED_BYTE_MASK = 0xFF
        const val HEX_RADIX = 16
        const val HEX_WIDTH = 2
    }
}
