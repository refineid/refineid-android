package fi.refineid.android.core

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Process-lifetime PIN1 custody for repeated authentication (credential
 * custody; RAPP v26.10.22 section 11 item 2).
 *
 * A positively verified PIN1 is held only in scrubbed memory, bound to the
 * card that accepted it, and only when that card's PIN 1 counter read
 * pristine before the verification; it never touches storage and is
 * zeroized on replacement, rejection, clear, or a request for another card.
 * A PIN 1 held for one card is never handed out for another: that card
 * simply has no held PIN. A card-rejected PIN1 is remembered as a keyed
 * fingerprint under fresh process-local random material and refused locally
 * thereafter, so a known-bad value can never burn a second card retry. Raw
 * rejected bytes are never kept.
 */
internal class AuthenticationPinCache {
    private val lock = Any()
    private val fingerprintKey = ByteArray(FINGERPRINT_KEY_BYTES).also { SecureRandom().nextBytes(it) }
    private val rejected = HashSet<String>()

    private var heldPin: ByteArray? = null
    private var heldFingerprint: String? = null
    private var heldCard: AuthenticationCardIdentity? = null
    private var custodyGeneration = 0L
    val generation: Long get() = synchronized(lock) { custodyGeneration }

    /** Whether [submission] is the PIN 1 held for [card]. */
    fun isVerified(
        submission: Pin1Submission,
        card: AuthenticationCardIdentity,
    ): Boolean =
        submission.peekBytes { bytes ->
            val fingerprint = fingerprintOf(bytes)
            synchronized(lock) {
                heldPin != null && heldFingerprint == fingerprint && heldCard == card
            }
        }

    /** True when a PIN1 is held for some card. */
    val hasPin: Boolean
        get() = synchronized(lock) { heldPin != null }

    /** True when a PIN1 is held for [card]. */
    fun holds(card: AuthenticationCardIdentity): Boolean = synchronized(lock) { heldPin != null && heldCard == card }

    /**
     * The PIN1 held for [card] as a fresh submission, or null when none is
     * held for it. A PIN1 held for another card is destroyed: the card in
     * use is not the one it was verified on.
     */
    fun take(card: AuthenticationCardIdentity): Pin1Submission? =
        synchronized(lock) {
            val held = heldPin ?: return null
            if (heldCard != card) {
                custodyGeneration += 1
                clearHeldLocked()
                return null
            }
            Pin1Submission.fromOwnedBytes(held.copyOf())
        }

    /** True when these digits were already card-rejected this process. */
    fun isRejected(pinBytes: ByteArray): Boolean {
        val fingerprint = fingerprintOf(pinBytes)
        return synchronized(lock) { fingerprint in rejected }
    }

    /** True when this submission's digits were already card-rejected this process. */
    fun isRejected(submission: Pin1Submission): Boolean = submission.peekBytes { isRejected(it) }

    /**
     * Holds PIN1 digits the card named by [retention] accepted, taking
     * ownership of them. False, with the digits zeroed, when custody changed
     * since [expectedGeneration].
     */
    fun recordVerified(
        pinBytes: ByteArray,
        retention: Pin1Retention,
        expectedGeneration: Long? = null,
    ): Boolean {
        val fingerprint = fingerprintOf(pinBytes)
        synchronized(lock) {
            if (expectedGeneration != null && expectedGeneration != custodyGeneration) {
                pinBytes.fill(CLEARED_BYTE)
                return false
            }
            clearHeldLocked()
            heldPin = pinBytes
            heldFingerprint = fingerprint
            heldCard = retention.card
            rejected.remove(fingerprint)
            return true
        }
    }

    /** Remember PIN1 digits the card rejected, taking ownership of them. */
    fun recordRejected(pinBytes: ByteArray) {
        val fingerprint = fingerprintOf(pinBytes)
        pinBytes.fill(CLEARED_BYTE)
        synchronized(lock) {
            rejected.add(fingerprint)
            if (heldFingerprint == fingerprint) {
                clearHeldLocked()
            }
        }
    }

    fun clear() {
        synchronized(lock) {
            custodyGeneration += 1
            clearHeldLocked()
        }
    }

    private fun clearHeldLocked() {
        heldPin?.fill(CLEARED_BYTE)
        heldPin = null
        heldFingerprint = null
        heldCard = null
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
        const val CLEARED_BYTE: Byte = 0
    }
}
