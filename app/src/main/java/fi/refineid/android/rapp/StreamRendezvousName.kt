package fi.refineid.android.rapp

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Derives published rendezvous names for mDNS discovery. */
internal object StreamRendezvousName {
    const val MANUAL_PAIRING_SERVICE_NAME = "rf-pairing"
    private const val DIGEST_PREFIX_BYTE_COUNT = 8
    private const val PREFIX = "rf-"

    fun name(sharingValue: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(sharingValue)
        val hex = StringBuilder()
        for (i in 0 until DIGEST_PREFIX_BYTE_COUNT) {
            hex.append(String.format("%02x", digest[i]))
        }
        return PREFIX + hex.toString()
    }

    fun name(sharingOfferUri: String): String {
        return name(sharingOfferUri.toByteArray(StandardCharsets.UTF_8))
    }
}
