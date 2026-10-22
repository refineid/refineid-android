package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappVaultException
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe durable storage for RAPP pairs on Android. Pair records, which
 * carry the pairing's private key, are sealed under a Keystore key in the
 * no-backup files directory, so they survive restarts but never leave the
 * device. Only non-secret revocation markers stay in preferences.
 */
internal class AndroidRappVault(
    context: Context,
) : RappPairVault {
    private val pairPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.pairs", Context.MODE_PRIVATE)
    private val revokedPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.revoked", Context.MODE_PRIVATE)

    private val pairRecords =
        RappPairRecordStore(
            root = File(context.noBackupFilesDir, PAIR_RECORD_DIRECTORY),
            sealer = AesGcmSealer(RappPairRecordKeystoreKey::get),
        )
    private val revokedPairs = ConcurrentHashMap<String, ULong>()

    init {
        migrateLegacyPairRecords()
        for ((key, value) in revokedPrefs.all) {
            if (value is Long) {
                revokedPairs[key] = value.toULong()
            }
        }
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /**
     * Moves records an earlier version kept as plaintext preferences into the
     * sealed store, then erases them; a value that does not decode is erased
     * without migrating.
     */
    private fun migrateLegacyPairRecords() {
        val legacy =
            pairPrefs.all
                .mapNotNull { (key, value) ->
                    val decoded =
                        try {
                            (value as? String)?.let { Base64.decode(it, Base64.NO_WRAP) }
                        } catch (_: IllegalArgumentException) {
                            null
                        }
                    decoded?.let { key to it }
                }.toMap()
        try {
            pairRecords.migrate(legacy)
        } catch (_: RappVaultException) {
            return
        }
        legacy.values.forEach { it.fill(0) }
        pairPrefs.edit(commit = true) { clear() }
    }

    override fun insertDeviceOnly(
        pairId: ByteArray,
        record: ByteArray,
    ) {
        val idHex = hex(pairId)
        if (revokedPairs.containsKey(idHex)) {
            throw RappVaultException.IdentifierAlreadyUsed()
        }
        pairRecords.insert(idHex, record)
    }

    override fun replaceDeviceOnly(
        pairId: ByteArray,
        record: ByteArray,
    ) {
        val idHex = hex(pairId)
        if (revokedPairs.containsKey(idHex)) {
            throw RappVaultException.IdentifierAlreadyUsed()
        }
        pairRecords.insert(idHex, record)
    }

    override fun loadDeviceOnly(pairId: ByteArray): ByteArray? {
        val idHex = hex(pairId)
        if (revokedPairs.containsKey(idHex)) return null
        return pairRecords.load(idHex)
    }

    override fun revokeDeviceOnly(
        pairId: ByteArray,
        revokedAtMs: ULong,
    ) {
        val idHex = hex(pairId)
        pairRecords.remove(idHex)
        revokedPairs[idHex] = revokedAtMs
        revokedPrefs.edit { putLong(idHex, revokedAtMs.toLong()) }
    }

    override fun isRevoked(pairId: ByteArray): Boolean = revokedPairs.containsKey(hex(pairId))

    /** The identifier of every stored pair record that is not revoked. */
    val storedPairIds: List<String>
        get() = pairRecords.pairIdentifiers().filterNot(revokedPairs::containsKey)

    private companion object {
        const val PAIR_RECORD_DIRECTORY = "rapp-pair-records"
    }
}
