package fi.refineid.android.rapp

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import uniffi.refineid_rapp.RappOperationVault
import uniffi.refineid_rapp.RappPairVault
import uniffi.refineid_rapp.RappStoredProxyJournal
import uniffi.refineid_rapp.RappVaultException
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe durable storage for RAPP pairs and the custodian operation
 * journal on Android. Pair records, which carry the pairing's private key,
 * and the journal are each sealed under their own Keystore key in the
 * no-backup files directory, so they survive restarts but never leave the
 * device. Only non-secret revocation markers stay in preferences.
 */
internal class AndroidRappVault(
    context: Context,
) : RappPairVault,
    RappOperationVault {
    private val pairPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.pairs", Context.MODE_PRIVATE)
    private val revokedPrefs = context.getSharedPreferences("fi.refineid.rapp.vault.revoked", Context.MODE_PRIVATE)

    private val pairRecords =
        RappPairRecordStore(
            root = File(context.noBackupFilesDir, PAIR_RECORD_DIRECTORY),
            sealer = AesGcmJournalSealer(RappPairRecordKeystoreKey::get),
        )
    private val revokedPairs = ConcurrentHashMap<String, ULong>()
    private val proxyJournal =
        RappProxyJournalStore(
            root = File(context.noBackupFilesDir, PROXY_JOURNAL_DIRECTORY),
            sealer = AesGcmJournalSealer(RappJournalKeystoreKey::get),
        )

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

    // --- RappPairVault ---

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
        // Tombstones live exactly as long as their pairing (section 8.2.5).
        proxyJournal.purge(pairId)
    }

    override fun isRevoked(pairId: ByteArray): Boolean {
        return revokedPairs.containsKey(hex(pairId))
    }

    // --- RappOperationVault ---

    override fun persistRequester(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) {
        // Android endpoint acts as proxy
    }

    override fun loadRequester(pairId: ByteArray): List<ByteArray> {
        return emptyList()
    }

    override fun persistProxy(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = proxyJournal.persist(pairId, operationId, record)

    override fun persistProxyResult(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
        result: ByteArray,
    ) = proxyJournal.persistWithResult(pairId, operationId, record, result)

    override fun retainProxyUncertain(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = proxyJournal.retainUncertain(pairId, operationId, record)

    override fun acknowledgeProxyResult(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = proxyJournal.acknowledge(pairId, operationId, record)

    override fun loadProxy(pairId: ByteArray): List<RappStoredProxyJournal> = proxyJournal.load(pairId)

    private companion object {
        const val PROXY_JOURNAL_DIRECTORY = "rapp-proxy-journal"
        const val PAIR_RECORD_DIRECTORY = "rapp-pair-records"
    }
}
