// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappVaultException
import java.io.File
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException

/**
 * Device-local store of encoded RAPP pair records, which carry the pairing's
 * static private key (RAPP v26.10.10 section 4.3.4).
 *
 * Each record is one file named by its pair identifier under [root], a
 * no-backup directory, sealed by [sealer] and replaced by an atomic move. A
 * file that does not open, because it was altered or its key is gone, reads
 * as absent.
 */
internal class RappPairRecordStore(
    private val root: File,
    private val sealer: RappJournalSealer,
) {
    /** Seals and stores one record, replacing any earlier one. */
    fun insert(
        pairIdHex: String,
        record: ByteArray,
    ) = synchronized(LOCK) {
        if (!root.isDirectory && !root.mkdirs()) throw RappVaultException.Unavailable()
        val target = file(pairIdHex)
        try {
            val temporary = File(root, target.name + TEMPORARY_SUFFIX)
            temporary.writeBytes(sealer.seal(record))
            Files.move(
                temporary.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            throw RappVaultException.Unavailable()
        } catch (_: IOException) {
            throw RappVaultException.Unavailable()
        } catch (_: GeneralSecurityException) {
            throw RappVaultException.Unavailable()
        }
    }

    /** The record of [pairIdHex], or null when absent or unreadable. */
    fun load(pairIdHex: String): ByteArray? =
        synchronized(LOCK) {
            val target = file(pairIdHex)
            if (!target.isFile) return null
            try {
                sealer.open(target.readBytes())
            } catch (_: IOException) {
                null
            } catch (_: GeneralSecurityException) {
                null
            }
        }

    /** Deletes the record of [pairIdHex]. */
    fun remove(pairIdHex: String) =
        synchronized(LOCK) {
            file(pairIdHex).delete()
            Unit
        }

    /**
     * Seals every legacy plaintext record into this store and returns the
     * identifiers it migrated, so the caller can erase them from their old
     * location. An entry that already exists here is not overwritten.
     */
    fun migrate(legacy: Map<String, ByteArray>): List<String> =
        legacy.mapNotNull { (pairIdHex, record) ->
            if (!isPairIdentifier(pairIdHex)) return@mapNotNull null
            if (load(pairIdHex) == null) insert(pairIdHex, record)
            pairIdHex
        }

    private fun file(pairIdHex: String): File {
        if (!isPairIdentifier(pairIdHex)) throw RappVaultException.Unavailable()
        return File(root, pairIdHex + RECORD_SUFFIX)
    }

    private companion object {
        /** One lock for the process: several vault instances share the same files. */
        val LOCK = Any()
        const val RECORD_SUFFIX = ".pair"
        const val TEMPORARY_SUFFIX = ".tmp"
        val PAIR_IDENTIFIER = Regex("[0-9a-f]{32}")

        fun isPairIdentifier(text: String) = PAIR_IDENTIFIER.matches(text)
    }
}
