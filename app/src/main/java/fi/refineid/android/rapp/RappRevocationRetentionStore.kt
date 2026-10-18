// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappVaultException
import java.io.File
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.GeneralSecurityException
import java.security.MessageDigest

/**
 * Device-local store of the revocation retentions the core returns when a
 * pairing is revoked (RAPP v26.10.18 section 4.6 item 2): the revocation
 * key, the pair identifier and the revocation time, encoded by the core and
 * opaque here.
 *
 * Each retention is one sealed file under [root], a no-backup directory,
 * named by a digest of its bytes so the same retention is stored once. A
 * retention stays until the core reports it expired (section 4.6 item 4),
 * after which [unexpired] deletes it. A file that does not open reads as
 * absent and is deleted.
 */
internal class RappRevocationRetentionStore(
    private val root: File,
    private val sealer: RappJournalSealer,
) {
    /** Seals and stores one retention the core produced. */
    fun retain(retention: ByteArray) =
        synchronized(LOCK) {
            if (!root.isDirectory && !root.mkdirs()) throw RappVaultException.Unavailable()
            val target = File(root, digestName(retention) + RETENTION_SUFFIX)
            try {
                val temporary = File(root, target.name + TEMPORARY_SUFFIX)
                temporary.writeBytes(sealer.seal(retention))
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

    /**
     * Every retention still to be announced at [nowUnixSeconds], judged by
     * [isExpired]; expired and unreadable ones are deleted on the way.
     */
    fun unexpired(
        nowUnixSeconds: ULong,
        isExpired: (retention: ByteArray, nowUnixSeconds: ULong) -> Boolean,
    ): List<ByteArray> =
        synchronized(LOCK) {
            val files = root.listFiles { file -> file.name.endsWith(RETENTION_SUFFIX) } ?: return emptyList()
            files.sortedBy { it.name }.mapNotNull { file ->
                val retention = open(file)
                if (retention == null || isExpired(retention, nowUnixSeconds)) {
                    file.delete()
                    null
                } else {
                    retention
                }
            }
        }

    private fun open(file: File): ByteArray? =
        try {
            sealer.open(file.readBytes())
        } catch (_: IOException) {
            null
        } catch (_: GeneralSecurityException) {
            null
        }

    private fun digestName(retention: ByteArray): String =
        MessageDigest
            .getInstance(DIGEST_ALGORITHM)
            .digest(retention)
            .joinToString("") { "%02x".format(it) }

    private companion object {
        /** One lock for the process: several vault instances share the same files. */
        val LOCK = Any()
        const val RETENTION_SUFFIX = ".revocation"
        const val TEMPORARY_SUFFIX = ".tmp"
        const val DIGEST_ALGORITHM = "SHA-256"
    }
}
