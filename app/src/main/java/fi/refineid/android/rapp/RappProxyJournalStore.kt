// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappStoredProxyJournal
import uniffi.refineid_rapp.RappVaultException
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Seals and opens journal entries so they are encrypted at rest. Opening
 * fails on any tampered or foreign entry.
 */
internal interface RappJournalSealer {
    fun seal(plaintext: ByteArray): ByteArray

    /** @throws java.security.GeneralSecurityException when the entry does not authenticate. */
    fun open(sealed: ByteArray): ByteArray
}

/**
 * The custodian's durable RAPP operation journal (RAPP v26.10.1 sections 8.1
 * and 8.2.5): one sealed file per operation under one directory per pairing.
 *
 * Every transition replaces the operation's file atomically, record and
 * retained result together, so a crash leaves either the previous entry or
 * the next one. Entries live for the lifetime of the pairing and are removed
 * only by [purge] when the pairing is revoked or deleted. The directory is
 * the caller's to choose; on Android it is the no-backup files directory,
 * so entries never leave the device.
 */
internal class RappProxyJournalStore(
    private val root: File,
    private val sealer: RappJournalSealer,
) {
    fun persist(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = synchronized(LOCK) { write(pairId, operationId, record, null) }

    fun persistWithResult(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
        result: ByteArray,
    ) = synchronized(LOCK) { write(pairId, operationId, record, result) }

    /** Replaces the record and keeps the retained result. */
    fun retainUncertain(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = synchronized(LOCK) {
        val current = read(entryFile(pairId, operationId)) ?: throw RappVaultException.Unavailable()
        write(pairId, operationId, record, current.retainedResult)
    }

    /** Replaces the record and erases the retained result, leaving the tombstone. */
    fun acknowledge(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
    ) = synchronized(LOCK) { write(pairId, operationId, record, null) }

    fun load(pairId: ByteArray): List<RappStoredProxyJournal> =
        synchronized(LOCK) {
            val directory = pairDirectory(pairId)
            val entries = directory.listFiles { file -> file.name.endsWith(ENTRY_SUFFIX) } ?: return emptyList()
            entries.sortedBy { it.name }.map { file -> read(file) ?: throw RappVaultException.Unavailable() }
        }

    /** Removes every entry of a revoked or deleted pairing. */
    fun purge(pairId: ByteArray) =
        synchronized(LOCK) {
            pairDirectory(pairId).deleteRecursively()
            Unit
        }

    private fun write(
        pairId: ByteArray,
        operationId: ByteArray,
        record: ByteArray,
        result: ByteArray?,
    ) {
        val target = entryFile(pairId, operationId)
        val directory = target.parentFile ?: throw RappVaultException.Unavailable()
        if (!directory.isDirectory && !directory.mkdirs()) {
            throw RappVaultException.Unavailable()
        }
        val plaintext = encode(record, result)
        try {
            val sealed = sealer.seal(plaintext)
            val temporary = File(directory, target.name + TEMPORARY_SUFFIX)
            temporary.writeBytes(sealed)
            try {
                Files.move(
                    temporary.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                throw RappVaultException.Unavailable()
            }
        } catch (_: IOException) {
            throw RappVaultException.Unavailable()
        } catch (_: java.security.GeneralSecurityException) {
            throw RappVaultException.Unavailable()
        } finally {
            plaintext.fill(0)
        }
    }

    private fun read(file: File): RappStoredProxyJournal? {
        if (!file.isFile) return null
        val plaintext =
            try {
                sealer.open(file.readBytes())
            } catch (_: IOException) {
                return null
            } catch (_: java.security.GeneralSecurityException) {
                return null
            }
        return try {
            decode(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun pairDirectory(pairId: ByteArray) = File(root, hex(pairId))

    private fun entryFile(
        pairId: ByteArray,
        operationId: ByteArray,
    ) = File(pairDirectory(pairId), hex(operationId) + ENTRY_SUFFIX)

    private companion object {
        /** One lock for the process: several vault instances share the same files. */
        val LOCK = Any()
        const val ENTRY_SUFFIX = ".entry"
        const val TEMPORARY_SUFFIX = ".tmp"
        const val LENGTH_BYTES = Int.SIZE_BYTES
        const val PRESENT: Byte = 1
        const val ABSENT: Byte = 0

        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        /** `[record length][record][result flag][result length][result]`, lengths big-endian. */
        fun encode(
            record: ByteArray,
            result: ByteArray?,
        ): ByteArray {
            val resultBytes = result ?: ByteArray(0)
            val buffer =
                ByteBuffer.allocate(LENGTH_BYTES + record.size + 1 + LENGTH_BYTES + resultBytes.size)
            buffer.putInt(record.size).put(record)
            buffer.put(if (result == null) ABSENT else PRESENT)
            buffer.putInt(resultBytes.size).put(resultBytes)
            return buffer.array()
        }

        fun decode(plaintext: ByteArray): RappStoredProxyJournal? =
            try {
                val buffer = ByteBuffer.wrap(plaintext)
                val record = ByteArray(buffer.int).also { buffer.get(it) }
                val flag = buffer.get()
                val result = ByteArray(buffer.int).also { buffer.get(it) }
                when {
                    buffer.hasRemaining() -> null
                    flag == PRESENT -> RappStoredProxyJournal(record, result)
                    flag == ABSENT && result.isEmpty() -> RappStoredProxyJournal(record, null)
                    else -> null
                }
            } catch (_: java.nio.BufferUnderflowException) {
                null
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: NegativeArraySizeException) {
                null
            }
    }
}
