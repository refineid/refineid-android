// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import uniffi.refineid_doc_sign_android.DocumentFormat
import uniffi.refineid_doc_sign_android.DocumentOutcome
import uniffi.refineid_doc_sign_android.DocumentVerdict
import uniffi.refineid_doc_sign_android.LocalCardSigner
import uniffi.refineid_doc_sign_android.TimestampAuthority
import uniffi.refineid_doc_sign_android.VerifyFailure
import uniffi.refineid_doc_sign_android.setHttpClient
import uniffi.refineid_doc_sign_android.signDocuments
import uniffi.refineid_doc_sign_android.verifyDocument
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.util.Locale

/** One chosen file: the name the holder sees and its bytes. */
internal class NamedInput(
    val name: String,
    val open: () -> InputStream,
)

/**
 * Signing and verifying chosen files with the core. The core works on
 * files, so each input is staged under its own name in a fresh directory
 * below [workDirectory], which is removed when the call returns. Every
 * call blocks and goes to the card and the network, so it runs off the
 * main thread.
 */
internal object CoreDocuments {
    private var httpClientInstalled = false

    /** Register the app's HTTP client with the core, once per process. */
    @Synchronized
    fun installHttpClient(client: CoreHttpClient = CoreHttpClient()) {
        if (!httpClientInstalled) {
            setHttpClient(client)
            httpClientInstalled = true
        }
    }

    /**
     * Sign [inputs] with the card through [signer] into [outputDirectory]:
     * each PDF on its own as [DocumentFormat.PADES], or every file as one
     * [DocumentFormat.ASIC_E] container. The PDF seal is in [locale]'s
     * language; [timestampAuthorities] are the holder's, none meaning the
     * core's default. One outcome per input for PDFs, one for the container.
     *
     * @throws uniffi.refineid_doc_sign_android.SignFailure when nothing was written.
     */
    fun sign(
        signer: LocalCardSigner,
        inputs: List<NamedInput>,
        workDirectory: File,
        outputDirectory: File,
        format: DocumentFormat,
        locale: Locale,
        timestampAuthorities: List<TimestampAuthority>,
    ): List<DocumentOutcome> =
        staged(workDirectory, inputs) { files ->
            signDocuments(
                signer = signer,
                inputs = files.map(File::getAbsolutePath),
                outputDirectory = outputDirectory.absolutePath,
                format = format,
                language = locale.language,
                timestampAuthorities = timestampAuthorities,
            )
        }

    /**
     * Verify every signature of [input].
     *
     * @throws VerifyFailure when there is nothing to judge.
     */
    fun verify(
        input: NamedInput,
        workDirectory: File,
    ): DocumentVerdict =
        staged(workDirectory, listOf(input)) { files ->
            verifyDocument(files.single().absolutePath)
        }

    /** [inputs] written under their names into a fresh directory for the span of [operation]. */
    private fun <T> staged(
        workDirectory: File,
        inputs: List<NamedInput>,
        operation: (List<File>) -> T,
    ): T {
        val directory = Files.createTempDirectory(workDirectory.toPath(), STAGING_PREFIX).toFile()
        try {
            val files =
                stagedNames(inputs.map(NamedInput::name)).zip(inputs) { name, input ->
                    File(directory, name).also { file ->
                        input.open().use { source -> file.outputStream().use(source::copyTo) }
                    }
                }
            return operation(files)
        } finally {
            directory.deleteRecursively()
        }
    }

    /**
     * File names for [names] in one directory: each reduced to its last path
     * segment, an empty one replaced, and a repeated one prefixed with its
     * position among the repeats so no input overwrites another.
     */
    internal fun stagedNames(names: List<String>): List<String> {
        val plain = names.map { name -> File(name).name.ifEmpty { DEFAULT_NAME } }
        val seen = mutableMapOf<String, Int>()
        return plain.map { name ->
            val occurrence = seen.getOrDefault(name, 0)
            seen[name] = occurrence + 1
            if (plain.count { it == name } > 1) "$occurrence$NAME_SEPARATOR$name" else name
        }
    }

    /**
     * Copy the signed document at [path] into [destination] and remove it.
     *
     * @throws IOException when the copy fails; the source stays.
     */
    fun deliver(
        path: String,
        destination: () -> java.io.OutputStream,
    ) {
        val source = File(path)
        source.inputStream().use { input -> destination().use(input::copyTo) }
        if (!source.delete()) {
            throw IOException("signed document could not be removed after delivery")
        }
    }

    private const val STAGING_PREFIX = "sign-"
    private const val DEFAULT_NAME = "document"
    private const val NAME_SEPARATOR = "-"
}
