// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit

/**
 * A synthetic self-signed X.509 certificate for tests that need a card's
 * authentication certificate, made with the host's OpenSSL; null where
 * OpenSSL is not installed.
 */
internal object RappTestCertificate {
    private const val OPENSSL = "openssl"
    private val SEARCH_PATH = listOf("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin")
    private const val COMMON_NAME = "/CN=Synthetic Holder"
    private const val VALIDITY_DAYS = "1"
    private const val TIMEOUT_SECONDS = 15L
    private const val SUCCESS_EXIT_CODE = 0
    private const val KEY_FILE = "key.pem"
    private const val PEM_FILE = "certificate.pem"
    private const val DER_FILE = "certificate.der"

    val der: ByteArray? by lazy(::make)

    private fun make(): ByteArray? {
        val openssl = SEARCH_PATH.map { Path.of(it, OPENSSL) }.firstOrNull(Files::isExecutable) ?: return null
        val directory = Files.createTempDirectory("rapp-certificate")
        return try {
            run(
                openssl,
                directory,
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-pkeyopt",
                "ec_param_enc:named_curve",
                "-nodes",
                "-days",
                VALIDITY_DAYS,
                "-subj",
                COMMON_NAME,
                "-keyout",
                KEY_FILE,
                "-out",
                PEM_FILE,
            )
            run(openssl, directory, "x509", "-in", PEM_FILE, "-outform", "DER", "-out", DER_FILE)
            Files.readAllBytes(directory.resolve(DER_FILE))
        } finally {
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun run(
        openssl: Path,
        directory: Path,
        vararg arguments: String,
    ) {
        val process =
            ProcessBuilder(listOf(openssl.toString()) + arguments)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS) && process.exitValue() == SUCCESS_EXIT_CODE) {
            "OpenSSL failed: $output"
        }
    }
}
