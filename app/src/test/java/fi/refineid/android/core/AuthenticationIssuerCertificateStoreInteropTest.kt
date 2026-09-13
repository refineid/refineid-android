// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Comparator
import java.util.concurrent.TimeUnit

class AuthenticationIssuerCertificateStoreInteropTest {
    @Test
    fun returnsOnlyTheExactCryptographicIssuerAsOwnedDer() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL is required for the issuer-store test", openssl != null)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            val environment = IssuerStoreEnvironment(checkNotNull(openssl), directory)
            environment.generate()
            val leaf = Files.readAllBytes(directory.resolve(LEAF_DER_FILENAME))
            val issuer = Files.readAllBytes(directory.resolve(ISSUER_DER_FILENAME))
            val wrongIssuer = Files.readAllBytes(directory.resolve(WRONG_ISSUER_DER_FILENAME))
            try {
                val store =
                    AuthenticationIssuerCertificateStore(
                        listOf(
                            parseCertificate(wrongIssuer),
                            parseCertificate(issuer),
                        ),
                    )
                val matched = checkNotNull(store.copyIssuerCertificate(leaf))
                try {
                    assertArrayEquals(issuer, matched)
                    matched.fill(CLEARED_BYTE)
                    val secondCopy = checkNotNull(store.copyIssuerCertificate(leaf))
                    try {
                        assertArrayEquals(issuer, secondCopy)
                    } finally {
                        secondCopy.fill(CLEARED_BYTE)
                    }
                } finally {
                    matched.fill(CLEARED_BYTE)
                }

                val withTrailingData = leaf + TRAILING_DATA_BYTE
                try {
                    assertNull(store.copyIssuerCertificate(withTrailingData))
                } finally {
                    withTrailingData.fill(CLEARED_BYTE)
                }
                assertNull(store.copyIssuerCertificate(MALFORMED_CERTIFICATE))
                assertNull(
                    AuthenticationIssuerCertificateStore(listOf(parseCertificate(leaf)))
                        .copyIssuerCertificate(leaf),
                )
            } finally {
                leaf.fill(CLEARED_BYTE)
                issuer.fill(CLEARED_BYTE)
                wrongIssuer.fill(CLEARED_BYTE)
            }
        } finally {
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate =
        CertificateFactory
            .getInstance(X509_CERTIFICATE_TYPE)
            .generateCertificate(encoded.inputStream()) as X509Certificate

    private fun findExecutable(name: String): Path? =
        TOOL_DIRECTORIES
            .asSequence()
            .map { directory -> Path.of(directory, name) }
            .firstOrNull(Files::isExecutable)

    private class IssuerStoreEnvironment(
        private val openssl: Path,
        private val directory: Path,
    ) {
        fun generate() {
            generateIssuer(
                keyFilename = ISSUER_KEY_FILENAME,
                certificateFilename = ISSUER_PEM_FILENAME,
            )
            generateIssuer(
                keyFilename = WRONG_ISSUER_KEY_FILENAME,
                certificateFilename = WRONG_ISSUER_PEM_FILENAME,
            )
            run(
                listOf(
                    CERTIFICATE_REQUEST_COMMAND,
                    NEW_REQUEST_ARGUMENT,
                    NEW_KEY_ARGUMENT,
                    EC_KEY_ARGUMENT,
                    KEY_OPTION_ARGUMENT,
                    P256_CURVE_ARGUMENT,
                    UNENCRYPTED_KEY_ARGUMENT,
                    SUBJECT_ARGUMENT,
                    LEAF_SUBJECT,
                    KEY_OUTPUT_ARGUMENT,
                    LEAF_KEY_FILENAME,
                    OUTPUT_ARGUMENT,
                    LEAF_REQUEST_FILENAME,
                ),
            )
            run(
                listOf(
                    CERTIFICATE_COMMAND,
                    CERTIFICATE_REQUEST_INPUT_ARGUMENT,
                    INPUT_ARGUMENT,
                    LEAF_REQUEST_FILENAME,
                    CERTIFICATE_AUTHORITY_ARGUMENT,
                    ISSUER_PEM_FILENAME,
                    CERTIFICATE_AUTHORITY_KEY_ARGUMENT,
                    ISSUER_KEY_FILENAME,
                    CREATE_CERTIFICATE_AUTHORITY_SERIAL_ARGUMENT,
                    SHA384_ARGUMENT,
                    VALIDITY_ARGUMENT,
                    CERTIFICATE_VALIDITY_DAYS,
                    OUTPUT_ARGUMENT,
                    LEAF_PEM_FILENAME,
                ),
            )
            convert(LEAF_PEM_FILENAME, LEAF_DER_FILENAME)
            convert(ISSUER_PEM_FILENAME, ISSUER_DER_FILENAME)
            convert(WRONG_ISSUER_PEM_FILENAME, WRONG_ISSUER_DER_FILENAME)
        }

        private fun generateIssuer(
            keyFilename: String,
            certificateFilename: String,
        ) {
            run(
                listOf(
                    CERTIFICATE_REQUEST_COMMAND,
                    SELF_SIGNED_ARGUMENT,
                    NEW_KEY_ARGUMENT,
                    EC_KEY_ARGUMENT,
                    KEY_OPTION_ARGUMENT,
                    P256_CURVE_ARGUMENT,
                    SHA384_ARGUMENT,
                    VALIDITY_ARGUMENT,
                    CERTIFICATE_VALIDITY_DAYS,
                    UNENCRYPTED_KEY_ARGUMENT,
                    SUBJECT_ARGUMENT,
                    ISSUER_SUBJECT,
                    ADD_EXTENSION_ARGUMENT,
                    AUTHORITY_BASIC_CONSTRAINTS,
                    ADD_EXTENSION_ARGUMENT,
                    AUTHORITY_KEY_USAGE,
                    KEY_OUTPUT_ARGUMENT,
                    keyFilename,
                    OUTPUT_ARGUMENT,
                    certificateFilename,
                ),
            )
        }

        private fun convert(
            input: String,
            output: String,
        ) {
            run(
                listOf(
                    CERTIFICATE_COMMAND,
                    INPUT_ARGUMENT,
                    input,
                    OUTPUT_FORMAT_ARGUMENT,
                    DER_OUTPUT_FORMAT,
                    OUTPUT_ARGUMENT,
                    output,
                ),
            )
        }

        private fun run(arguments: List<String>) {
            val process =
                ProcessBuilder(listOf(openssl.toString()) + arguments)
                    .directory(directory.toFile())
                    .redirectErrorStream(true)
                    .start()
            val completed = process.waitFor(TOOL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
            }
            val report = process.inputStream.bufferedReader().use { reader -> reader.readText() }
            assertTrue("OpenSSL timed out", completed)
            assertTrue(report, process.exitValue() == SUCCESSFUL_PROCESS_EXIT_CODE)
        }
    }

    private companion object {
        const val OPENSSL_EXECUTABLE_NAME = "openssl"
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-issuer-store-"
        const val X509_CERTIFICATE_TYPE = "X.509"
        const val ISSUER_KEY_FILENAME = "issuer-key.pem"
        const val ISSUER_PEM_FILENAME = "issuer.pem"
        const val ISSUER_DER_FILENAME = "issuer.der"
        const val WRONG_ISSUER_KEY_FILENAME = "wrong-issuer-key.pem"
        const val WRONG_ISSUER_PEM_FILENAME = "wrong-issuer.pem"
        const val WRONG_ISSUER_DER_FILENAME = "wrong-issuer.der"
        const val LEAF_KEY_FILENAME = "leaf-key.pem"
        const val LEAF_REQUEST_FILENAME = "leaf.csr"
        const val LEAF_PEM_FILENAME = "leaf.pem"
        const val LEAF_DER_FILENAME = "leaf.der"
        const val CERTIFICATE_REQUEST_COMMAND = "req"
        const val CERTIFICATE_COMMAND = "x509"
        const val SELF_SIGNED_ARGUMENT = "-x509"
        const val NEW_REQUEST_ARGUMENT = "-new"
        const val NEW_KEY_ARGUMENT = "-newkey"
        const val EC_KEY_ARGUMENT = "ec"
        const val KEY_OPTION_ARGUMENT = "-pkeyopt"
        const val P256_CURVE_ARGUMENT = "ec_paramgen_curve:P-256"
        const val SHA384_ARGUMENT = "-sha384"
        const val VALIDITY_ARGUMENT = "-days"
        const val CERTIFICATE_VALIDITY_DAYS = "2"
        const val UNENCRYPTED_KEY_ARGUMENT = "-nodes"
        const val SUBJECT_ARGUMENT = "-subj"
        const val KEY_OUTPUT_ARGUMENT = "-keyout"
        const val OUTPUT_ARGUMENT = "-out"
        const val INPUT_ARGUMENT = "-in"
        const val OUTPUT_FORMAT_ARGUMENT = "-outform"
        const val DER_OUTPUT_FORMAT = "der"
        const val ADD_EXTENSION_ARGUMENT = "-addext"
        const val CERTIFICATE_REQUEST_INPUT_ARGUMENT = "-req"
        const val CERTIFICATE_AUTHORITY_ARGUMENT = "-CA"
        const val CERTIFICATE_AUTHORITY_KEY_ARGUMENT = "-CAkey"
        const val CREATE_CERTIFICATE_AUTHORITY_SERIAL_ARGUMENT = "-CAcreateserial"
        const val ISSUER_SUBJECT = "/CN=RefineID synthetic authentication issuer"
        const val LEAF_SUBJECT = "/CN=RefineID synthetic authentication leaf"
        const val AUTHORITY_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:true"
        const val AUTHORITY_KEY_USAGE = "keyUsage=critical,keyCertSign"
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val CLEARED_BYTE: Byte = 0
        const val TRAILING_DATA_BYTE: Byte = 0x31
        val MALFORMED_CERTIFICATE = "not-a-certificate".encodeToByteArray()
        val TOOL_DIRECTORIES =
            listOf(
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/bin",
            )
    }
}
