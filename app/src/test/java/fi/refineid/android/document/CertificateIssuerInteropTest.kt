// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Comparator
import java.util.concurrent.TimeUnit

class CertificateIssuerInteropTest {
    @Test
    fun authenticatesOnlyTheExactDirectIssuerInsideCertificateValidity() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL is required for certificate issuer interop", openssl != null)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            createCertificates(checkNotNull(openssl), directory)
            val certificate = Files.readAllBytes(directory.resolve(LEAF_DER_FILENAME))
            val issuer = Files.readAllBytes(directory.resolve(ISSUER_DER_FILENAME))
            val unrelated = Files.readAllBytes(directory.resolve(UNRELATED_DER_FILENAME))
            val changedCertificate = certificate.copyOf()
            changedCertificate[changedCertificate.lastIndex] =
                (changedCertificate.last().toInt() xor CHANGED_SIGNATURE_BIT).toByte()
            try {
                val currentTime = Instant.now()
                assertTrue(CertificateIssuer.isDirectlyIssued(certificate, issuer, currentTime))
                assertFalse(CertificateIssuer.isDirectlyIssued(certificate, unrelated, currentTime))
                assertFalse(CertificateIssuer.isDirectlyIssued(changedCertificate, issuer, currentTime))
                assertFalse(
                    CertificateIssuer.isDirectlyIssued(
                        certificate,
                        issuer,
                        currentTime.plus(OUTSIDE_VALIDITY_DAY_COUNT, ChronoUnit.DAYS),
                    ),
                )
            } finally {
                certificate.fill(ZERO_BYTE)
                issuer.fill(ZERO_BYTE)
                unrelated.fill(ZERO_BYTE)
                changedCertificate.fill(ZERO_BYTE)
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun createCertificates(
        openssl: Path,
        directory: Path,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                REQUEST_COMMAND,
                X509_ARGUMENT,
                NEW_KEY_ARGUMENT,
                RSA_KEY_SPECIFICATION,
                NO_KEY_ENCRYPTION_ARGUMENT,
                KEY_OUTPUT_ARGUMENT,
                ISSUER_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                ISSUER_PEM_FILENAME,
                VALIDITY_DAYS_ARGUMENT,
                CERTIFICATE_VALIDITY_DAYS,
                SUBJECT_ARGUMENT,
                ISSUER_SUBJECT,
                SET_SERIAL_ARGUMENT,
                ISSUER_SERIAL_NUMBER,
                DIGEST_ARGUMENT,
                ADD_EXTENSION_ARGUMENT,
                ISSUER_BASIC_CONSTRAINTS,
                ADD_EXTENSION_ARGUMENT,
                ISSUER_KEY_USAGE,
            ),
        )
        runTool(
            openssl,
            directory,
            listOf(
                REQUEST_COMMAND,
                NEW_ARGUMENT,
                NEW_KEY_ARGUMENT,
                RSA_KEY_SPECIFICATION,
                NO_KEY_ENCRYPTION_ARGUMENT,
                KEY_OUTPUT_ARGUMENT,
                LEAF_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                LEAF_REQUEST_FILENAME,
                SUBJECT_ARGUMENT,
                LEAF_SUBJECT,
            ),
        )
        Files.writeString(directory.resolve(LEAF_EXTENSIONS_FILENAME), LEAF_EXTENSIONS)
        runTool(
            openssl,
            directory,
            listOf(
                X509_COMMAND,
                REQUEST_INPUT_ARGUMENT,
                INPUT_ARGUMENT,
                LEAF_REQUEST_FILENAME,
                CERTIFICATE_AUTHORITY_ARGUMENT,
                ISSUER_PEM_FILENAME,
                CERTIFICATE_AUTHORITY_KEY_ARGUMENT,
                ISSUER_KEY_FILENAME,
                SET_SERIAL_ARGUMENT,
                LEAF_SERIAL_NUMBER,
                OUTPUT_ARGUMENT,
                LEAF_PEM_FILENAME,
                VALIDITY_DAYS_ARGUMENT,
                CERTIFICATE_VALIDITY_DAYS,
                DIGEST_ARGUMENT,
                EXTENSIONS_FILE_ARGUMENT,
                LEAF_EXTENSIONS_FILENAME,
            ),
        )
        runTool(
            openssl,
            directory,
            listOf(
                REQUEST_COMMAND,
                X509_ARGUMENT,
                NEW_KEY_ARGUMENT,
                RSA_KEY_SPECIFICATION,
                NO_KEY_ENCRYPTION_ARGUMENT,
                KEY_OUTPUT_ARGUMENT,
                UNRELATED_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                UNRELATED_PEM_FILENAME,
                VALIDITY_DAYS_ARGUMENT,
                CERTIFICATE_VALIDITY_DAYS,
                SUBJECT_ARGUMENT,
                UNRELATED_SUBJECT,
                SET_SERIAL_ARGUMENT,
                UNRELATED_SERIAL_NUMBER,
                DIGEST_ARGUMENT,
                ADD_EXTENSION_ARGUMENT,
                ISSUER_BASIC_CONSTRAINTS,
                ADD_EXTENSION_ARGUMENT,
                ISSUER_KEY_USAGE,
            ),
        )
        convertCertificate(openssl, directory, ISSUER_PEM_FILENAME, ISSUER_DER_FILENAME)
        convertCertificate(openssl, directory, LEAF_PEM_FILENAME, LEAF_DER_FILENAME)
        convertCertificate(openssl, directory, UNRELATED_PEM_FILENAME, UNRELATED_DER_FILENAME)
    }

    private fun convertCertificate(
        openssl: Path,
        directory: Path,
        input: String,
        output: String,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                X509_COMMAND,
                INPUT_ARGUMENT,
                input,
                OUTPUT_FORMAT_ARGUMENT,
                DER_FORMAT,
                OUTPUT_ARGUMENT,
                output,
            ),
        )
    }

    private fun runTool(
        executable: Path,
        directory: Path,
        arguments: List<String>,
    ) {
        val process =
            ProcessBuilder(listOf(executable.toString()) + arguments)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start()
        val output = process.inputStream.bufferedReader().use { reader -> reader.readText() }
        assertTrue("OpenSSL timed out", process.waitFor(TOOL_TIMEOUT_SECONDS, TimeUnit.SECONDS))
        assertTrue("OpenSSL failed: $output", process.exitValue() == SUCCESS_EXIT_CODE)
    }

    private fun findExecutable(name: String): Path? =
        System
            .getenv(PATH_ENVIRONMENT_VARIABLE)
            ?.split(System.getProperty(PATH_SEPARATOR_PROPERTY))
            ?.asSequence()
            ?.map { directory -> Path.of(directory, name) }
            ?.firstOrNull(Files::isExecutable)

    private fun Path.deleteRecursively() {
        if (!Files.exists(this)) {
            return
        }
        Files.walk(this).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val OPENSSL_EXECUTABLE_NAME = "openssl"
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-certificate-issuer-"
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val PATH_SEPARATOR_PROPERTY = "path.separator"
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val SUCCESS_EXIT_CODE = 0
        const val OUTSIDE_VALIDITY_DAY_COUNT = 3L
        const val CHANGED_SIGNATURE_BIT = 1
        const val ZERO_BYTE: Byte = 0

        const val REQUEST_COMMAND = "req"
        const val X509_COMMAND = "x509"
        const val X509_ARGUMENT = "-x509"
        const val NEW_ARGUMENT = "-new"
        const val NEW_KEY_ARGUMENT = "-newkey"
        const val NO_KEY_ENCRYPTION_ARGUMENT = "-nodes"
        const val KEY_OUTPUT_ARGUMENT = "-keyout"
        const val OUTPUT_ARGUMENT = "-out"
        const val INPUT_ARGUMENT = "-in"
        const val REQUEST_INPUT_ARGUMENT = "-req"
        const val VALIDITY_DAYS_ARGUMENT = "-days"
        const val SUBJECT_ARGUMENT = "-subj"
        const val SET_SERIAL_ARGUMENT = "-set_serial"
        const val DIGEST_ARGUMENT = "-sha256"
        const val ADD_EXTENSION_ARGUMENT = "-addext"
        const val CERTIFICATE_AUTHORITY_ARGUMENT = "-CA"
        const val CERTIFICATE_AUTHORITY_KEY_ARGUMENT = "-CAkey"
        const val EXTENSIONS_FILE_ARGUMENT = "-extfile"
        const val OUTPUT_FORMAT_ARGUMENT = "-outform"
        const val DER_FORMAT = "DER"
        const val RSA_KEY_SPECIFICATION = "rsa:2048"
        const val CERTIFICATE_VALIDITY_DAYS = "2"
        const val ISSUER_SERIAL_NUMBER = "1"
        const val LEAF_SERIAL_NUMBER = "2"
        const val UNRELATED_SERIAL_NUMBER = "3"

        const val ISSUER_SUBJECT = "/CN=RefineID synthetic issuer"
        const val LEAF_SUBJECT = "/CN=RefineID synthetic leaf"
        const val UNRELATED_SUBJECT = "/CN=RefineID unrelated issuer"
        const val ISSUER_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:TRUE,pathlen:1"
        const val ISSUER_KEY_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
        const val LEAF_EXTENSIONS =
            "basicConstraints=critical,CA:FALSE\n" +
                "keyUsage=critical,digitalSignature\n" +
                "authorityInfoAccess=caIssuers;URI:https://issuer.example/certificate.der," +
                "OCSP;URI:http://status.example/ocsp\n" +
                "crlDistributionPoints=URI:https://issuer.example/current.crl\n"

        const val ISSUER_KEY_FILENAME = "issuer.key"
        const val ISSUER_PEM_FILENAME = "issuer.pem"
        const val ISSUER_DER_FILENAME = "issuer.der"
        const val LEAF_KEY_FILENAME = "leaf.key"
        const val LEAF_REQUEST_FILENAME = "leaf.csr"
        const val LEAF_EXTENSIONS_FILENAME = "leaf.ext"
        const val LEAF_PEM_FILENAME = "leaf.pem"
        const val LEAF_DER_FILENAME = "leaf.der"
        const val UNRELATED_KEY_FILENAME = "unrelated.key"
        const val UNRELATED_PEM_FILENAME = "unrelated.pem"
        const val UNRELATED_DER_FILENAME = "unrelated.der"
    }
}
