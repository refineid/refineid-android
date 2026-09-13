// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.document

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Comparator
import java.util.concurrent.TimeUnit

class CertificateRevocationListInteropTest {
    @Test
    fun authenticatesCurrentDerAndPemAndRejectsRevocationOrTampering() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL is required for CRL interop", openssl != null)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            createFixture(checkNotNull(openssl), directory)
            verifyFixture(directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun verifyFixture(directory: Path) {
        val certificate = Files.readAllBytes(directory.resolve(LEAF_DER_FILENAME))
        val issuer = Files.readAllBytes(directory.resolve(ISSUER_DER_FILENAME))
        val unauthorizedIssuer = Files.readAllBytes(directory.resolve(UNAUTHORIZED_ISSUER_DER_FILENAME))
        val unrelated = Files.readAllBytes(directory.resolve(UNRELATED_DER_FILENAME))
        val goodDer = Files.readAllBytes(directory.resolve(GOOD_CRL_DER_FILENAME))
        val goodPem = Files.readAllBytes(directory.resolve(GOOD_CRL_PEM_FILENAME))
        val revokedDer = Files.readAllBytes(directory.resolve(REVOKED_CRL_DER_FILENAME))
        val changedDer = goodDer.copyOf()
        changedDer[changedDer.lastIndex] =
            (changedDer.last().toInt() xor CHANGED_SIGNATURE_BIT).toByte()
        try {
            val currentTime = Instant.now()
            verifyGoodList(goodDer, goodPem, certificate, issuer, currentTime)
            assertFailure(RevocationListValidationFailure.REVOKED) {
                CertificateRevocationList.verify(revokedDer, certificate, issuer, currentTime).close()
            }
            assertFailure(RevocationListValidationFailure.SIGNATURE_INVALID) {
                CertificateRevocationList.verify(changedDer, certificate, issuer, currentTime).close()
            }
            assertFailure(RevocationListValidationFailure.ISSUER_MISMATCH) {
                CertificateRevocationList.verify(goodDer, certificate, unrelated, currentTime).close()
            }
            assertFailure(RevocationListValidationFailure.ISSUER_UNAUTHORIZED) {
                CertificateRevocationList.verify(goodDer, certificate, unauthorizedIssuer, currentTime).close()
            }
            assertFailure(RevocationListValidationFailure.LIST_FROM_FUTURE) {
                CertificateRevocationList
                    .verify(
                        goodDer,
                        certificate,
                        issuer,
                        currentTime.minus(OUTSIDE_LIST_VALIDITY_DAY_COUNT, ChronoUnit.DAYS),
                    ).close()
            }
            assertFailure(RevocationListValidationFailure.LIST_EXPIRED) {
                CertificateRevocationList
                    .verify(
                        goodDer,
                        certificate,
                        issuer,
                        currentTime.plus(OUTSIDE_LIST_VALIDITY_DAY_COUNT, ChronoUnit.DAYS),
                    ).close()
            }
        } finally {
            listOf(
                certificate,
                issuer,
                unauthorizedIssuer,
                unrelated,
                goodDer,
                goodPem,
                revokedDer,
                changedDer,
            ).forEach { bytes -> bytes.fill(ZERO_BYTE) }
        }
    }

    private fun verifyGoodList(
        goodDer: ByteArray,
        goodPem: ByteArray,
        certificate: ByteArray,
        issuer: ByteArray,
        currentTime: Instant,
    ) {
        val verifiedDer = CertificateRevocationList.verify(goodDer, certificate, issuer, currentTime)
        val verifiedPem = CertificateRevocationList.verify(goodPem, certificate, issuer, currentTime)
        var copiedEncoding = ByteArray(EMPTY_BYTE_COUNT)
        try {
            copiedEncoding = verifiedDer.copyEncoding()
            assertArrayEquals(goodDer, copiedEncoding)
            assertArrayEquals(goodDer, verifiedPem.copyEncoding())
            assertTrue(verifiedDer.thisUpdate <= currentTime)
            assertTrue(verifiedDer.nextUpdate > currentTime)
        } finally {
            verifiedDer.close()
            verifiedPem.close()
            copiedEncoding.fill(ZERO_BYTE)
        }
        assertThrows(IllegalStateException::class.java, verifiedDer::copyEncoding)
    }

    private fun assertFailure(
        expected: RevocationListValidationFailure,
        operation: () -> Unit,
    ) {
        val failure = assertThrows(RevocationListValidationException::class.java, operation)
        assertEquals(expected, failure.kind)
    }

    private fun createFixture(
        openssl: Path,
        directory: Path,
    ) {
        Files.createDirectories(directory.resolve(NEW_CERTIFICATES_DIRECTORY))
        Files.writeString(directory.resolve(CERTIFICATE_DATABASE_FILENAME), EMPTY_DATABASE)
        Files.writeString(directory.resolve(NEXT_CERTIFICATE_SERIAL_FILENAME), INITIAL_CERTIFICATE_SERIAL)
        Files.writeString(directory.resolve(NEXT_CRL_NUMBER_FILENAME), INITIAL_CRL_NUMBER)
        Files.writeString(directory.resolve(CA_CONFIGURATION_FILENAME), caConfiguration())
        createIssuer(openssl, directory)
        createUnauthorizedIssuer(openssl, directory)
        createLeaf(openssl, directory)
        generateRevocationList(openssl, directory, GOOD_CRL_PEM_FILENAME)
        convertRevocationList(openssl, directory, GOOD_CRL_PEM_FILENAME, GOOD_CRL_DER_FILENAME)
        runTool(
            openssl,
            directory,
            listOf(
                CA_COMMAND,
                CONFIGURATION_ARGUMENT,
                CA_CONFIGURATION_FILENAME,
                REVOKE_ARGUMENT,
                LEAF_PEM_FILENAME,
                BATCH_ARGUMENT,
            ),
        )
        generateRevocationList(openssl, directory, REVOKED_CRL_PEM_FILENAME)
        convertRevocationList(openssl, directory, REVOKED_CRL_PEM_FILENAME, REVOKED_CRL_DER_FILENAME)
        createUnrelatedIssuer(openssl, directory)
        convertCertificate(openssl, directory, ISSUER_PEM_FILENAME, ISSUER_DER_FILENAME)
        convertCertificate(
            openssl,
            directory,
            UNAUTHORIZED_ISSUER_PEM_FILENAME,
            UNAUTHORIZED_ISSUER_DER_FILENAME,
        )
        convertCertificate(openssl, directory, LEAF_PEM_FILENAME, LEAF_DER_FILENAME)
        convertCertificate(openssl, directory, UNRELATED_PEM_FILENAME, UNRELATED_DER_FILENAME)
    }

    private fun createIssuer(
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
    }

    private fun createLeaf(
        openssl: Path,
        directory: Path,
    ) {
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
        runTool(
            openssl,
            directory,
            listOf(
                CA_COMMAND,
                CONFIGURATION_ARGUMENT,
                CA_CONFIGURATION_FILENAME,
                INPUT_ARGUMENT,
                LEAF_REQUEST_FILENAME,
                OUTPUT_ARGUMENT,
                LEAF_PEM_FILENAME,
                BATCH_ARGUMENT,
                NOTEXT_ARGUMENT,
            ),
        )
    }

    private fun createUnauthorizedIssuer(
        openssl: Path,
        directory: Path,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                REQUEST_COMMAND,
                NEW_ARGUMENT,
                X509_ARGUMENT,
                KEY_INPUT_ARGUMENT,
                ISSUER_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                UNAUTHORIZED_ISSUER_PEM_FILENAME,
                VALIDITY_DAYS_ARGUMENT,
                CERTIFICATE_VALIDITY_DAYS,
                SUBJECT_ARGUMENT,
                ISSUER_SUBJECT,
                SET_SERIAL_ARGUMENT,
                UNAUTHORIZED_ISSUER_SERIAL_NUMBER,
                DIGEST_ARGUMENT,
                ADD_EXTENSION_ARGUMENT,
                ISSUER_BASIC_CONSTRAINTS,
                ADD_EXTENSION_ARGUMENT,
                UNAUTHORIZED_ISSUER_KEY_USAGE,
            ),
        )
    }

    private fun createUnrelatedIssuer(
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
    }

    private fun generateRevocationList(
        openssl: Path,
        directory: Path,
        output: String,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                CA_COMMAND,
                GENERATE_CRL_ARGUMENT,
                CONFIGURATION_ARGUMENT,
                CA_CONFIGURATION_FILENAME,
                OUTPUT_ARGUMENT,
                output,
            ),
        )
    }

    private fun convertRevocationList(
        openssl: Path,
        directory: Path,
        input: String,
        output: String,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                CRL_COMMAND,
                INPUT_ARGUMENT,
                input,
                OUTPUT_FORMAT_ARGUMENT,
                DER_FORMAT,
                OUTPUT_ARGUMENT,
                output,
            ),
        )
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

    private fun caConfiguration(): String =
        """
        [ ca ]
        default_ca = local_ca

        [ local_ca ]
        dir = .
        database = $CERTIFICATE_DATABASE_FILENAME
        new_certs_dir = $NEW_CERTIFICATES_DIRECTORY
        certificate = $ISSUER_PEM_FILENAME
        private_key = $ISSUER_KEY_FILENAME
        serial = $NEXT_CERTIFICATE_SERIAL_FILENAME
        crlnumber = $NEXT_CRL_NUMBER_FILENAME
        default_md = sha256
        default_days = $CERTIFICATE_VALIDITY_DAYS
        default_crl_days = $REVOCATION_LIST_VALIDITY_DAYS
        policy = policy_any
        x509_extensions = leaf_extensions
        unique_subject = no

        [ policy_any ]
        commonName = supplied

        [ leaf_extensions ]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        authorityInfoAccess = OCSP;URI:http://status.example/ocsp,caIssuers;URI:https://issuer.example/certificate.der
        crlDistributionPoints = URI:https://issuer.example/current.crl
        """.trimIndent()

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
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-crl-"
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val PATH_SEPARATOR_PROPERTY = "path.separator"
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val SUCCESS_EXIT_CODE = 0
        const val EMPTY_BYTE_COUNT = 0
        const val OUTSIDE_LIST_VALIDITY_DAY_COUNT = 3L
        const val CHANGED_SIGNATURE_BIT = 1
        const val ZERO_BYTE: Byte = 0

        const val REQUEST_COMMAND = "req"
        const val X509_COMMAND = "x509"
        const val CA_COMMAND = "ca"
        const val CRL_COMMAND = "crl"
        const val X509_ARGUMENT = "-x509"
        const val NEW_ARGUMENT = "-new"
        const val NEW_KEY_ARGUMENT = "-newkey"
        const val NO_KEY_ENCRYPTION_ARGUMENT = "-nodes"
        const val KEY_OUTPUT_ARGUMENT = "-keyout"
        const val KEY_INPUT_ARGUMENT = "-key"
        const val OUTPUT_ARGUMENT = "-out"
        const val INPUT_ARGUMENT = "-in"
        const val VALIDITY_DAYS_ARGUMENT = "-days"
        const val SUBJECT_ARGUMENT = "-subj"
        const val SET_SERIAL_ARGUMENT = "-set_serial"
        const val DIGEST_ARGUMENT = "-sha256"
        const val ADD_EXTENSION_ARGUMENT = "-addext"
        const val CONFIGURATION_ARGUMENT = "-config"
        const val BATCH_ARGUMENT = "-batch"
        const val NOTEXT_ARGUMENT = "-notext"
        const val GENERATE_CRL_ARGUMENT = "-gencrl"
        const val REVOKE_ARGUMENT = "-revoke"
        const val OUTPUT_FORMAT_ARGUMENT = "-outform"
        const val DER_FORMAT = "DER"
        const val RSA_KEY_SPECIFICATION = "rsa:2048"
        const val CERTIFICATE_VALIDITY_DAYS = "10"
        const val REVOCATION_LIST_VALIDITY_DAYS = "2"
        const val ISSUER_SERIAL_NUMBER = "1"
        const val UNRELATED_SERIAL_NUMBER = "3"
        const val UNAUTHORIZED_ISSUER_SERIAL_NUMBER = "4"
        const val INITIAL_CERTIFICATE_SERIAL = "1000\n"
        const val INITIAL_CRL_NUMBER = "1000\n"
        const val EMPTY_DATABASE = ""

        const val ISSUER_SUBJECT = "/CN=RefineID synthetic CRL issuer"
        const val LEAF_SUBJECT = "/CN=RefineID synthetic CRL leaf"
        const val UNRELATED_SUBJECT = "/CN=RefineID unrelated CRL issuer"
        const val ISSUER_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:TRUE,pathlen:1"
        const val ISSUER_KEY_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
        const val UNAUTHORIZED_ISSUER_KEY_USAGE = "keyUsage=critical,keyCertSign"

        const val CA_CONFIGURATION_FILENAME = "openssl.cnf"
        const val CERTIFICATE_DATABASE_FILENAME = "index.txt"
        const val NEXT_CERTIFICATE_SERIAL_FILENAME = "serial"
        const val NEXT_CRL_NUMBER_FILENAME = "crlnumber"
        const val NEW_CERTIFICATES_DIRECTORY = "newcerts"
        const val ISSUER_KEY_FILENAME = "issuer.key"
        const val ISSUER_PEM_FILENAME = "issuer.pem"
        const val ISSUER_DER_FILENAME = "issuer.der"
        const val UNAUTHORIZED_ISSUER_PEM_FILENAME = "unauthorized-issuer.pem"
        const val UNAUTHORIZED_ISSUER_DER_FILENAME = "unauthorized-issuer.der"
        const val LEAF_KEY_FILENAME = "leaf.key"
        const val LEAF_REQUEST_FILENAME = "leaf.csr"
        const val LEAF_PEM_FILENAME = "leaf.pem"
        const val LEAF_DER_FILENAME = "leaf.der"
        const val UNRELATED_KEY_FILENAME = "unrelated.key"
        const val UNRELATED_PEM_FILENAME = "unrelated.pem"
        const val UNRELATED_DER_FILENAME = "unrelated.der"
        const val GOOD_CRL_PEM_FILENAME = "good.crl.pem"
        const val GOOD_CRL_DER_FILENAME = "good.crl.der"
        const val REVOKED_CRL_PEM_FILENAME = "revoked.crl.pem"
        const val REVOKED_CRL_DER_FILENAME = "revoked.crl.der"
    }
}
