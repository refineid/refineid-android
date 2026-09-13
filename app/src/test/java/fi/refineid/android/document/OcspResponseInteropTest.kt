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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Comparator
import java.util.concurrent.TimeUnit

class OcspResponseInteropTest {
    @Test
    fun authenticatesOpenSslResponseBeforeAcceptingAnyCertificateStatus() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL is required for OCSP response interop", openssl != null)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            createFixture(checkNotNull(openssl), directory)
            verifyFixture(directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun verifyFixture(directory: Path) {
        val delegatedCertificate =
            Files.newInputStream(directory.resolve(DELEGATED_RESPONDER.certificate)).use { input ->
                CertificateFactory.getInstance(X509_CERTIFICATE_TYPE).generateCertificate(input) as X509Certificate
            }
        val exactNoCheckValue =
            checkNotNull(
                CertificateExtensionReader.value(
                    delegatedCertificate.encoded,
                    OCSP_NO_CHECK_IDENTIFIER,
                ),
            )
        assertArrayEquals(DerEncoder.nullValue(), exactNoCheckValue)
        exactNoCheckValue.fill(ZERO_BYTE)
        val certificate = Files.readAllBytes(directory.resolve(LEAF_DER_FILENAME))
        val issuer = Files.readAllBytes(directory.resolve(ISSUER_DER_FILENAME))
        val good = Files.readAllBytes(directory.resolve(GOOD_RESPONSE_FILENAME))
        val revoked = Files.readAllBytes(directory.resolve(REVOKED_RESPONSE_FILENAME))
        val delegated = Files.readAllBytes(directory.resolve(DELEGATED_RESPONSE_FILENAME))
        val unchecked = Files.readAllBytes(directory.resolve(UNCHECKED_RESPONSE_FILENAME))
        val unauthorized = Files.readAllBytes(directory.resolve(UNAUTHORIZED_RESPONSE_FILENAME))
        val nonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { NONCE_FILL_BYTE }
        val wrongNonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { WRONG_NONCE_FILL_BYTE }
        val changed = good.copyOf()
        changed[changed.lastIndex] = (changed.last().toInt() xor CHANGED_SIGNATURE_BIT).toByte()
        val trailing = good + byteArrayOf(TRAILING_BYTE)
        val rejected =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.tlv(
                        tag = DerValues.TAG_ENUMERATED,
                        content = byteArrayOf(REJECTED_RESPONSE_STATUS),
                    ),
                ),
            )
        try {
            val currentTime = Instant.now()
            verifyGood(good, certificate, issuer, nonce, currentTime)
            assertFailure(OcspResponseValidationFailure.NONCE_MISMATCH) {
                OcspResponse.verify(good, certificate, issuer, wrongNonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.SIGNATURE_INVALID) {
                OcspResponse.verify(changed, certificate, issuer, nonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.REVOKED) {
                OcspResponse.verify(revoked, certificate, issuer, nonce, currentTime).close()
            }
            OcspResponse.verify(delegated, certificate, issuer, nonce, currentTime).close()
            assertFailure(OcspResponseValidationFailure.RESPONDER_REVOCATION_UNCHECKED) {
                OcspResponse.verify(unchecked, certificate, issuer, nonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.RESPONDER_UNAUTHORIZED) {
                OcspResponse.verify(unauthorized, certificate, issuer, nonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.CERTIFICATE_MISMATCH) {
                OcspResponse.verify(good, issuer, issuer, nonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.MALFORMED) {
                OcspResponse.verify(trailing, certificate, issuer, nonce, currentTime).close()
            }
            assertFailure(OcspResponseValidationFailure.RESPONSE_FROM_FUTURE) {
                OcspResponse
                    .verify(
                        good,
                        certificate,
                        issuer,
                        nonce,
                        currentTime.minus(OUTSIDE_VALIDITY_DAY_COUNT, ChronoUnit.DAYS),
                    ).close()
            }
            assertFailure(OcspResponseValidationFailure.RESPONSE_EXPIRED) {
                OcspResponse
                    .verify(
                        good,
                        certificate,
                        issuer,
                        nonce,
                        currentTime.plus(OUTSIDE_VALIDITY_DAY_COUNT, ChronoUnit.DAYS),
                    ).close()
            }
            val rejectedFailure =
                assertFailure(OcspResponseValidationFailure.REJECTED) {
                    OcspResponse.verify(rejected, certificate, issuer, nonce, currentTime).close()
                }
            assertEquals(REJECTED_RESPONSE_STATUS.toInt(), rejectedFailure.responderStatus)
        } finally {
            listOf(
                certificate,
                issuer,
                good,
                revoked,
                delegated,
                unchecked,
                unauthorized,
                nonce,
                wrongNonce,
                changed,
                trailing,
                rejected,
            ).forEach { bytes -> bytes.fill(ZERO_BYTE) }
        }
    }

    private fun verifyGood(
        response: ByteArray,
        certificate: ByteArray,
        issuer: ByteArray,
        nonce: ByteArray,
        currentTime: Instant,
    ) {
        val verified = OcspResponse.verify(response, certificate, issuer, nonce, currentTime)
        var copied = ByteArray(EMPTY_BYTE_COUNT)
        try {
            copied = verified.copyEncoding()
            assertArrayEquals(response, copied)
            assertTrue(verified.producedAt <= currentTime)
            assertTrue(verified.thisUpdate <= currentTime)
            assertTrue(checkNotNull(verified.nextUpdate) > currentTime)
        } finally {
            verified.close()
            copied.fill(ZERO_BYTE)
        }
        assertThrows(IllegalStateException::class.java, verified::copyEncoding)
    }

    private fun assertFailure(
        expected: OcspResponseValidationFailure,
        operation: () -> Unit,
    ): OcspResponseValidationException {
        val failure = assertThrows(OcspResponseValidationException::class.java, operation)
        assertEquals(expected, failure.kind)
        return failure
    }

    private fun createFixture(
        openssl: Path,
        directory: Path,
    ) {
        initializeCertificateAuthority(directory)
        createIssuer(openssl, directory)
        createLeaf(openssl, directory)
        createResponder(openssl, directory, DELEGATED_RESPONDER)
        createResponder(openssl, directory, UNCHECKED_RESPONDER)
        createResponder(openssl, directory, UNAUTHORIZED_RESPONDER)
        convertCertificate(openssl, directory, ISSUER_PEM_FILENAME, ISSUER_DER_FILENAME)
        convertCertificate(openssl, directory, LEAF_PEM_FILENAME, LEAF_DER_FILENAME)
        val request = createRequest(directory)
        try {
            Files.write(directory.resolve(REQUEST_FILENAME), request)
        } finally {
            request.fill(ZERO_BYTE)
        }
        generateResponse(openssl, directory, GOOD_RESPONSE_FILENAME)
        generateDelegatedResponse(
            openssl,
            directory,
            DELEGATED_RESPONDER,
            DELEGATED_RESPONSE_FILENAME,
        )
        generateDelegatedResponse(
            openssl,
            directory,
            UNCHECKED_RESPONDER,
            UNCHECKED_RESPONSE_FILENAME,
        )
        generateDelegatedResponse(
            openssl,
            directory,
            UNAUTHORIZED_RESPONDER,
            UNAUTHORIZED_RESPONSE_FILENAME,
        )
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
        generateResponse(openssl, directory, REVOKED_RESPONSE_FILENAME)
    }

    private fun initializeCertificateAuthority(directory: Path) {
        Files.createDirectories(directory.resolve(NEW_CERTIFICATES_DIRECTORY))
        Files.writeString(directory.resolve(CERTIFICATE_DATABASE_FILENAME), EMPTY_DATABASE)
        Files.writeString(directory.resolve(NEXT_CERTIFICATE_SERIAL_FILENAME), INITIAL_CERTIFICATE_SERIAL)
        Files.writeString(directory.resolve(CA_CONFIGURATION_FILENAME), caConfiguration())
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

    private fun createRequest(directory: Path): ByteArray {
        val certificate = Files.readAllBytes(directory.resolve(LEAF_DER_FILENAME))
        val issuer = Files.readAllBytes(directory.resolve(ISSUER_DER_FILENAME))
        val targetFacts = checkNotNull(CertificateFacts.parse(certificate))
        val issuerFacts = checkNotNull(CertificateFacts.parse(issuer))
        val nonce = ByteArray(OcspRequest.NONCE_BYTE_COUNT) { NONCE_FILL_BYTE }
        return try {
            targetFacts.useOcspIdentity { issuerName, serialNumber ->
                issuerFacts.usePublicKeyBits { publicKeyBits ->
                    OcspRequest.encoded(issuerName, publicKeyBits, serialNumber, nonce)
                }
            }
        } finally {
            certificate.fill(ZERO_BYTE)
            issuer.fill(ZERO_BYTE)
            nonce.fill(ZERO_BYTE)
            targetFacts.close()
            issuerFacts.close()
        }
    }

    private fun createResponder(
        openssl: Path,
        directory: Path,
        responder: ResponderFixture,
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
                responder.key,
                OUTPUT_ARGUMENT,
                responder.request,
                SUBJECT_ARGUMENT,
                responder.subject,
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
                responder.request,
                OUTPUT_ARGUMENT,
                responder.certificate,
                EXTENSIONS_ARGUMENT,
                responder.extensionSection,
                BATCH_ARGUMENT,
                NOTEXT_ARGUMENT,
            ),
        )
    }

    private fun generateResponse(
        openssl: Path,
        directory: Path,
        output: String,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                OCSP_COMMAND,
                INDEX_ARGUMENT,
                CERTIFICATE_DATABASE_FILENAME,
                RESPONDER_CERTIFICATE_ARGUMENT,
                ISSUER_PEM_FILENAME,
                RESPONDER_KEY_ARGUMENT,
                ISSUER_KEY_FILENAME,
                CERTIFICATE_AUTHORITY_ARGUMENT,
                ISSUER_PEM_FILENAME,
                REQUEST_INPUT_ARGUMENT,
                REQUEST_FILENAME,
                RESPONSE_OUTPUT_ARGUMENT,
                output,
                NEXT_UPDATE_DAYS_ARGUMENT,
                RESPONSE_VALIDITY_DAYS,
                OMIT_RESPONSE_CERTIFICATES_ARGUMENT,
            ),
        )
    }

    private fun generateDelegatedResponse(
        openssl: Path,
        directory: Path,
        responder: ResponderFixture,
        output: String,
    ) {
        runTool(
            openssl,
            directory,
            listOf(
                OCSP_COMMAND,
                INDEX_ARGUMENT,
                CERTIFICATE_DATABASE_FILENAME,
                RESPONDER_CERTIFICATE_ARGUMENT,
                responder.certificate,
                RESPONDER_KEY_ARGUMENT,
                responder.key,
                CERTIFICATE_AUTHORITY_ARGUMENT,
                ISSUER_PEM_FILENAME,
                REQUEST_INPUT_ARGUMENT,
                REQUEST_FILENAME,
                RESPONSE_OUTPUT_ARGUMENT,
                output,
                NEXT_UPDATE_DAYS_ARGUMENT,
                RESPONSE_VALIDITY_DAYS,
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
        default_md = sha256
        default_days = $CERTIFICATE_VALIDITY_DAYS
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

        [ delegated_responder_extensions ]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        extendedKeyUsage = critical,OCSPSigning
        $OCSP_NO_CHECK_CONFIGURATION

        [ unchecked_responder_extensions ]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
        extendedKeyUsage = critical,OCSPSigning

        [ unauthorized_responder_extensions ]
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature
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
        const val X509_CERTIFICATE_TYPE = "X.509"
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-ocsp-"
        const val PATH_ENVIRONMENT_VARIABLE = "PATH"
        const val PATH_SEPARATOR_PROPERTY = "path.separator"
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val SUCCESS_EXIT_CODE = 0
        const val EMPTY_BYTE_COUNT = 0
        const val OUTSIDE_VALIDITY_DAY_COUNT = 3L
        const val CHANGED_SIGNATURE_BIT = 1
        const val NONCE_FILL_BYTE: Byte = 0x5A
        const val WRONG_NONCE_FILL_BYTE: Byte = 0x3C
        const val TRAILING_BYTE: Byte = 0
        const val REJECTED_RESPONSE_STATUS: Byte = 1
        const val ZERO_BYTE: Byte = 0

        const val REQUEST_COMMAND = "req"
        const val X509_COMMAND = "x509"
        const val CA_COMMAND = "ca"
        const val OCSP_COMMAND = "ocsp"
        const val X509_ARGUMENT = "-x509"
        const val NEW_ARGUMENT = "-new"
        const val NEW_KEY_ARGUMENT = "-newkey"
        const val NO_KEY_ENCRYPTION_ARGUMENT = "-nodes"
        const val KEY_OUTPUT_ARGUMENT = "-keyout"
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
        const val EXTENSIONS_ARGUMENT = "-extensions"
        const val REVOKE_ARGUMENT = "-revoke"
        const val OUTPUT_FORMAT_ARGUMENT = "-outform"
        const val INDEX_ARGUMENT = "-index"
        const val RESPONDER_CERTIFICATE_ARGUMENT = "-rsigner"
        const val RESPONDER_KEY_ARGUMENT = "-rkey"
        const val CERTIFICATE_AUTHORITY_ARGUMENT = "-CA"
        const val REQUEST_INPUT_ARGUMENT = "-reqin"
        const val RESPONSE_OUTPUT_ARGUMENT = "-respout"
        const val NEXT_UPDATE_DAYS_ARGUMENT = "-ndays"
        const val OMIT_RESPONSE_CERTIFICATES_ARGUMENT = "-resp_no_certs"
        const val DER_FORMAT = "DER"
        const val RSA_KEY_SPECIFICATION = "rsa:2048"
        const val CERTIFICATE_VALIDITY_DAYS = "10"
        const val RESPONSE_VALIDITY_DAYS = "2"
        const val ISSUER_SERIAL_NUMBER = "1"
        const val INITIAL_CERTIFICATE_SERIAL = "1000\n"
        const val EMPTY_DATABASE = ""

        const val ISSUER_SUBJECT = "/CN=RefineID synthetic OCSP issuer"
        const val LEAF_SUBJECT = "/CN=RefineID synthetic OCSP leaf"
        const val ISSUER_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:TRUE,pathlen:1"
        const val ISSUER_KEY_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
        const val OCSP_NO_CHECK_IDENTIFIER = "1.3.6.1.5.5.7.48.1.5"
        const val OCSP_NO_CHECK_CONFIGURATION = "noCheck = ignored"

        const val CA_CONFIGURATION_FILENAME = "openssl.cnf"
        const val CERTIFICATE_DATABASE_FILENAME = "index.txt"
        const val NEXT_CERTIFICATE_SERIAL_FILENAME = "serial"
        const val NEW_CERTIFICATES_DIRECTORY = "newcerts"
        const val ISSUER_KEY_FILENAME = "issuer.key"
        const val ISSUER_PEM_FILENAME = "issuer.pem"
        const val ISSUER_DER_FILENAME = "issuer.der"
        const val LEAF_KEY_FILENAME = "leaf.key"
        const val LEAF_REQUEST_FILENAME = "leaf.csr"
        const val LEAF_PEM_FILENAME = "leaf.pem"
        const val LEAF_DER_FILENAME = "leaf.der"
        const val REQUEST_FILENAME = "request.ocsp.der"
        const val GOOD_RESPONSE_FILENAME = "good.ocsp.der"
        const val REVOKED_RESPONSE_FILENAME = "revoked.ocsp.der"
        const val DELEGATED_RESPONSE_FILENAME = "delegated.ocsp.der"
        const val UNCHECKED_RESPONSE_FILENAME = "unchecked.ocsp.der"
        const val UNAUTHORIZED_RESPONSE_FILENAME = "unauthorized.ocsp.der"

        val DELEGATED_RESPONDER =
            ResponderFixture(
                key = "delegated.key",
                request = "delegated.csr",
                certificate = "delegated.pem",
                subject = "/CN=RefineID synthetic delegated OCSP responder",
                extensionSection = "delegated_responder_extensions",
            )
        val UNCHECKED_RESPONDER =
            ResponderFixture(
                key = "unchecked.key",
                request = "unchecked.csr",
                certificate = "unchecked.pem",
                subject = "/CN=RefineID synthetic unchecked OCSP responder",
                extensionSection = "unchecked_responder_extensions",
            )
        val UNAUTHORIZED_RESPONDER =
            ResponderFixture(
                key = "unauthorized.key",
                request = "unauthorized.csr",
                certificate = "unauthorized.pem",
                subject = "/CN=RefineID synthetic unauthorized OCSP responder",
                extensionSection = "unauthorized_responder_extensions",
            )
    }

    private data class ResponderFixture(
        val key: String,
        val request: String,
        val certificate: String,
        val subject: String,
        val extensionSection: String,
    )
}
