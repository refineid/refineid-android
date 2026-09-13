package fi.refineid.android.document

import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Instant
import java.util.Comparator
import java.util.concurrent.TimeUnit

/** RFC 3161 verification against a token independently produced by OpenSSL. */
class TimestampTokenVerifierInteropTest {
    @Test
    fun explicitAnchorAcceptsAuthenticTokenAndRejectsWrongTrustAndMutation() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL is required for the timestamp interop test", openssl != null)
        val executable = checkNotNull(openssl)
        val directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            val fixture = createFixture(executable, directory)
            verifyAuthenticToken(fixture, executable, directory)
            verifyConfiguredAuthorityTrust(fixture)
            verifyEssCertificateBinding(fixture)
            verifyTsaNameBinding(fixture)
            rejectWrongTrust(fixture)
            rejectChangedSignature(fixture)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun createFixture(
        openssl: Path,
        directory: Path,
    ): TimestampFixture {
        generateTimestampAuthority(openssl, directory)
        generateUnrelatedAnchor(openssl, directory)
        convertCertificate(
            openssl = openssl,
            directory = directory,
            input = TIMESTAMP_CERTIFICATE_PEM_FILENAME,
            output = TIMESTAMP_CERTIFICATE_DER_FILENAME,
        )
        convertCertificate(
            openssl = openssl,
            directory = directory,
            input = ROOT_CERTIFICATE_PEM_FILENAME,
            output = ROOT_CERTIFICATE_DER_FILENAME,
        )
        convertCertificate(
            openssl = openssl,
            directory = directory,
            input = UNRELATED_CERTIFICATE_PEM_FILENAME,
            output = UNRELATED_CERTIFICATE_DER_FILENAME,
        )
        Files.writeString(directory.resolve(TIMESTAMP_SERIAL_FILENAME), INITIAL_TIMESTAMP_SERIAL)
        Files.writeString(directory.resolve(TIMESTAMP_CONFIGURATION_FILENAME), configuration(directory))
        val request = Rfc3161Timestamp.request(SYNTHETIC_DIGEST, SYNTHETIC_NONCE)
        Files.write(directory.resolve(TIMESTAMP_REQUEST_FILENAME), request)
        runTool(
            executable = openssl,
            arguments =
                listOf(
                    TIMESTAMP_COMMAND,
                    TIMESTAMP_REPLY_ARGUMENT,
                    CONFIGURATION_ARGUMENT,
                    TIMESTAMP_CONFIGURATION_FILENAME,
                    CONFIGURATION_SECTION_ARGUMENT,
                    TIMESTAMP_CONFIGURATION_SECTION,
                    TIMESTAMP_QUERY_FILE_ARGUMENT,
                    TIMESTAMP_REQUEST_FILENAME,
                    OUTPUT_ARGUMENT,
                    TIMESTAMP_RESPONSE_FILENAME,
                ),
            directory = directory,
        )
        val response = Files.readAllBytes(directory.resolve(TIMESTAMP_RESPONSE_FILENAME))
        val signer = Files.readAllBytes(directory.resolve(TIMESTAMP_CERTIFICATE_DER_FILENAME))
        val root = Files.readAllBytes(directory.resolve(ROOT_CERTIFICATE_DER_FILENAME))
        val unrelated = Files.readAllBytes(directory.resolve(UNRELATED_CERTIFICATE_DER_FILENAME))
        return TimestampFixture(
            response = response,
            signerCertificate = signer,
            trustedCertificate = root,
            unrelatedCertificate = unrelated,
        )
    }

    private fun verifyAuthenticToken(
        fixture: TimestampFixture,
        openssl: Path,
        directory: Path,
    ) {
        val unverified =
            Rfc3161Timestamp.token(
                response = fixture.response,
                digest = SYNTHETIC_DIGEST,
                nonce = SYNTHETIC_NONCE,
            )
        val verified =
            try {
                TimestampTokenVerifier.verify(
                    token = unverified,
                    trustedCertificates = listOf(fixture.trustedCertificate),
                )
            } finally {
                unverified.close()
            }
        var ownedEncoding: ByteArray? = null
        try {
            verified.useEncoding { encoding -> ownedEncoding = encoding }
            assertArrayEquals(fixture.signerCertificate, verified.copySignerCertificate())
            assertEquals(TIMESTAMP_CHAIN_CERTIFICATE_COUNT, verified.embeddedCertificateCount)
            assertEquals(TIMESTAMP_CHAIN_CERTIFICATE_COUNT, verified.verifiedCertificateCount)
            assertArrayEquals(fixture.trustedCertificate, verified.copyTrustedCertificate())
            assertTrue(
                TimestampTokenVerifier.certificateProfileIsValid(
                    certificateDer = fixture.signerCertificate,
                    generatedAt = verified.generatedAt,
                ),
            )
            assertFalse(
                TimestampTokenVerifier.certificateProfileIsValid(
                    certificateDer = fixture.trustedCertificate,
                    generatedAt = verified.generatedAt,
                ),
            )
            assertFalse(
                TimestampTokenVerifier.certificateProfileIsValid(
                    certificateDer = fixture.signerCertificate,
                    generatedAt = OUTSIDE_CERTIFICATE_VALIDITY,
                ),
            )
            val independent =
                runTool(
                    executable = openssl,
                    arguments =
                        listOf(
                            TIMESTAMP_COMMAND,
                            TIMESTAMP_VERIFY_ARGUMENT,
                            TIMESTAMP_QUERY_FILE_ARGUMENT,
                            TIMESTAMP_REQUEST_FILENAME,
                            INPUT_ARGUMENT,
                            TIMESTAMP_RESPONSE_FILENAME,
                            CERTIFICATE_AUTHORITY_FILE_ARGUMENT,
                            ROOT_CERTIFICATE_PEM_FILENAME,
                        ),
                    directory = directory,
                )
            assertTrue(independent.contains(TIMESTAMP_VERIFICATION_SUCCESS))
        } finally {
            verified.close()
        }
        assertTrue(checkNotNull(ownedEncoding).all { byte -> byte == ZERO_BYTE })
        assertThrows(IllegalStateException::class.java, verified::copyEncoding)
    }

    private fun verifyConfiguredAuthorityTrust(fixture: TimestampFixture) {
        val unverified = requestBoundToken(fixture.response)
        val verified =
            try {
                TimestampTokenVerifier.verifyConfiguredAuthority(unverified)
            } finally {
                unverified.close()
            }
        try {
            assertArrayEquals(fixture.signerCertificate, verified.copySignerCertificate())
            assertArrayEquals(fixture.trustedCertificate, verified.copyTrustedCertificate())
            assertEquals(TIMESTAMP_CHAIN_CERTIFICATE_COUNT, verified.verifiedCertificateCount)
        } finally {
            verified.close()
        }
    }

    private fun verifyEssCertificateBinding(fixture: TimestampFixture) {
        val attributes = signingCertificateAttributes(fixture.signerCertificate)
        try {
            TimestampSigningCertificateVerifier.verify(
                signedAttributesSet = attributes,
                signerCertificateDer = fixture.signerCertificate,
            )
            assertFailure(TimestampTokenVerificationFailure.SIGNING_CERTIFICATE_MISMATCH) {
                TimestampSigningCertificateVerifier.verify(
                    signedAttributesSet = attributes,
                    signerCertificateDer = fixture.unrelatedCertificate,
                )
            }
            assertFailure(TimestampTokenVerificationFailure.SIGNING_CERTIFICATE_MISMATCH) {
                TimestampSigningCertificateVerifier.verify(
                    signedAttributesSet = DerEncoder.setOf(emptyList()),
                    signerCertificateDer = fixture.signerCertificate,
                )
            }
        } finally {
            attributes.fill(ZERO_BYTE)
        }
    }

    private fun verifyTsaNameBinding(fixture: TimestampFixture) {
        val unverified = requestBoundToken(fixture.response)
        try {
            unverified.useEncoding { encoding ->
                val layout = TimestampCmsLayoutParser.parse(encoding)
                try {
                    val binding = Rfc3161TstInfoParser.binding(layout.tstInfo)
                    try {
                        assertNotNull(binding.tsaName)
                        assertTrue(
                            TimestampCertificateProfile.tsaNameMatches(
                                name = binding.tsaName,
                                certificateDer = fixture.signerCertificate,
                                certificate = parseCertificate(fixture.signerCertificate),
                            ),
                        )
                        assertFalse(
                            TimestampCertificateProfile.tsaNameMatches(
                                name = binding.tsaName,
                                certificateDer = fixture.trustedCertificate,
                                certificate = parseCertificate(fixture.trustedCertificate),
                            ),
                        )
                    } finally {
                        binding.close()
                    }
                } finally {
                    layout.close()
                }
            }
        } finally {
            unverified.close()
        }
    }

    private fun rejectWrongTrust(fixture: TimestampFixture) {
        val unverified = requestBoundToken(fixture.response)
        try {
            assertFailure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER) {
                TimestampTokenVerifier
                    .verify(
                        token = unverified,
                        trustedCertificates = listOf(fixture.unrelatedCertificate),
                    ).close()
            }
            assertFailure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER) {
                TimestampTokenVerifier.verify(token = unverified, trustedCertificates = emptyList()).close()
            }
            assertFailure(TimestampTokenVerificationFailure.UNTRUSTED_SIGNER) {
                TimestampTokenVerifier
                    .verify(
                        token = unverified,
                        trustedCertificates = listOf(MALFORMED_CERTIFICATE_TEXT.encodeToByteArray()),
                    ).close()
            }
        } finally {
            unverified.close()
        }
    }

    private fun rejectChangedSignature(fixture: TimestampFixture) {
        val changedResponse = fixture.response.copyOf()
        changedResponse[changedResponse.lastIndex] =
            (changedResponse.last().toInt() xor CHANGED_SIGNATURE_MASK).toByte()
        val unverified = requestBoundToken(changedResponse)
        try {
            assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
                TimestampTokenVerifier
                    .verify(
                        token = unverified,
                        trustedCertificates = listOf(fixture.trustedCertificate),
                    ).close()
            }
            assertFailure(TimestampTokenVerificationFailure.INVALID_SIGNATURE) {
                TimestampTokenVerifier.verifyConfiguredAuthority(unverified).close()
            }
        } finally {
            unverified.close()
            changedResponse.fill(ZERO_BYTE)
        }
    }

    private fun requestBoundToken(response: ByteArray): UnverifiedTimestampToken =
        Rfc3161Timestamp.token(
            response = response,
            digest = SYNTHETIC_DIGEST,
            nonce = SYNTHETIC_NONCE,
        )

    private fun signingCertificateAttributes(certificateDer: ByteArray): ByteArray {
        val identity = QualifiedDocumentCmsValidation.issuerAndSerial(certificateDer)
        val certificateDigest = MessageDigest.getInstance(SHA384_JAVA_NAME).digest(certificateDer)
        try {
            val outer = DerReader(identity)
            val sequence = checkNotNull(outer.next())
            check(sequence.tag == DerValues.TAG_SEQUENCE && outer.isAtEnd)
            val fields = outer.children(sequence)
            val issuer = checkNotNull(fields.next())
            val serial = checkNotNull(fields.next())
            check(
                issuer.tag == DerValues.TAG_SEQUENCE &&
                    serial.tag == DerValues.TAG_INTEGER &&
                    fields.isAtEnd,
            )
            val issuerSerial =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.sequence(
                            listOf(
                                DerEncoder.tlv(
                                    tag = DerValues.TAG_CONTEXT_4_CONSTRUCTED,
                                    content = fields.raw(issuer),
                                ),
                            ),
                        ),
                        fields.raw(serial),
                    ),
                )
            val reference =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.sequence(
                            listOf(DerEncoder.objectIdentifier(QualifiedCmsOids.SHA384)),
                        ),
                        DerEncoder.octetString(certificateDigest),
                        issuerSerial,
                    ),
                )
            val value = DerEncoder.sequence(listOf(DerEncoder.sequence(listOf(reference))))
            val attribute =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNING_CERTIFICATE_V2),
                        DerEncoder.setOf(listOf(value)),
                    ),
                )
            return DerEncoder.setOf(listOf(attribute))
        } finally {
            identity.fill(ZERO_BYTE)
            certificateDigest.fill(ZERO_BYTE)
        }
    }

    private fun parseCertificate(encoded: ByteArray) =
        java.security.cert.CertificateFactory
            .getInstance(X509_CERTIFICATE_TYPE)
            .generateCertificate(encoded.inputStream()) as java.security.cert.X509Certificate

    private fun generateTimestampAuthority(
        openssl: Path,
        directory: Path,
    ) {
        runTool(
            executable = openssl,
            arguments =
                certificateRequestArguments(
                    subject = ROOT_CERTIFICATE_SUBJECT,
                    keyFilename = ROOT_PRIVATE_KEY_FILENAME,
                    certificateFilename = ROOT_CERTIFICATE_PEM_FILENAME,
                ) +
                    listOf(
                        ADD_EXTENSION_ARGUMENT,
                        AUTHORITY_BASIC_CONSTRAINTS,
                        ADD_EXTENSION_ARGUMENT,
                        AUTHORITY_KEY_USAGE,
                        ADD_EXTENSION_ARGUMENT,
                        SUBJECT_KEY_IDENTIFIER_EXTENSION,
                    ),
            directory = directory,
        )
        runTool(
            executable = openssl,
            arguments =
                listOf(
                    CERTIFICATE_REQUEST_COMMAND,
                    NEW_ARGUMENT,
                    NEW_KEY_ARGUMENT,
                    EC_KEY_ARGUMENT,
                    KEY_OPTION_ARGUMENT,
                    P256_CURVE_ARGUMENT,
                    UNENCRYPTED_KEY_ARGUMENT,
                    SUBJECT_ARGUMENT,
                    TIMESTAMP_CERTIFICATE_SUBJECT,
                    KEY_OUTPUT_ARGUMENT,
                    TIMESTAMP_PRIVATE_KEY_FILENAME,
                    OUTPUT_ARGUMENT,
                    TIMESTAMP_CERTIFICATE_REQUEST_FILENAME,
                ),
            directory = directory,
        )
        Files.writeString(
            directory.resolve(TIMESTAMP_CERTIFICATE_EXTENSIONS_FILENAME),
            TIMESTAMP_CERTIFICATE_EXTENSIONS,
        )
        runTool(
            executable = openssl,
            arguments =
                listOf(
                    CERTIFICATE_COMMAND,
                    CERTIFICATE_REQUEST_INPUT_ARGUMENT,
                    INPUT_ARGUMENT,
                    TIMESTAMP_CERTIFICATE_REQUEST_FILENAME,
                    CERTIFICATE_AUTHORITY_ARGUMENT,
                    ROOT_CERTIFICATE_PEM_FILENAME,
                    CERTIFICATE_AUTHORITY_KEY_ARGUMENT,
                    ROOT_PRIVATE_KEY_FILENAME,
                    CREATE_CERTIFICATE_AUTHORITY_SERIAL_ARGUMENT,
                    SHA384_ARGUMENT,
                    VALIDITY_ARGUMENT,
                    CERTIFICATE_VALIDITY_DAYS,
                    EXTENSION_FILE_ARGUMENT,
                    TIMESTAMP_CERTIFICATE_EXTENSIONS_FILENAME,
                    OUTPUT_ARGUMENT,
                    TIMESTAMP_CERTIFICATE_PEM_FILENAME,
                ),
            directory = directory,
        )
    }

    private fun generateUnrelatedAnchor(
        openssl: Path,
        directory: Path,
    ) {
        runTool(
            executable = openssl,
            arguments =
                certificateRequestArguments(
                    subject = UNRELATED_CERTIFICATE_SUBJECT,
                    keyFilename = UNRELATED_PRIVATE_KEY_FILENAME,
                    certificateFilename = UNRELATED_CERTIFICATE_PEM_FILENAME,
                ) +
                    listOf(
                        ADD_EXTENSION_ARGUMENT,
                        AUTHORITY_BASIC_CONSTRAINTS,
                        ADD_EXTENSION_ARGUMENT,
                        AUTHORITY_KEY_USAGE,
                    ),
            directory = directory,
        )
    }

    private fun certificateRequestArguments(
        subject: String,
        keyFilename: String,
        certificateFilename: String,
    ): List<String> =
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
            subject,
            KEY_OUTPUT_ARGUMENT,
            keyFilename,
            OUTPUT_ARGUMENT,
            certificateFilename,
        )

    private fun convertCertificate(
        openssl: Path,
        directory: Path,
        input: String,
        output: String,
    ) {
        runTool(
            executable = openssl,
            arguments =
                listOf(
                    CERTIFICATE_COMMAND,
                    INPUT_ARGUMENT,
                    input,
                    OUTPUT_FORMAT_ARGUMENT,
                    DER_OUTPUT_FORMAT,
                    OUTPUT_ARGUMENT,
                    output,
                ),
            directory = directory,
        )
    }

    private fun configuration(directory: Path): String =
        """
        [ tsa ]
        default_tsa = $TIMESTAMP_CONFIGURATION_SECTION

        [ $TIMESTAMP_CONFIGURATION_SECTION ]
        serial = ${directory.resolve(TIMESTAMP_SERIAL_FILENAME)}
        crypto_device = builtin
        signer_cert = ${directory.resolve(TIMESTAMP_CERTIFICATE_PEM_FILENAME)}
        signer_key = ${directory.resolve(TIMESTAMP_PRIVATE_KEY_FILENAME)}
        certs = ${directory.resolve(ROOT_CERTIFICATE_PEM_FILENAME)}
        signer_digest = sha384
        default_policy = $TIMESTAMP_POLICY_OID
        digests = $TIMESTAMP_ACCEPTED_DIGESTS
        accuracy = secs:$TIMESTAMP_ACCURACY_SECONDS
        ordering = no
        tsa_name = yes
        ess_cert_id_chain = no
        ess_cert_id_alg = sha256
        """.trimIndent()

    private fun assertFailure(
        expected: TimestampTokenVerificationFailure,
        operation: () -> Unit,
    ) {
        val failure =
            assertThrows(TimestampTokenVerificationException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
    }

    private fun runTool(
        executable: Path,
        arguments: List<String>,
        directory: Path,
    ): String {
        val process =
            ProcessBuilder(listOf(executable.toString()) + arguments)
                .directory(directory.toFile())
                .redirectErrorStream(true)
                .start()
        val completed = process.waitFor(TOOL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!completed) {
            process.destroyForcibly()
        }
        assertTrue(executable.fileName.toString() + " timed out", completed)
        val report = process.inputStream.bufferedReader().use { reader -> reader.readText() }
        assertEquals(report, SUCCESSFUL_PROCESS_EXIT_CODE, process.exitValue())
        return report
    }

    private fun findExecutable(name: String): Path? =
        TOOL_DIRECTORIES
            .asSequence()
            .map { directory -> Path.of(directory, name) }
            .firstOrNull(Files::isExecutable)

    private fun Path.deleteRecursively() {
        if (!Files.exists(this)) {
            return
        }
        Files.walk(this).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private data class TimestampFixture(
        val response: ByteArray,
        val signerCertificate: ByteArray,
        val trustedCertificate: ByteArray,
        val unrelatedCertificate: ByteArray,
    )

    private companion object {
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-rfc3161-interop-"
        const val TIMESTAMP_PRIVATE_KEY_FILENAME = "timestamp-private-key.pem"
        const val TIMESTAMP_CERTIFICATE_REQUEST_FILENAME = "timestamp-certificate.csr"
        const val TIMESTAMP_CERTIFICATE_EXTENSIONS_FILENAME = "timestamp-certificate-extensions.cnf"
        const val TIMESTAMP_CERTIFICATE_PEM_FILENAME = "timestamp-certificate.pem"
        const val TIMESTAMP_CERTIFICATE_DER_FILENAME = "timestamp-certificate.der"
        const val ROOT_PRIVATE_KEY_FILENAME = "root-private-key.pem"
        const val ROOT_CERTIFICATE_PEM_FILENAME = "root-certificate.pem"
        const val ROOT_CERTIFICATE_DER_FILENAME = "root-certificate.der"
        const val UNRELATED_PRIVATE_KEY_FILENAME = "unrelated-private-key.pem"
        const val UNRELATED_CERTIFICATE_PEM_FILENAME = "unrelated-certificate.pem"
        const val UNRELATED_CERTIFICATE_DER_FILENAME = "unrelated-certificate.der"
        const val TIMESTAMP_SERIAL_FILENAME = "timestamp-serial"
        const val TIMESTAMP_CONFIGURATION_FILENAME = "timestamp.cnf"
        const val TIMESTAMP_REQUEST_FILENAME = "timestamp-request.der"
        const val TIMESTAMP_RESPONSE_FILENAME = "timestamp-response.der"

        const val OPENSSL_EXECUTABLE_NAME = "openssl"
        const val CERTIFICATE_REQUEST_COMMAND = "req"
        const val CERTIFICATE_COMMAND = "x509"
        const val TIMESTAMP_COMMAND = "ts"
        const val SELF_SIGNED_ARGUMENT = "-x509"
        const val NEW_ARGUMENT = "-new"
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
        const val EXTENSION_FILE_ARGUMENT = "-extfile"
        const val CERTIFICATE_REQUEST_INPUT_ARGUMENT = "-req"
        const val CERTIFICATE_AUTHORITY_ARGUMENT = "-CA"
        const val CERTIFICATE_AUTHORITY_KEY_ARGUMENT = "-CAkey"
        const val CREATE_CERTIFICATE_AUTHORITY_SERIAL_ARGUMENT = "-CAcreateserial"
        const val CONFIGURATION_ARGUMENT = "-config"
        const val CONFIGURATION_SECTION_ARGUMENT = "-section"
        const val TIMESTAMP_QUERY_FILE_ARGUMENT = "-queryfile"
        const val TIMESTAMP_REPLY_ARGUMENT = "-reply"
        const val TIMESTAMP_VERIFY_ARGUMENT = "-verify"
        const val CERTIFICATE_AUTHORITY_FILE_ARGUMENT = "-CAfile"

        const val TIMESTAMP_CERTIFICATE_SUBJECT = "/CN=RefineID synthetic timestamp authority"
        const val ROOT_CERTIFICATE_SUBJECT = "/CN=RefineID synthetic timestamp root"
        const val UNRELATED_CERTIFICATE_SUBJECT = "/CN=RefineID unrelated synthetic authority"
        const val SUBJECT_KEY_IDENTIFIER_EXTENSION = "subjectKeyIdentifier=hash"
        const val TIMESTAMP_CERTIFICATE_EXTENSIONS =
            "basicConstraints=critical,CA:false\n" +
                "keyUsage=critical,digitalSignature\n" +
                "extendedKeyUsage=critical,timeStamping\n" +
                "subjectKeyIdentifier=hash\n" +
                "authorityKeyIdentifier=keyid,issuer\n"
        const val AUTHORITY_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:true"
        const val AUTHORITY_KEY_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
        const val TIMESTAMP_CONFIGURATION_SECTION = "timestamp_authority"
        const val TIMESTAMP_POLICY_OID = "1.2.3.4.1"
        const val TIMESTAMP_ACCEPTED_DIGESTS = "sha256, sha384, sha512"
        const val TIMESTAMP_ACCURACY_SECONDS = "1"
        const val INITIAL_TIMESTAMP_SERIAL = "01\n"
        const val TIMESTAMP_VERIFICATION_SUCCESS = "Verification: OK"
        const val SHA384_JAVA_NAME = "SHA-384"
        const val X509_CERTIFICATE_TYPE = "X.509"
        const val MALFORMED_CERTIFICATE_TEXT = "not-a-certificate"

        const val TIMESTAMP_CHAIN_CERTIFICATE_COUNT = 2
        const val CHANGED_SIGNATURE_MASK = 1
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val SYNTHETIC_DIGEST_FILL: Byte = 0x5A
        const val ZERO_BYTE: Byte = 0
        val SYNTHETIC_DIGEST = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { SYNTHETIC_DIGEST_FILL }
        val SYNTHETIC_NONCE = SYNTHETIC_NONCE_TEXT.encodeToByteArray()
        const val SYNTHETIC_NONCE_TEXT = "test-nonce"
        val OUTSIDE_CERTIFICATE_VALIDITY: Instant = Instant.EPOCH
        val TOOL_DIRECTORIES =
            listOf(
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/bin",
            )
    }
}
