package fi.refineid.android.document

import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.SHA384_DIGEST_LENGTH_BYTES
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import java.util.HexFormat
import java.util.concurrent.TimeUnit

/** PAdES-B-T and B-LTA validation against independently generated cryptographic material. */
class PadesBaselineTInteropTest {
    @Test
    fun verifiedTimestampBuildsAnIndependentlyAcceptedSignature() {
        val environment = PadesInteropEnvironment.discover()
        assumeTrue(
            "OpenSSL, qpdf, and pdfsig are required for the PAdES-B-T test",
            environment != null,
        )
        checkNotNull(environment).use { tools ->
            PadesSigningFixture.create(tools).use { signing ->
                VerifiedTimestampAuthority.create(tools).use { authority ->
                    verifyTimestampedAssembly(
                        environment = tools,
                        signing = signing,
                        authority = authority,
                    )
                }
            }
        }
    }

    @Test
    fun verifiedDocumentTimestampCoversAppendedDss() {
        val environment = PadesInteropEnvironment.discover()
        assumeTrue(
            "OpenSSL, qpdf, and pdfsig are required for the document-timestamp test",
            environment != null,
        )
        checkNotNull(environment).use { tools ->
            PadesSigningFixture.create(tools).use { signing ->
                VerifiedTimestampAuthority.create(tools).use { authority ->
                    validateDocumentTimestamp(
                        environment = tools,
                        signing = signing,
                        authority = authority,
                    )
                }
            }
        }
    }

    private fun validateDocumentTimestamp(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        authority: VerifiedTimestampAuthority,
    ) {
        val signatureTimestampDigest = signing.timestampDigest()
        try {
            val signatureTimestamp = authority.issue(signatureTimestampDigest)
            try {
                val timestampedPdf = timestampedDocument(environment, signing, signatureTimestamp)
                try {
                    validateArchiveTimestamp(
                        environment = environment,
                        signing = signing,
                        authority = authority,
                        signatureTimestamp = signatureTimestamp,
                        timestampedPdf = timestampedPdf,
                    )
                } finally {
                    timestampedPdf.fill(ZERO_BYTE)
                }
            } finally {
                signatureTimestamp.close()
            }
        } finally {
            signatureTimestampDigest.fill(ZERO_BYTE)
        }
    }

    private fun timestampedDocument(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        signatureTimestamp: VerifiedTimestampToken,
    ): ByteArray {
        val cms = signing.assemble(listOf(signatureTimestamp))
        return try {
            environment.validateCms(cms)
            signing.fill(cms)
        } finally {
            cms.fill(ZERO_BYTE)
        }
    }

    private fun validateArchiveTimestamp(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        authority: VerifiedTimestampAuthority,
        signatureTimestamp: VerifiedTimestampToken,
        timestampedPdf: ByteArray,
    ) {
        val material = validationMaterial(environment, signing, signatureTimestamp)
        try {
            val prepared = PdfArchiveTimestamp.prepare(timestampedPdf, material)
            try {
                completeArchiveTimestamp(environment, authority, prepared)
            } finally {
                prepared.close()
            }
        } finally {
            material.close()
        }
    }

    private fun completeArchiveTimestamp(
        environment: PadesInteropEnvironment,
        authority: VerifiedTimestampAuthority,
        prepared: PreparedPdfArchiveTimestamp,
    ) {
        val archiveDigest = prepared.copyDigest()
        try {
            val archiveTimestamp = authority.issue(archiveDigest)
            try {
                authority.validate(archiveTimestamp, archiveDigest)
                val archived = prepared.complete(archiveTimestamp)
                try {
                    assertArchiveInspection(archived.useBytes(environment::inspectPdf))
                } finally {
                    archived.close()
                }
            } finally {
                archiveTimestamp.close()
            }
        } finally {
            archiveDigest.fill(ZERO_BYTE)
        }
    }

    private fun assertArchiveInspection(inspection: PadesToolResult) {
        val validSignatures =
            inspection.output.split(PDFSIG_VALID_SIGNATURE_REPORT).size - REPORT_SPLIT_OFFSET
        assertTrue(inspection.exitCode in PERMITTED_PDFSIG_INSPECTION_EXIT_CODES)
        assertTrue(validSignatures >= MINIMUM_INDEPENDENTLY_VALID_SIGNATURES)
        assertTrue(inspection.output.contains(PDFSIG_WHOLE_DOCUMENT_REPORT))
        assertTrue(
            validSignatures == EXPECTED_SIGNATURE_COUNT ||
                inspection.output.contains(PDFSIG_UNVERIFIED_SIGNATURE_REPORT),
        )
    }

    private fun validationMaterial(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        timestamp: VerifiedTimestampToken,
    ): PdfValidationMaterial {
        val signerCertificate = signing.copySignerCertificate()
        return try {
            ValidationMaterialCollector.collect(
                request =
                    ValidationMaterialCollectionRequest(
                        signerCertificate = signerCertificate,
                        timestampTokens = listOf(timestamp),
                        signerTrustCertificates = listOf(signerCertificate),
                    ),
                dependencies = environment.validationDependencies(timestamp.generatedAt),
            )
        } finally {
            signerCertificate.fill(ZERO_BYTE)
        }
    }

    private fun verifyTimestampedAssembly(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        authority: VerifiedTimestampAuthority,
    ) {
        val timestampDigest = signing.timestampDigest()
        try {
            val token = authority.issue(timestampDigest)
            try {
                assertCmsFailure(QualifiedDocumentCmsFailure.TIMESTAMP_MISSING) {
                    signing.assemble(emptyList()).fill(ZERO_BYTE)
                }
                validateTimestampedOutput(
                    environment = environment,
                    signing = signing,
                    token = token,
                )
                rejectTimestampForAnotherSignature(signing, authority)
            } finally {
                token.close()
            }
            assertCmsFailure(QualifiedDocumentCmsFailure.TIMESTAMP_TOKEN_UNAVAILABLE) {
                signing.assemble(listOf(token)).fill(ZERO_BYTE)
            }
        } finally {
            timestampDigest.fill(ZERO_BYTE)
        }
    }

    private fun validateTimestampedOutput(
        environment: PadesInteropEnvironment,
        signing: PadesSigningFixture,
        token: VerifiedTimestampToken,
    ) {
        val tokenEncoding = token.copyEncoding()
        val cms = signing.assemble(listOf(token, token))
        try {
            assertSingleTimestampAttribute(cms, tokenEncoding)
            environment.validateCms(cms)
            val signedPdf = signing.fill(cms)
            try {
                val report = environment.validatePdf(signedPdf)
                assertTrue(report.contains(PDFSIG_VALID_SIGNATURE_REPORT))
                assertTrue(report.contains(PDFSIG_WHOLE_DOCUMENT_REPORT))
            } finally {
                signedPdf.fill(ZERO_BYTE)
            }
        } finally {
            tokenEncoding.fill(ZERO_BYTE)
            cms.fill(ZERO_BYTE)
        }
    }

    private fun rejectTimestampForAnotherSignature(
        signing: PadesSigningFixture,
        authority: VerifiedTimestampAuthority,
    ) {
        val differentDigest = ByteArray(SHA384_DIGEST_LENGTH_BYTES) { DIFFERENT_TIMESTAMP_DIGEST_FILL }
        try {
            val differentToken = authority.issue(differentDigest)
            try {
                assertCmsFailure(QualifiedDocumentCmsFailure.TIMESTAMP_IMPRINT_MISMATCH) {
                    signing.assemble(listOf(differentToken)).fill(ZERO_BYTE)
                }
            } finally {
                differentToken.close()
            }
        } finally {
            differentDigest.fill(ZERO_BYTE)
        }
    }

    private fun assertSingleTimestampAttribute(
        cms: ByteArray,
        expectedToken: ByteArray,
    ) {
        val outer = DerReader(cms)
        val contentInfo = checkNotNull(outer.next())
        check(contentInfo.tag == DerValues.TAG_SEQUENCE && outer.isAtEnd)
        val contentInfoFields = outer.children(contentInfo)
        checkNotNull(contentInfoFields.next())
        val wrapper = checkNotNull(contentInfoFields.next())
        check(wrapper.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED && contentInfoFields.isAtEnd)
        val wrapped = contentInfoFields.children(wrapper)
        val signedData = checkNotNull(wrapped.next())
        check(signedData.tag == DerValues.TAG_SEQUENCE && wrapped.isAtEnd)
        val signedDataFields = wrapped.children(signedData)
        repeat(SIGNED_DATA_FIELDS_BEFORE_SIGNERS) { checkNotNull(signedDataFields.next()) }
        val signerInfos = checkNotNull(signedDataFields.next())
        check(signerInfos.tag == DerValues.TAG_SET && signedDataFields.isAtEnd)
        val signerSet = signedDataFields.children(signerInfos)
        val signerInfo = checkNotNull(signerSet.next())
        check(signerInfo.tag == DerValues.TAG_SEQUENCE && signerSet.isAtEnd)
        val signerFields = signerSet.children(signerInfo)
        repeat(SIGNER_INFO_FIELDS_BEFORE_UNSIGNED_ATTRIBUTES) {
            checkNotNull(signerFields.next())
        }
        val unsignedAttributes = checkNotNull(signerFields.next())
        assertEquals(DerValues.TAG_CONTEXT_1_CONSTRUCTED, unsignedAttributes.tag)
        assertTrue(signerFields.isAtEnd)
        val attributes = signerFields.children(unsignedAttributes)
        val timestampAttribute = checkNotNull(attributes.next())
        assertEquals(DerValues.TAG_SEQUENCE, timestampAttribute.tag)
        assertTrue(attributes.isAtEnd)
        val attributeFields = attributes.children(timestampAttribute)
        val identifier = checkNotNull(attributeFields.next())
        val values = checkNotNull(attributeFields.next())
        assertArrayEquals(
            DerEncoder.objectIdentifier(QualifiedCmsOids.SIGNATURE_TIMESTAMP_TOKEN),
            attributeFields.raw(identifier),
        )
        assertEquals(DerValues.TAG_SET, values.tag)
        assertTrue(attributeFields.isAtEnd)
        val tokenSet = attributeFields.children(values)
        val token = checkNotNull(tokenSet.next())
        assertArrayEquals(expectedToken, tokenSet.raw(token))
        assertTrue(tokenSet.isAtEnd)
    }

    private fun assertCmsFailure(
        expected: QualifiedDocumentCmsFailure,
        operation: () -> Unit,
    ) {
        val failure =
            assertThrows(QualifiedDocumentCmsException::class.java) {
                operation()
            }
        assertEquals(expected, failure.kind)
    }

    private companion object {
        const val PDFSIG_VALID_SIGNATURE_REPORT = "Signature Validation: Signature is Valid."
        const val PDFSIG_WHOLE_DOCUMENT_REPORT = "Total document signed"
        const val SIGNED_DATA_FIELDS_BEFORE_SIGNERS = 4
        const val SIGNER_INFO_FIELDS_BEFORE_UNSIGNED_ATTRIBUTES = 6
        const val EXPECTED_SIGNATURE_COUNT = 2
        const val MINIMUM_INDEPENDENTLY_VALID_SIGNATURES = 1
        const val REPORT_SPLIT_OFFSET = 1
        const val PDFSIG_SUCCESS_EXIT_CODE = 0
        const val PDFSIG_UNVERIFIED_EXIT_CODE = 1
        const val PDFSIG_UNVERIFIED_SIGNATURE_REPORT = "Signature has not yet been verified."
        const val DIFFERENT_TIMESTAMP_DIGEST_FILL: Byte = 0x31
        const val ZERO_BYTE: Byte = 0
        val PERMITTED_PDFSIG_INSPECTION_EXIT_CODES =
            setOf(PDFSIG_SUCCESS_EXIT_CODE, PDFSIG_UNVERIFIED_EXIT_CODE)
    }
}

private class PadesSigningFixture private constructor(
    private val placeholder: PdfSignaturePlaceholder,
    private val ownedSignedAttributes: ByteArray,
    private val ownedSignature: NativeQualifiedSignature,
    private val ownedCertificate: NativeQualifiedCertificate,
) : AutoCloseable {
    fun timestampDigest(): ByteArray = QualifiedDocumentCms.signatureTimestampDigest(ownedSignature)

    fun assemble(tokens: List<VerifiedTimestampToken>): ByteArray =
        QualifiedDocumentCms.assembleTimestamped(
            signedAttributesSet = ownedSignedAttributes,
            signature = ownedSignature,
            signerCertificate = ownedCertificate,
            timestampTokens = tokens,
        )

    fun fill(cms: ByteArray): ByteArray = placeholder.filledWith(cms)

    fun copySignerCertificate(): ByteArray = ownedCertificate.copyDer()

    override fun close() {
        placeholder.close()
        ownedSignedAttributes.fill(ZERO_BYTE)
        ownedSignature.close()
        ownedCertificate.close()
    }

    companion object {
        fun create(environment: PadesInteropEnvironment): PadesSigningFixture {
            val certificate =
                NativeQualifiedCertificate(
                    keyProfile = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.keyProfile,
                    ownedDer = environment.generateQualifiedCertificate(),
                )
            val placeholder =
                PdfIncrementalSigner.prepare(
                    document = PdfTestDocuments.minimalClassic().document,
                    revision = PdfSignatureRevision.Signature(PADES_SIGNATURE_CLAIM),
                )
            val documentDigest = placeholder.digest()
            val signedAttributes =
                try {
                    QualifiedDocumentCms.signedAttributes(documentDigest, certificate)
                } finally {
                    documentDigest.fill(ZERO_BYTE)
                }
            val signatureBytes = environment.sign(signedAttributes)
            check(signatureBytes.size == QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.signatureLength)
            return PadesSigningFixture(
                placeholder = placeholder,
                ownedSignedAttributes = signedAttributes,
                ownedSignature =
                    NativeQualifiedSignature(
                        algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                        ownedBytes = signatureBytes,
                    ),
                ownedCertificate = certificate,
            )
        }

        private const val ZERO_BYTE: Byte = 0
        private val PADES_SIGNATURE_CLAIM =
            PdfSignatureClaim(
                signedAt = Instant.parse("2026-08-15T12:34:56Z"),
                reason = null,
                location = null,
            )
    }
}

private class VerifiedTimestampAuthority private constructor(
    private val environment: PadesInteropEnvironment,
    private val ownedTrustedCertificate: ByteArray,
) : AutoCloseable {
    fun issue(digest: ByteArray): VerifiedTimestampToken {
        val response = environment.issueTimestamp(digest)
        val unverified =
            try {
                Rfc3161Timestamp.token(
                    response = response,
                    digest = digest,
                    nonce = PadesInteropEnvironment.TIMESTAMP_REQUEST_NONCE,
                )
            } finally {
                response.fill(ZERO_BYTE)
            }
        return try {
            TimestampTokenVerifier.verify(
                token = unverified,
                trustedCertificates = listOf(ownedTrustedCertificate),
            )
        } finally {
            unverified.close()
        }
    }

    fun validate(
        token: VerifiedTimestampToken,
        digest: ByteArray,
    ) {
        val encoding = token.copyEncoding()
        try {
            environment.validateTimestampToken(encoding, digest)
        } finally {
            encoding.fill(ZERO_BYTE)
        }
    }

    override fun close() {
        ownedTrustedCertificate.fill(ZERO_BYTE)
    }

    companion object {
        fun create(environment: PadesInteropEnvironment): VerifiedTimestampAuthority =
            VerifiedTimestampAuthority(
                environment = environment,
                ownedTrustedCertificate = environment.generateTimestampAuthority(),
            )

        private const val ZERO_BYTE: Byte = 0
    }
}

private class PadesInteropEnvironment private constructor(
    private val executables: PadesInteropExecutables,
    private val directory: Path,
) : AutoCloseable {
    fun generateQualifiedCertificate(): ByteArray {
        runOpenSsl(
            listOf(
                CERTIFICATE_REQUEST_COMMAND,
                SELF_SIGNED_ARGUMENT,
                NEW_KEY_ARGUMENT,
                QUALIFIED_RSA_KEY_ARGUMENT,
                SHA384_ARGUMENT,
                VALIDITY_ARGUMENT,
                CERTIFICATE_VALIDITY_DAYS,
                UNENCRYPTED_KEY_ARGUMENT,
                SUBJECT_ARGUMENT,
                QUALIFIED_CERTIFICATE_SUBJECT,
                KEY_OUTPUT_ARGUMENT,
                QUALIFIED_PRIVATE_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                QUALIFIED_CERTIFICATE_PEM_FILENAME,
            ),
        )
        convertCertificate(
            input = QUALIFIED_CERTIFICATE_PEM_FILENAME,
            output = QUALIFIED_CERTIFICATE_DER_FILENAME,
        )
        return Files.readAllBytes(directory.resolve(QUALIFIED_CERTIFICATE_DER_FILENAME))
    }

    fun sign(signedAttributes: ByteArray): ByteArray {
        Files.write(directory.resolve(QUALIFIED_SIGNED_ATTRIBUTES_FILENAME), signedAttributes)
        runOpenSsl(
            listOf(
                DIGEST_COMMAND,
                SHA384_ARGUMENT,
                SIGN_ARGUMENT,
                QUALIFIED_PRIVATE_KEY_FILENAME,
                OUTPUT_ARGUMENT,
                QUALIFIED_SIGNATURE_FILENAME,
                QUALIFIED_SIGNED_ATTRIBUTES_FILENAME,
            ),
        )
        return Files.readAllBytes(directory.resolve(QUALIFIED_SIGNATURE_FILENAME))
    }

    fun generateTimestampAuthority(): ByteArray {
        generateTimestampRoot()
        generateTimestampSigner()
        generateTimestampRevocationList()
        convertCertificate(
            input = ROOT_CERTIFICATE_PEM_FILENAME,
            output = ROOT_CERTIFICATE_DER_FILENAME,
        )
        Files.writeString(directory.resolve(TIMESTAMP_SERIAL_FILENAME), INITIAL_TIMESTAMP_SERIAL)
        Files.writeString(
            directory.resolve(TIMESTAMP_CONFIGURATION_FILENAME),
            timestampConfiguration(),
        )
        return Files.readAllBytes(directory.resolve(ROOT_CERTIFICATE_DER_FILENAME))
    }

    fun validationDependencies(currentTime: Instant): ValidationMaterialCollectorDependencies =
        ValidationMaterialCollectorDependencies(
            get =
                ValidationMaterialGetter { address, resource ->
                    if (
                        address != TIMESTAMP_REVOCATION_LIST_ADDRESS ||
                        resource != ValidationMaterialGetResource.REVOCATION_LIST
                    ) {
                        throw UnexpectedValidationIoException()
                    }
                    Files.readAllBytes(directory.resolve(ROOT_REVOCATION_LIST_DER_FILENAME))
                },
            post = ValidationMaterialPoster { _, _, _ -> throw UnexpectedValidationIoException() },
            now = { currentTime },
            random = ValidationSecureRandom { _ -> throw UnexpectedValidationIoException() },
        )

    fun issueTimestamp(digest: ByteArray): ByteArray {
        val request = Rfc3161Timestamp.request(digest, TIMESTAMP_REQUEST_NONCE)
        try {
            Files.write(directory.resolve(TIMESTAMP_REQUEST_FILENAME), request)
            runOpenSsl(
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
            )
            return Files.readAllBytes(directory.resolve(TIMESTAMP_RESPONSE_FILENAME))
        } finally {
            request.fill(ZERO_BYTE)
        }
    }

    fun validateCms(cms: ByteArray) {
        Files.write(directory.resolve(TIMESTAMPED_CMS_FILENAME), cms)
        runOpenSsl(
            listOf(
                CMS_COMMAND,
                CMS_OUTPUT_ARGUMENT,
                INPUT_FORMAT_ARGUMENT,
                DER_INPUT_FORMAT,
                INPUT_ARGUMENT,
                TIMESTAMPED_CMS_FILENAME,
                CMS_PRINT_ARGUMENT,
            ),
        )
    }

    fun validatePdf(pdf: ByteArray): String {
        Files.write(directory.resolve(TIMESTAMPED_PDF_FILENAME), pdf)
        runTool(executables.qpdf, listOf(QPDF_CHECK_ARGUMENT, TIMESTAMPED_PDF_FILENAME))
        return runTool(
            executables.pdfsig,
            listOf(PDFSIG_NO_CERTIFICATE_ARGUMENT, TIMESTAMPED_PDF_FILENAME),
        )
    }

    fun inspectPdf(pdf: ByteArray): PadesToolResult {
        Files.write(directory.resolve(TIMESTAMPED_PDF_FILENAME), pdf)
        runTool(executables.qpdf, listOf(QPDF_CHECK_ARGUMENT, TIMESTAMPED_PDF_FILENAME))
        return executeTool(
            executables.pdfsig,
            listOf(PDFSIG_NO_CERTIFICATE_ARGUMENT, TIMESTAMPED_PDF_FILENAME),
        )
    }

    fun validateTimestampToken(
        token: ByteArray,
        digest: ByteArray,
    ) {
        Files.write(directory.resolve(ARCHIVE_TIMESTAMP_TOKEN_FILENAME), token)
        runOpenSsl(
            listOf(
                TIMESTAMP_COMMAND,
                TIMESTAMP_VERIFY_ARGUMENT,
                TIMESTAMP_TOKEN_INPUT_ARGUMENT,
                INPUT_ARGUMENT,
                ARCHIVE_TIMESTAMP_TOKEN_FILENAME,
                TIMESTAMP_DIGEST_ARGUMENT,
                HexFormat.of().formatHex(digest),
                CERTIFICATE_AUTHORITY_FILE_ARGUMENT,
                ROOT_CERTIFICATE_PEM_FILENAME,
            ),
        )
    }

    override fun close() {
        if (!Files.exists(directory)) {
            return
        }
        Files.walk(directory).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private fun generateTimestampRoot() {
        runOpenSsl(
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
        )
    }

    private fun generateTimestampSigner() {
        runOpenSsl(
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
        )
        Files.writeString(
            directory.resolve(TIMESTAMP_CERTIFICATE_EXTENSIONS_FILENAME),
            TIMESTAMP_CERTIFICATE_EXTENSIONS,
        )
        runOpenSsl(
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
        )
    }

    private fun generateTimestampRevocationList() {
        Files.createDirectories(directory.resolve(ROOT_CA_NEW_CERTIFICATES_DIRECTORY))
        Files.writeString(directory.resolve(ROOT_CA_DATABASE_FILENAME), EMPTY_CERTIFICATE_DATABASE)
        Files.writeString(directory.resolve(ROOT_CA_SERIAL_FILENAME), INITIAL_ROOT_CA_SERIAL)
        Files.writeString(directory.resolve(ROOT_CRL_NUMBER_FILENAME), INITIAL_ROOT_CRL_NUMBER)
        Files.writeString(
            directory.resolve(ROOT_CA_CONFIGURATION_FILENAME),
            rootCaConfiguration(),
        )
        runOpenSsl(
            listOf(
                CERTIFICATE_AUTHORITY_COMMAND,
                GENERATE_REVOCATION_LIST_ARGUMENT,
                CONFIGURATION_ARGUMENT,
                ROOT_CA_CONFIGURATION_FILENAME,
                OUTPUT_ARGUMENT,
                ROOT_REVOCATION_LIST_PEM_FILENAME,
                BATCH_ARGUMENT,
            ),
        )
        runOpenSsl(
            listOf(
                REVOCATION_LIST_COMMAND,
                INPUT_ARGUMENT,
                ROOT_REVOCATION_LIST_PEM_FILENAME,
                OUTPUT_FORMAT_ARGUMENT,
                DER_OUTPUT_FORMAT,
                OUTPUT_ARGUMENT,
                ROOT_REVOCATION_LIST_DER_FILENAME,
            ),
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
        input: String,
        output: String,
    ) {
        runOpenSsl(
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

    private fun timestampConfiguration(): String =
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

    private fun rootCaConfiguration(): String =
        """
        [ ca ]
        default_ca = local_ca

        [ local_ca ]
        database = ${directory.resolve(ROOT_CA_DATABASE_FILENAME)}
        new_certs_dir = ${directory.resolve(ROOT_CA_NEW_CERTIFICATES_DIRECTORY)}
        certificate = ${directory.resolve(ROOT_CERTIFICATE_PEM_FILENAME)}
        private_key = ${directory.resolve(ROOT_PRIVATE_KEY_FILENAME)}
        serial = ${directory.resolve(ROOT_CA_SERIAL_FILENAME)}
        crlnumber = ${directory.resolve(ROOT_CRL_NUMBER_FILENAME)}
        default_md = sha384
        default_crl_days = $ROOT_CRL_VALIDITY_DAYS
        policy = policy_any
        unique_subject = no

        [ policy_any ]
        commonName = supplied
        """.trimIndent()

    private fun runOpenSsl(arguments: List<String>): String = runTool(executables.openssl, arguments)

    private fun runTool(
        executable: Path,
        arguments: List<String>,
    ): String {
        val result = executeTool(executable, arguments)
        assertEquals(result.output, SUCCESSFUL_PROCESS_EXIT_CODE, result.exitCode)
        return result.output
    }

    private fun executeTool(
        executable: Path,
        arguments: List<String>,
    ): PadesToolResult {
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
        return PadesToolResult(output = report, exitCode = process.exitValue())
    }

    companion object {
        fun discover(): PadesInteropEnvironment? {
            val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME) ?: return null
            val qpdf = findExecutable(QPDF_EXECUTABLE_NAME) ?: return null
            val pdfsig = findExecutable(PDFSIG_EXECUTABLE_NAME) ?: return null
            return PadesInteropEnvironment(
                executables =
                    PadesInteropExecutables(
                        openssl = openssl,
                        qpdf = qpdf,
                        pdfsig = pdfsig,
                    ),
                directory = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX),
            )
        }

        private fun findExecutable(name: String): Path? =
            TOOL_DIRECTORIES
                .asSequence()
                .map { directory -> Path.of(directory, name) }
                .firstOrNull(Files::isExecutable)

        private const val TEMPORARY_DIRECTORY_PREFIX = "refineid-pades-timestamp-interop-"
        private const val OPENSSL_EXECUTABLE_NAME = "openssl"
        private const val QPDF_EXECUTABLE_NAME = "qpdf"
        private const val PDFSIG_EXECUTABLE_NAME = "pdfsig"
        private val TOOL_DIRECTORIES =
            listOf(
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/bin",
            )

        const val QUALIFIED_PRIVATE_KEY_FILENAME = "qualified-private-key.pem"
        const val QUALIFIED_CERTIFICATE_PEM_FILENAME = "qualified-certificate.pem"
        const val QUALIFIED_CERTIFICATE_DER_FILENAME = "qualified-certificate.der"
        const val QUALIFIED_SIGNED_ATTRIBUTES_FILENAME = "qualified-signed-attributes.der"
        const val QUALIFIED_SIGNATURE_FILENAME = "qualified-signature.bin"
        const val TIMESTAMP_PRIVATE_KEY_FILENAME = "timestamp-private-key.pem"
        const val TIMESTAMP_CERTIFICATE_REQUEST_FILENAME = "timestamp-certificate.csr"
        const val TIMESTAMP_CERTIFICATE_EXTENSIONS_FILENAME = "timestamp-certificate-extensions.cnf"
        const val TIMESTAMP_CERTIFICATE_PEM_FILENAME = "timestamp-certificate.pem"
        const val ROOT_PRIVATE_KEY_FILENAME = "root-private-key.pem"
        const val ROOT_CERTIFICATE_PEM_FILENAME = "root-certificate.pem"
        const val ROOT_CERTIFICATE_DER_FILENAME = "root-certificate.der"
        const val ROOT_CA_CONFIGURATION_FILENAME = "root-ca.cnf"
        const val ROOT_CA_DATABASE_FILENAME = "root-ca-index.txt"
        const val ROOT_CA_SERIAL_FILENAME = "root-ca-serial"
        const val ROOT_CRL_NUMBER_FILENAME = "root-crl-number"
        const val ROOT_CA_NEW_CERTIFICATES_DIRECTORY = "root-newcerts"
        const val ROOT_REVOCATION_LIST_PEM_FILENAME = "root.crl.pem"
        const val ROOT_REVOCATION_LIST_DER_FILENAME = "root.crl.der"
        const val TIMESTAMP_SERIAL_FILENAME = "timestamp-serial"
        const val TIMESTAMP_CONFIGURATION_FILENAME = "timestamp.cnf"
        const val TIMESTAMP_REQUEST_FILENAME = "timestamp-request.der"
        const val TIMESTAMP_RESPONSE_FILENAME = "timestamp-response.der"
        const val TIMESTAMPED_CMS_FILENAME = "timestamped-signature.der"
        const val TIMESTAMPED_PDF_FILENAME = "timestamped.pdf"
        const val ARCHIVE_TIMESTAMP_TOKEN_FILENAME = "archive-timestamp-token.der"

        const val CERTIFICATE_REQUEST_COMMAND = "req"
        const val CERTIFICATE_COMMAND = "x509"
        const val TIMESTAMP_COMMAND = "ts"
        const val CMS_COMMAND = "cms"
        const val DIGEST_COMMAND = "dgst"
        const val CERTIFICATE_AUTHORITY_COMMAND = "ca"
        const val REVOCATION_LIST_COMMAND = "crl"
        const val SELF_SIGNED_ARGUMENT = "-x509"
        const val NEW_ARGUMENT = "-new"
        const val NEW_KEY_ARGUMENT = "-newkey"
        const val EC_KEY_ARGUMENT = "ec"
        const val QUALIFIED_RSA_KEY_ARGUMENT = "rsa:3072"
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
        const val INPUT_FORMAT_ARGUMENT = "-inform"
        const val DER_OUTPUT_FORMAT = "der"
        const val DER_INPUT_FORMAT = "DER"
        const val ADD_EXTENSION_ARGUMENT = "-addext"
        const val EXTENSION_FILE_ARGUMENT = "-extfile"
        const val CERTIFICATE_REQUEST_INPUT_ARGUMENT = "-req"
        const val CERTIFICATE_AUTHORITY_ARGUMENT = "-CA"
        const val CERTIFICATE_AUTHORITY_KEY_ARGUMENT = "-CAkey"
        const val CREATE_CERTIFICATE_AUTHORITY_SERIAL_ARGUMENT = "-CAcreateserial"
        const val CONFIGURATION_ARGUMENT = "-config"
        const val CONFIGURATION_SECTION_ARGUMENT = "-section"
        const val TIMESTAMP_QUERY_FILE_ARGUMENT = "-queryfile"
        const val GENERATE_REVOCATION_LIST_ARGUMENT = "-gencrl"
        const val BATCH_ARGUMENT = "-batch"
        const val TIMESTAMP_REPLY_ARGUMENT = "-reply"
        const val TIMESTAMP_VERIFY_ARGUMENT = "-verify"
        const val TIMESTAMP_TOKEN_INPUT_ARGUMENT = "-token_in"
        const val TIMESTAMP_DIGEST_ARGUMENT = "-digest"
        const val CERTIFICATE_AUTHORITY_FILE_ARGUMENT = "-CAfile"
        const val SIGN_ARGUMENT = "-sign"
        const val CMS_OUTPUT_ARGUMENT = "-cmsout"
        const val CMS_PRINT_ARGUMENT = "-print"
        const val QPDF_CHECK_ARGUMENT = "--check"
        const val PDFSIG_NO_CERTIFICATE_ARGUMENT = "-nocert"

        const val TIMESTAMP_CERTIFICATE_SUBJECT = "/CN=RefineID synthetic timestamp authority"
        const val ROOT_CERTIFICATE_SUBJECT = "/CN=RefineID synthetic timestamp root"
        const val QUALIFIED_CERTIFICATE_SUBJECT = "/CN=RefineID synthetic qualified PDF signer"
        const val SUBJECT_KEY_IDENTIFIER_EXTENSION = "subjectKeyIdentifier=hash"
        const val TIMESTAMP_REVOCATION_LIST_ADDRESS = "https://tsa.example/root.crl"
        const val TIMESTAMP_CERTIFICATE_EXTENSIONS =
            "basicConstraints=critical,CA:false\n" +
                "keyUsage=critical,digitalSignature\n" +
                "extendedKeyUsage=critical,timeStamping\n" +
                "subjectKeyIdentifier=hash\n" +
                "authorityKeyIdentifier=keyid,issuer\n" +
                "crlDistributionPoints=URI:$TIMESTAMP_REVOCATION_LIST_ADDRESS\n"
        const val AUTHORITY_BASIC_CONSTRAINTS = "basicConstraints=critical,CA:true"
        const val AUTHORITY_KEY_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
        const val TIMESTAMP_CONFIGURATION_SECTION = "timestamp_authority"
        const val TIMESTAMP_POLICY_OID = "1.2.3.4.1"
        const val TIMESTAMP_ACCEPTED_DIGESTS = "sha256, sha384, sha512"
        const val TIMESTAMP_ACCURACY_SECONDS = "1"
        const val INITIAL_TIMESTAMP_SERIAL = "01\n"
        const val INITIAL_ROOT_CA_SERIAL = "1000\n"
        const val INITIAL_ROOT_CRL_NUMBER = "01\n"
        const val EMPTY_CERTIFICATE_DATABASE = ""
        const val ROOT_CRL_VALIDITY_DAYS = "2"
        private const val TIMESTAMP_REQUEST_NONCE_TEXT = "pades-baseline-t-test-nonce"
        val TIMESTAMP_REQUEST_NONCE = TIMESTAMP_REQUEST_NONCE_TEXT.encodeToByteArray()

        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val ZERO_BYTE: Byte = 0
    }

    private class UnexpectedValidationIoException : Exception()
}

private data class PadesInteropExecutables(
    val openssl: Path,
    val qpdf: Path,
    val pdfsig: Path,
)

private data class PadesToolResult(
    val output: String,
    val exitCode: Int,
)
