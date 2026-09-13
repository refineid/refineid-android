package fi.refineid.android.document

import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.P384_COORDINATE_LENGTH_BITS
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.Comparator
import java.util.concurrent.TimeUnit

/** End-to-end PAdES verification by parsers and cryptography outside this project. */
class QualifiedPdfInteropTest {
    @Test
    fun independentToolsVerifyBothProfilesAndRejectDocumentMutation() {
        val tools = ExternalTools.find()
        assumeTrue("OpenSSL, qpdf, and pdfsig are required for the interop test", tools != null)
        val availableTools = checkNotNull(tools)
        val root = Files.createTempDirectory(TEMPORARY_DIRECTORY_PREFIX)
        try {
            for (signingCase in SIGNING_CASES) {
                verifyCase(
                    signingCase = signingCase,
                    tools = availableTools,
                    directory = Files.createDirectory(root.resolve(signingCase.label)),
                )
            }
        } finally {
            root.deleteRecursively()
        }
    }

    private fun verifyCase(
        signingCase: SigningCase,
        tools: ExternalTools,
        directory: Path,
    ) {
        generateSigner(signingCase = signingCase, tools = tools, directory = directory)
        val certificateDer = Files.readAllBytes(directory.resolve(CERTIFICATE_DER_FILENAME))
        val card =
            OpenSslQualifiedCardService(
                signingCase = signingCase,
                tools = tools,
                directory = directory,
                certificateDer = certificateDer,
            )
        val signedDocument =
            try {
                sign(card)
            } finally {
                card.close()
                certificateDer.fill(ZERO_BYTE)
            }
        val signedPath = directory.resolve(SIGNED_PDF_FILENAME)
        val tamperedPath = directory.resolve(TAMPERED_PDF_FILENAME)
        try {
            Files.write(signedPath, signedDocument)

            tools.run(
                executable = tools.qpdf,
                arguments = listOf(QPDF_CHECK_ARGUMENT, SIGNED_PDF_FILENAME),
                directory = directory,
            )
            val verified =
                tools.run(
                    executable = tools.pdfsig,
                    arguments = listOf(PDFSIG_NO_CERTIFICATE_ARGUMENT, SIGNED_PDF_FILENAME),
                    directory = directory,
                )
            assertTrue(verified.report, verified.report.contains(PDFSIG_VALID_SIGNATURE_REPORT))
            assertTrue(verified.report, verified.report.contains(PDFSIG_WHOLE_DOCUMENT_REPORT))

            val tampered = signedDocument.copyOf()
            try {
                mutatePdfHeaderVersion(tampered)
                Files.write(tamperedPath, tampered)
                val refused =
                    tools.run(
                        executable = tools.pdfsig,
                        arguments = listOf(PDFSIG_NO_CERTIFICATE_ARGUMENT, TAMPERED_PDF_FILENAME),
                        directory = directory,
                        expectSuccess = false,
                    )
                assertNotEquals(SUCCESSFUL_PROCESS_EXIT_CODE, refused.status)
                assertTrue(refused.report, refused.report.contains(PDFSIG_DIGEST_MISMATCH_REPORT))
            } finally {
                tampered.fill(ZERO_BYTE)
            }
        } finally {
            signedDocument.fill(ZERO_BYTE)
        }
    }

    private fun sign(card: QualifiedCardService): ByteArray {
        var completion: QualifiedPdfSigningResult? = null
        val pin2 = Pin2Submission.from(SYNTHETIC_PIN2)
        QualifiedPdfSigningCoordinator(cardService = card).sign(
            document = PdfTestDocuments.minimalClassic().document,
            claim =
                PdfSignatureClaim(
                    signedAt = SIGNING_INSTANT,
                    reason = null,
                    location = null,
                ),
            pin2 = pin2,
        ) { result ->
            check(completion == null)
            completion = result
        }
        val success = checkNotNull(completion) as QualifiedPdfSigningResult.Success
        return try {
            success.document.copyBytes()
        } finally {
            success.document.close()
        }
    }

    private fun generateSigner(
        signingCase: SigningCase,
        tools: ExternalTools,
        directory: Path,
    ) {
        tools.run(
            executable = tools.openssl,
            arguments =
                listOf(
                    OPENSSL_CERTIFICATE_REQUEST_COMMAND,
                    OPENSSL_SELF_SIGNED_ARGUMENT,
                ) +
                    signingCase.keyArguments +
                    listOf(
                        OPENSSL_DIGEST_ARGUMENT,
                        OPENSSL_VALIDITY_ARGUMENT,
                        OPENSSL_VALIDITY_DAYS,
                        OPENSSL_UNENCRYPTED_KEY_ARGUMENT,
                        OPENSSL_SUBJECT_ARGUMENT,
                        OPENSSL_SYNTHETIC_SUBJECT,
                        OPENSSL_KEY_OUTPUT_ARGUMENT,
                        PRIVATE_KEY_FILENAME,
                        OPENSSL_CERTIFICATE_OUTPUT_ARGUMENT,
                        CERTIFICATE_PEM_FILENAME,
                    ),
            directory = directory,
        )
        tools.run(
            executable = tools.openssl,
            arguments =
                listOf(
                    OPENSSL_CERTIFICATE_COMMAND,
                    OPENSSL_INPUT_ARGUMENT,
                    CERTIFICATE_PEM_FILENAME,
                    OPENSSL_OUTPUT_FORMAT_ARGUMENT,
                    OPENSSL_DER_FORMAT,
                    OPENSSL_CERTIFICATE_OUTPUT_ARGUMENT,
                    CERTIFICATE_DER_FILENAME,
                ),
            directory = directory,
        )
    }

    private fun mutatePdfHeaderVersion(document: ByteArray) {
        val header = PDF_HEADER.encodeToByteArray()
        val headerStart = document.indexOf(header)
        check(headerStart >= FIRST_VALID_INDEX)
        val versionOffset = headerStart + header.lastIndex
        check(document[versionOffset] == ORIGINAL_PDF_VERSION_DIGIT)
        document[versionOffset] = ALTERNATE_PDF_VERSION_DIGIT
    }

    private fun ByteArray.indexOf(needle: ByteArray): Int {
        if (needle.size > size) {
            return MISSING_INDEX
        }
        return indices.firstOrNull { start ->
            start <= size - needle.size &&
                needle.indices.all { offset -> this[start + offset] == needle[offset] }
        } ?: MISSING_INDEX
    }

    private class OpenSslQualifiedCardService(
        private val signingCase: SigningCase,
        private val tools: ExternalTools,
        private val directory: Path,
        private val certificateDer: ByteArray,
    ) : QualifiedCardService,
        AutoCloseable {
        override fun requestQualifiedCertificate(
            onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit,
        ) {
            onResult(
                NativeCertificateReadResult.Success(
                    NativeQualifiedCertificate(
                        keyProfile = signingCase.algorithm.keyProfile,
                        ownedDer = certificateDer.copyOf(),
                    ),
                ),
            )
        }

        override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit) {
            error("the interop signer does not probe a credential")
        }

        override fun requestQualifiedSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            content: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) {
            assertEquals(signingCase.algorithm, algorithm)
            assertEquals(signingCase.algorithm.keyProfile, expectedCertificate.keyProfile)
            val submittedPin = pin2.consume(ByteArray::copyOf)
            try {
                assertArrayEquals(SYNTHETIC_PIN2.encodeToByteArray(), submittedPin)
            } finally {
                submittedPin.fill(ZERO_BYTE)
            }
            Files.write(directory.resolve(SIGNED_ATTRIBUTES_FILENAME), content)
            tools.run(
                executable = tools.openssl,
                arguments =
                    listOf(
                        OPENSSL_DIGEST_COMMAND,
                        OPENSSL_DIGEST_ARGUMENT,
                        OPENSSL_SIGN_ARGUMENT,
                        PRIVATE_KEY_FILENAME,
                        OPENSSL_SIGNATURE_OUTPUT_ARGUMENT,
                        SIGNATURE_FILENAME,
                        SIGNED_ATTRIBUTES_FILENAME,
                    ),
                directory = directory,
            )
            val opensslSignature = Files.readAllBytes(directory.resolve(SIGNATURE_FILENAME))
            val cardSignature =
                try {
                    when (algorithm) {
                        QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> opensslSignature.copyOf()
                        QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> ecdsaDerToRaw(opensslSignature)
                    }
                } finally {
                    opensslSignature.fill(ZERO_BYTE)
                }
            onResult(
                QualifiedSignResult.Success(
                    NativeQualifiedSignature(
                        algorithm = algorithm,
                        ownedBytes = cardSignature,
                    ),
                ),
            )
        }

        override fun requestQualifiedDigestSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            digest: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) {
            error("the interop signer does not sign prehashed digests")
        }

        override fun close() {
            certificateDer.fill(ZERO_BYTE)
        }

        private fun ecdsaDerToRaw(signature: ByteArray): ByteArray {
            val outer = DerReader(signature)
            val sequence = checkNotNull(outer.next())
            check(sequence.tag == DerValues.TAG_SEQUENCE && outer.isAtEnd)
            val fields = outer.children(sequence)
            val rElement = checkNotNull(fields.next())
            val sElement = checkNotNull(fields.next())
            check(
                rElement.tag == DerValues.TAG_INTEGER &&
                    sElement.tag == DerValues.TAG_INTEGER &&
                    fields.isAtEnd,
            )
            val r = fields.content(rElement)
            val s = fields.content(sElement)
            return try {
                ByteArray(signingCase.algorithm.signatureLength).also { raw ->
                    copyUnsignedCoordinate(r, raw, FIRST_COORDINATE_OFFSET)
                    copyUnsignedCoordinate(s, raw, P384_COORDINATE_LENGTH_BYTES)
                }
            } finally {
                r.fill(ZERO_BYTE)
                s.fill(ZERO_BYTE)
            }
        }

        private fun copyUnsignedCoordinate(
            encoded: ByteArray,
            destination: ByteArray,
            destinationOffset: Int,
        ) {
            var first = FIRST_COORDINATE_OFFSET
            while (first < encoded.lastIndex && encoded[first] == ZERO_BYTE) {
                first += COORDINATE_INDEX_STEP
            }
            val magnitudeLength = encoded.size - first
            check(magnitudeLength in MINIMUM_COORDINATE_LENGTH..P384_COORDINATE_LENGTH_BYTES)
            encoded.copyInto(
                destination = destination,
                destinationOffset = destinationOffset + P384_COORDINATE_LENGTH_BYTES - magnitudeLength,
                startIndex = first,
            )
        }
    }

    private data class SigningCase(
        val label: String,
        val algorithm: QualifiedSigningAlgorithm,
        val keyArguments: List<String>,
    )

    private data class ToolResult(
        val status: Int,
        val report: String,
    )

    private data class ExternalTools(
        val openssl: Path,
        val qpdf: Path,
        val pdfsig: Path,
    ) {
        fun run(
            executable: Path,
            arguments: List<String>,
            directory: Path,
            expectSuccess: Boolean = true,
        ): ToolResult {
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
            val result =
                ToolResult(
                    status = process.exitValue(),
                    report = process.inputStream.bufferedReader().use { reader -> reader.readText() },
                )
            if (expectSuccess) {
                assertEquals(result.report, SUCCESSFUL_PROCESS_EXIT_CODE, result.status)
            }
            return result
        }

        companion object {
            fun find(): ExternalTools? {
                val openssl = executable(OPENSSL_EXECUTABLE_NAME) ?: return null
                val qpdf = executable(QPDF_EXECUTABLE_NAME) ?: return null
                val pdfsig = executable(PDFSIG_EXECUTABLE_NAME) ?: return null
                return ExternalTools(openssl = openssl, qpdf = qpdf, pdfsig = pdfsig)
            }

            private fun executable(name: String): Path? =
                TOOL_DIRECTORIES
                    .asSequence()
                    .map { directory -> Path.of(directory, name) }
                    .firstOrNull(Files::isExecutable)
        }
    }

    private fun Path.deleteRecursively() {
        if (!Files.exists(this)) {
            return
        }
        Files.walk(this).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val TEMPORARY_DIRECTORY_PREFIX = "refineid-pades-interop-"
        const val PRIVATE_KEY_FILENAME = "synthetic-key.pem"
        const val CERTIFICATE_PEM_FILENAME = "synthetic-certificate.pem"
        const val CERTIFICATE_DER_FILENAME = "synthetic-certificate.der"
        const val SIGNED_ATTRIBUTES_FILENAME = "signed-attributes.der"
        const val SIGNATURE_FILENAME = "signature.bin"
        const val SIGNED_PDF_FILENAME = "signed.pdf"
        const val TAMPERED_PDF_FILENAME = "tampered.pdf"

        const val OPENSSL_EXECUTABLE_NAME = "openssl"
        const val QPDF_EXECUTABLE_NAME = "qpdf"
        const val PDFSIG_EXECUTABLE_NAME = "pdfsig"
        const val OPENSSL_CERTIFICATE_REQUEST_COMMAND = "req"
        const val OPENSSL_SELF_SIGNED_ARGUMENT = "-x509"
        const val OPENSSL_RSA_KEY_ARGUMENT = "rsa:3072"
        const val OPENSSL_EC_KEY_ARGUMENT = "ec"
        const val OPENSSL_NEW_KEY_ARGUMENT = "-newkey"
        const val OPENSSL_KEY_OPTION_ARGUMENT = "-pkeyopt"
        const val OPENSSL_P384_CURVE_ARGUMENT = "ec_paramgen_curve:secp384r1"
        const val OPENSSL_DIGEST_COMMAND = "dgst"
        const val OPENSSL_DIGEST_ARGUMENT = "-sha384"
        const val OPENSSL_VALIDITY_ARGUMENT = "-days"
        const val OPENSSL_VALIDITY_DAYS = "1"
        const val OPENSSL_UNENCRYPTED_KEY_ARGUMENT = "-nodes"
        const val OPENSSL_SUBJECT_ARGUMENT = "-subj"
        const val OPENSSL_SYNTHETIC_SUBJECT = "/CN=RefineID synthetic PDF interop"
        const val OPENSSL_KEY_OUTPUT_ARGUMENT = "-keyout"
        const val OPENSSL_CERTIFICATE_OUTPUT_ARGUMENT = "-out"
        const val OPENSSL_CERTIFICATE_COMMAND = "x509"
        const val OPENSSL_INPUT_ARGUMENT = "-in"
        const val OPENSSL_OUTPUT_FORMAT_ARGUMENT = "-outform"
        const val OPENSSL_DER_FORMAT = "der"
        const val OPENSSL_SIGN_ARGUMENT = "-sign"
        const val OPENSSL_SIGNATURE_OUTPUT_ARGUMENT = "-out"
        const val QPDF_CHECK_ARGUMENT = "--check"
        const val PDFSIG_NO_CERTIFICATE_ARGUMENT = "-nocert"

        const val PDFSIG_VALID_SIGNATURE_REPORT = "Signature Validation: Signature is Valid."
        const val PDFSIG_DIGEST_MISMATCH_REPORT = "Signature Validation: Digest Mismatch."
        const val PDFSIG_WHOLE_DOCUMENT_REPORT = "Total document signed"

        const val SYNTHETIC_PIN2 = "123456"
        const val PDF_HEADER = "%PDF-1.7"
        const val MISSING_INDEX = -1
        const val FIRST_VALID_INDEX = 0
        const val SUCCESSFUL_PROCESS_EXIT_CODE = 0
        const val TOOL_TIMEOUT_SECONDS = 30L
        const val FIRST_COORDINATE_OFFSET = 0
        const val COORDINATE_INDEX_STEP = 1
        const val MINIMUM_COORDINATE_LENGTH = 1
        const val ZERO_BYTE: Byte = 0
        val ORIGINAL_PDF_VERSION_DIGIT = '7'.code.toByte()
        val ALTERNATE_PDF_VERSION_DIGIT = '6'.code.toByte()
        val SIGNING_INSTANT: Instant = Instant.parse("2026-08-15T12:34:56Z")
        val P384_COORDINATE_LENGTH_BYTES = P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS
        val TOOL_DIRECTORIES = listOf("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin")
        val SIGNING_CASES =
            listOf(
                SigningCase(
                    label = "rsa3072",
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    keyArguments = listOf(OPENSSL_NEW_KEY_ARGUMENT, OPENSSL_RSA_KEY_ARGUMENT),
                ),
                SigningCase(
                    label = "p384",
                    algorithm = QualifiedSigningAlgorithm.ECDSA_P384_SHA384,
                    keyArguments =
                        listOf(
                            OPENSSL_NEW_KEY_ARGUMENT,
                            OPENSSL_EC_KEY_ARGUMENT,
                            OPENSSL_KEY_OPTION_ARGUMENT,
                            OPENSSL_P384_CURVE_ARGUMENT,
                        ),
                ),
            )
    }
}
