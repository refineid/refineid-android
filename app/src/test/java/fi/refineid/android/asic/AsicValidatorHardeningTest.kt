// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber")

package fi.refineid.android.asic

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.document.DerEncoder
import fi.refineid.android.document.DocumentValidationResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Hardening tests for AsicValidator: XSW prevention, unsigned ZIP entry detection,
 * #SignedProperties verification, zip bomb protection, and META-INF role validation.
 *
 * Addresses refineid-android#299 (critical): AsicValidator.kt raw substring slicing
 * allows XSW forgery, skips #SignedProperties, ignores unsigned ZIP entries, and
 * OOMs on zip bombs (overlaps refineid-android#295 and security-review#63).
 */
class AsicValidatorHardeningTest {
    private val mimeType = AsicContainer.MIME_TYPE

    private fun obj(
        name: String,
        content: String = "hello",
        mimeType: String = "text/plain",
    ) = AsicDataObject(name = name, content = content.encodeToByteArray(), mimeType = mimeType)

    private fun generateTestCertificate(): Pair<KeyPair, X509Certificate> {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp384r1"))
        val keyPair = generator.generateKeyPair()
        val name =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.setOf(
                        listOf(
                            DerEncoder.sequence(
                                listOf(
                                    DerEncoder.objectIdentifier("2.5.4.3"),
                                    DerEncoder.tlv(0x0C, "Test Signer".encodeToByteArray()),
                                ),
                            ),
                        ),
                    ),
                ),
            )
        val algorithm = DerEncoder.sequence(listOf(DerEncoder.objectIdentifier("1.2.840.10045.4.3.3")))
        val validity =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.tlv(0x17, "240101000000Z".encodeToByteArray()),
                    DerEncoder.tlv(0x17, "340101000000Z".encodeToByteArray()),
                ),
            )
        val tbs =
            DerEncoder.sequence(
                listOf(
                    DerEncoder.tlv(0xA0, DerEncoder.integer(2)),
                    DerEncoder.integer(1),
                    algorithm,
                    name,
                    validity,
                    name,
                    keyPair.public.encoded,
                ),
            )
        val signer = Signature.getInstance("SHA384withECDSA")
        signer.initSign(keyPair.private)
        signer.update(tbs)
        val tbsSignature = signer.sign()
        val certBytes =
            DerEncoder.sequence(
                listOf(
                    tbs,
                    algorithm,
                    DerEncoder.tlv(0x03, byteArrayOf(0) + tbsSignature),
                ),
            )
        val cert =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(certBytes.inputStream()) as X509Certificate
        return keyPair to cert
    }

    private fun createSignedContainer(
        objects: List<AsicDataObject>,
        keyPair: KeyPair,
        certificate: X509Certificate,
    ): Pair<ByteArray, String> {
        val plan =
            XadesSignature.plan(
                profile = NativeCardKeyProfile.ECDSA_P384,
                objects = objects,
                certificateDer = certificate.encoded,
                signedAt = Instant.parse("2026-08-29T12:00:00Z"),
            )
        val signer = Signature.getInstance("SHA384withECDSA")
        signer.initSign(keyPair.private)
        signer.update(plan.signedInfo.encodeToByteArray())
        val rawSig = signer.sign()
        val docXml = plan.document(xmlSignature = rawSig)
        val container =
            AsicContainer.container(objects, docXml.encodeToByteArray())
                ?: error("failed to create container")
        return container to docXml
    }

    private fun buildZip(entries: List<Pair<String, ByteArray>>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            for ((name, content) in entries) {
                val entry = ZipEntry(name)
                if (name == "mimetype") {
                    entry.method = ZipEntry.STORED
                    entry.size = content.size.toLong()
                    entry.compressedSize = content.size.toLong()
                    entry.crc =
                        java.util.zip.CRC32().let { crc ->
                            crc.update(content)
                            crc.value
                        }
                }
                zip.putNextEntry(entry)
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    // ---- 1. Intact signed container passes verification ----

    @Test
    fun containerWithOnlySignedFilesPassesDigestCheck() {
        val (keyPair, cert) = generateTestCertificate()
        val objects = listOf(obj("doc.txt", "Sample document text"))
        val (container, _) = createSignedContainer(objects, keyPair, cert)

        val result = AsicValidator.validate(container, listOf(cert))
        assertTrue("valid container should complete", result is DocumentValidationResult.Completed)
        val verdict = (result as DocumentValidationResult.Completed).signatures.single()
        assertTrue("digest should match", verdict.digestMatches)
        assertTrue("signature should be valid", verdict.signatureValid)
        assertTrue("chain should be trusted", verdict.chainTrusted)
        assertTrue("should cover whole document", verdict.coversWholeDocument)
    }

    // ---- 2. Unsigned extra ZIP entries are detected ----

    @Test
    fun unsignedExtraFileInArchiveFailsDigestCheck() {
        val (keyPair, cert) = generateTestCertificate()
        val objects = listOf(obj("doc.txt", "Sample document text"))
        val (_, docXml) = createSignedContainer(objects, keyPair, cert)

        // Inject an unsigned extra file into the archive
        val tamperedArchive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.encodeToByteArray(),
                    "doc.txt" to "Sample document text".encodeToByteArray(),
                    "evil.txt" to "unsigned payload".encodeToByteArray(),
                    "META-INF/manifest.xml" to AsicContainer.manifest(objects),
                    "META-INF/signatures0.xml" to docXml.encodeToByteArray(),
                ),
            )

        val result = AsicValidator.validate(tamperedArchive, listOf(cert))
        assertTrue("should complete", result is DocumentValidationResult.Completed)
        val verdict = (result as DocumentValidationResult.Completed).signatures.single()
        assertFalse("unsigned extra file MUST cause digest mismatch", verdict.digestMatches)
    }

    // ---- 3. XSW: duplicate SignedInfo rejected ----

    @Test
    fun duplicateSignedInfoInsideSignatureFailsValidation() {
        val (keyPair, cert) = generateTestCertificate()
        val objects = listOf(obj("doc.txt", "Sample document text"))
        val (_, docXml) = createSignedContainer(objects, keyPair, cert)

        // Duplicate the SignedInfo element inside the Signature
        val dummySignedInfo =
            """
            <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"></ds:SignatureMethod>
            <ds:Reference URI="doc.txt">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"></ds:DigestMethod>
            <ds:DigestValue>AAAA</ds:DigestValue>
            </ds:Reference>
            </ds:SignedInfo>
            """.trimIndent()

        val tamperedXml =
            docXml
                .replace(
                    "<ds:Signature ",
                    "<ds:Signature ",
                ).replace(
                    "<ds:SignedInfo",
                    "$dummySignedInfo\n<ds:SignedInfo",
                )

        val tamperedArchive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.encodeToByteArray(),
                    "doc.txt" to "Sample document text".encodeToByteArray(),
                    "META-INF/signatures0.xml" to tamperedXml.encodeToByteArray(),
                ),
            )

        val result = AsicValidator.validate(tamperedArchive, listOf(cert))
        // Multiple SignedInfo elements must be rejected
        if (result is DocumentValidationResult.Completed) {
            for (verdict in result.signatures) {
                assertFalse(
                    "duplicate SignedInfo should fail validation",
                    verdict.signatureValid && verdict.digestMatches,
                )
            }
        } else {
            assertEquals(DocumentValidationResult.Malformed, result)
        }
    }

    // ---- 4. Tampered #SignedProperties fails digest check ----

    @Test
    fun tamperedSignedPropertiesFailsDigestCheck() {
        val (keyPair, cert) = generateTestCertificate()
        val objects = listOf(obj("doc.txt", "Sample document text"))
        val (_, docXml) = createSignedContainer(objects, keyPair, cert)

        // Tamper with the signing time inside SignedProperties
        val tamperedXml = docXml.replace("2026-08-29T12:00:00Z", "2026-01-01T00:00:00Z")
        assertTrue("replacement should have changed XML", tamperedXml != docXml)

        val tamperedArchive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.encodeToByteArray(),
                    "doc.txt" to "Sample document text".encodeToByteArray(),
                    "META-INF/signatures0.xml" to tamperedXml.encodeToByteArray(),
                ),
            )

        val result = AsicValidator.validate(tamperedArchive, listOf(cert))
        assertTrue("should parse into Completed", result is DocumentValidationResult.Completed)
        val verdict = (result as DocumentValidationResult.Completed).signatures.single()
        assertFalse("tampered SignedProperties must fail digest check", verdict.digestMatches)
    }

    // ---- 5. Missing #SignedProperties reference is rejected ----

    @Test
    fun signatureWithoutSignedPropertiesReferenceFailsDigest() {
        // A signature that has file references but no #SignedProperties reference
        val content = "PDF content"
        val digest =
            java.security.MessageDigest
                .getInstance("SHA-384")
                .digest(content.toByteArray())
        val b64Digest =
            java.util.Base64
                .getEncoder()
                .encodeToString(digest)
        val sigXml =
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#">
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="SIG-1">
            <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"></ds:SignatureMethod>
            <ds:Reference URI="document.pdf">
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"></ds:DigestMethod>
            <ds:DigestValue>$b64Digest</ds:DigestValue>
            </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>AAAA</ds:SignatureValue>
            <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </ds:Signature>
            </asic:XAdESSignatures>
            """.trimIndent()

        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "document.pdf" to content.toByteArray(),
                    "META-INF/signatures0.xml" to sigXml.toByteArray(),
                ),
            )
        val result = AsicValidator.validate(archive, emptyList())
        if (result is DocumentValidationResult.Completed) {
            for (verdict in result.signatures) {
                assertFalse("missing #SignedProperties should fail digest", verdict.digestMatches)
            }
        }
    }

    // ---- 6. Unsafe META-INF entries are refused ----

    @Test
    fun unknownMetaInfEntryIsMalformed() {
        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "document.pdf" to "hello".toByteArray(),
                    "META-INF/signatures0.xml" to "<sig/>".toByteArray(),
                    "META-INF/payload.pdf" to "unsigned payload".toByteArray(),
                ),
            )
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals("unknown META-INF file should be Malformed", DocumentValidationResult.Malformed, result)
    }

    @Test
    fun nestedMetaInfDirectoryEntryIsMalformed() {
        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "document.pdf" to "hello".toByteArray(),
                    "META-INF/signatures0.xml" to "<sig/>".toByteArray(),
                    "META-INF/sub/evil.xml" to "nested payload".toByteArray(),
                ),
            )
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals("nested META-INF entry should be Malformed", DocumentValidationResult.Malformed, result)
    }

    // ---- 7. Path traversal entries are refused ----

    @Test
    fun pathTraversalEntryIsMalformed() {
        for (badName in listOf("../escape.pdf", "/absolute.pdf", "a\\b.pdf", "a\u0000b.pdf")) {
            val archive =
                buildZip(
                    listOf(
                        "mimetype" to mimeType.toByteArray(),
                        badName to "payload".toByteArray(),
                    ),
                )
            val result = AsicValidator.validate(archive, emptyList())
            assertEquals(
                "path traversal name '$badName' should be Malformed",
                DocumentValidationResult.Malformed,
                result,
            )
        }
    }

    // ---- 8. Zip bomb protection ----

    @Test
    fun oversizedEntryIsMalformed() {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            val mt = mimeType.toByteArray()
            val mte = ZipEntry("mimetype")
            mte.method = ZipEntry.STORED
            mte.size = mt.size.toLong()
            mte.compressedSize = mt.size.toLong()
            mte.crc =
                java.util.zip.CRC32().let { crc ->
                    crc.update(mt)
                    crc.value
                }
            zip.putNextEntry(mte)
            zip.write(mt)
            zip.closeEntry()

            // 128 MiB of zeros (compressed to tiny size)
            val bomb = ZipEntry("bomb.bin")
            bomb.method = ZipEntry.DEFLATED
            zip.putNextEntry(bomb)
            val chunk = ByteArray(65536)
            val totalSize = 128L * 1024 * 1024
            var written = 0L
            while (written < totalSize) {
                val toWrite = minOf(chunk.size.toLong(), totalSize - written).toInt()
                zip.write(chunk, 0, toWrite)
                written += toWrite
            }
            zip.closeEntry()
        }
        val archive = out.toByteArray()
        assertTrue("archive should be small (compressed)", archive.size < 200_000)
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals("zip bomb should be Malformed", DocumentValidationResult.Malformed, result)
    }

    // ---- 9. Entry count limit ----

    @Test
    fun tooManyEntriesIsMalformed() {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            val mt = mimeType.toByteArray()
            val mte = ZipEntry("mimetype")
            mte.method = ZipEntry.STORED
            mte.size = mt.size.toLong()
            mte.compressedSize = mt.size.toLong()
            mte.crc =
                java.util.zip.CRC32().let { crc ->
                    crc.update(mt)
                    crc.value
                }
            zip.putNextEntry(mte)
            zip.write(mt)
            zip.closeEntry()

            for (i in 0..1025) {
                zip.putNextEntry(ZipEntry("file$i.txt"))
                zip.write("x".toByteArray())
                zip.closeEntry()
            }
        }
        val archive = out.toByteArray()
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals("too many entries should be Malformed", DocumentValidationResult.Malformed, result)
    }

    // ---- 10. isAsic detection ----

    @Test
    fun isAsicDetectsZipHeaderAndRejectsNonZip() {
        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "doc.txt" to "hello".toByteArray(),
                ),
            )
        assertTrue(AsicValidator.isAsic(archive))
        assertFalse(AsicValidator.isAsic("not a zip".toByteArray()))
        assertFalse(AsicValidator.isAsic(ByteArray(0)))
        assertFalse(AsicValidator.isAsic(ByteArray(3)))
    }

    // ---- 11. Unsigned container ----

    @Test
    fun containerWithNoSignatureXmlIsUnsigned() {
        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "doc.txt" to "hello".toByteArray(),
                ),
            )
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals(DocumentValidationResult.Unsigned, result)
    }

    // ---- 12. Allowed META-INF entries ----

    @Test
    fun allowedMetaInfEntriesAreAccepted() {
        val archive =
            buildZip(
                listOf(
                    "mimetype" to mimeType.toByteArray(),
                    "document.pdf" to "hello".toByteArray(),
                    "META-INF/signatures0.xml" to "<sig/>".toByteArray(),
                    "META-INF/manifest.xml" to "<manifest/>".toByteArray(),
                ),
            )
        val result = AsicValidator.validate(archive, emptyList())
        assertEquals(
            "manifest.xml should be allowed, result should be Unsigned",
            DocumentValidationResult.Unsigned,
            result,
        )
    }
}
