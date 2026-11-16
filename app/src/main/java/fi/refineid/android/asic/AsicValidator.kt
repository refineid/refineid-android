// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress(
    "MagicNumber",
    "ComplexMethod",
    "CyclomaticComplexMethod",
    "LongMethod",
    "NestedBlockDepth",
    "ReturnCount",
    "LoopWithTooManyJumpStatements",
    "TooGenericExceptionCaught",
    "TooManyFunctions",
)

package fi.refineid.android.asic

import fi.refineid.android.document.DocumentSignatureVerdict
import fi.refineid.android.document.DocumentValidationResult
import fi.refineid.android.document.RevocationStatus
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory

internal object AsicValidator {
    /**
     * Maximum decompressed size of any single ZIP entry (64 MiB).
     * Prevents zip bombs from exhausting memory.
     */
    private const val MAX_ENTRY_BYTES = 64L * 1024 * 1024

    /**
     * Maximum number of ZIP entries in a container.
     * A legitimate ASiC-E has a handful; this prevents DoS via
     * archives with millions of empty entries.
     */
    private const val MAX_ENTRY_COUNT = 1_024

    /** Namespace URI for XML Digital Signatures. */
    private const val NAMESPACE_DSIG = "http://www.w3.org/2000/09/xmldsig#"

    /** Namespace URI for XAdES 1.3.2 Qualifying Properties. */
    private const val NAMESPACE_XADES = "http://uri.etsi.org/01903/v1.3.2#"

    /** The fixed Type value that marks a Reference as pointing to SignedProperties. */
    private const val SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

    /** Permitted META-INF file names (lowercase, without the META-INF/ prefix). */
    private val ALLOWED_META_INF_PATTERNS = listOf("manifest.xml", "container.xml")

    fun isAsic(bytes: ByteArray): Boolean = bytes.size >= 4 && bytes[0] == 0x50.toByte() && bytes[1] == 0x4B.toByte()

    fun validate(
        archiveBytes: ByteArray,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus = { RevocationStatus.UNCHECKED },
    ): DocumentValidationResult {
        val entries = mutableMapOf<String, ByteArray>()
        var entryCount = 0
        try {
            ZipInputStream(ByteArrayInputStream(archiveBytes)).use { zip ->
                while (true) {
                    val entry = zip.nextEntry ?: break
                    entryCount++
                    if (entryCount > MAX_ENTRY_COUNT) {
                        return DocumentValidationResult.Malformed
                    }
                    if (!entry.isDirectory) {
                        // Validate entry name: refuse path traversal and control characters
                        if (!isEntryNameSafe(entry.name)) {
                            return DocumentValidationResult.Malformed
                        }
                        val content =
                            readBounded(zip, MAX_ENTRY_BYTES)
                                ?: return DocumentValidationResult.Malformed
                        entries[entry.name] = content
                    }
                    zip.closeEntry()
                }
            }
        } catch (_: Exception) {
            return DocumentValidationResult.Malformed
        }

        // Validate that all META-INF entries are recognized roles
        for (name in entries.keys) {
            if (!isMetaInfEntryAllowed(name)) {
                return DocumentValidationResult.Malformed
            }
        }

        val signatureXmlEntries =
            entries.filter { (name, _) ->
                name.startsWith("META-INF/") && name.endsWith(".xml") &&
                    (name.contains("signature", ignoreCase = true) || name.contains("signatures", ignoreCase = true))
            }

        if (signatureXmlEntries.isEmpty()) {
            return DocumentValidationResult.Unsigned
        }

        // Collect all data entries (non-META-INF, non-mimetype)
        val dataEntryNames =
            entries.keys
                .filter { name ->
                    !name.startsWith("META-INF/") && !name.equals("mimetype", ignoreCase = true)
                }.toSet()

        val verdicts = mutableListOf<DocumentSignatureVerdict>()
        for ((_, xmlBytes) in signatureXmlEntries) {
            val sigVerdicts =
                parseAndVerifyXml(xmlBytes, entries, dataEntryNames, trustAnchors, checkRevocation)
                    ?: return DocumentValidationResult.Malformed
            verdicts.addAll(sigVerdicts)
        }

        return if (verdicts.isEmpty()) {
            DocumentValidationResult.Unsigned
        } else {
            DocumentValidationResult.Completed(verdicts)
        }
    }

    /**
     * Reads up to [limit] bytes from [input]. Returns null if the stream
     * exceeds the limit, preventing OOM from decompression bombs.
     */
    private fun readBounded(
        input: InputStream,
        limit: Long,
    ): ByteArray? {
        val buffer = ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var total = 0L
        while (true) {
            val read = input.read(chunk)
            if (read == -1) break
            total += read
            if (total > limit) return null
            buffer.write(chunk, 0, read)
        }
        return buffer.toByteArray()
    }

    /**
     * Validates a ZIP entry name: refuses empty names, absolute paths,
     * parent-directory traversals, backslashes, and control characters.
     */
    private fun isEntryNameSafe(name: String): Boolean {
        if (name.isEmpty()) return false
        if (name.startsWith("/")) return false
        if (name.contains('\\')) return false
        if (name.any { it.isISOControl() }) return false
        val segments = name.split("/")
        for (segment in segments) {
            if (segment == "..") return false
            if (segment == "." && segments.size > 1) return false
        }
        // Reject duplicate slashes (empty segments in the middle)
        for (i in 0 until segments.size - 1) {
            if (segments[i].isEmpty()) return false
        }
        return true
    }

    /**
     * Validates that META-INF entries are recognized container metadata.
     * Rejects unknown files inside META-INF/ to prevent unsigned payload injection.
     */
    private fun isMetaInfEntryAllowed(name: String): Boolean {
        if (!name.startsWith("META-INF/")) return true
        val inside = name.removePrefix("META-INF/")
        // Reject nested directories inside META-INF
        if (inside.contains("/")) return false
        if (inside.isEmpty()) return false
        val foldedInside = inside.lowercase()
        // Allow signature XML files
        if (foldedInside.endsWith(".xml") &&
            (foldedInside.contains("signature") || foldedInside.contains("signatures"))
        ) {
            return true
        }
        // Allow known passive metadata
        if (foldedInside in ALLOWED_META_INF_PATTERNS) return true
        // Allow ASiC manifest files
        if (foldedInside.endsWith(".xml") &&
            (foldedInside.contains("asicmanifest") || foldedInside.contains("asicarchivemanifest"))
        ) {
            return true
        }
        // Allow CAdES signature entries
        if (foldedInside.contains("signature") &&
            (foldedInside.endsWith(".p7s") || foldedInside.endsWith(".p7m") || foldedInside.endsWith(".p7c"))
        ) {
            return true
        }
        // Allow timestamp token entries
        if (foldedInside.contains("timestamp") && foldedInside.endsWith(".tst")) return true
        // Everything else is refused
        return false
    }

    private fun parseAndVerifyXml(
        xmlBytes: ByteArray,
        archiveEntries: Map<String, ByteArray>,
        dataEntryNames: Set<String>,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus,
    ): List<DocumentSignatureVerdict>? {
        val factory =
            DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                try {
                    setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                } catch (_: Throwable) {
                    // Ignored on platforms without this feature
                }
            }
        val builder = factory.newDocumentBuilder()
        val doc =
            try {
                builder.parse(ByteArrayInputStream(xmlBytes))
            } catch (_: Exception) {
                return null
            }

        val signatures = doc.getElementsByTagNameNS("*", "Signature")
        val totalSignatures = signatures.length
        val totalSignedInfo = doc.getElementsByTagNameNS("*", "SignedInfo").length
        if (totalSignatures == 0) {
            return if (totalSignedInfo > 0) null else emptyList()
        }
        if (totalSignedInfo != totalSignatures) {
            return null
        }

        val results = mutableListOf<DocumentSignatureVerdict>()
        for (i in 0 until signatures.length) {
            val sigElement = signatures.item(i) as? Element ?: continue
            val verdict =
                verifySingleSignature(sigElement, archiveEntries, dataEntryNames, trustAnchors, checkRevocation)
                    ?: return null
            results.add(verdict)
        }
        return results
    }

    private fun verifySingleSignature(
        sigElement: Element,
        archiveEntries: Map<String, ByteArray>,
        dataEntryNames: Set<String>,
        trustAnchors: List<X509Certificate>,
        checkRevocation: (X509Certificate) -> RevocationStatus,
    ): DocumentSignatureVerdict? {
        // --- XSW hardening: require exactly one ds:SignedInfo as a direct child of ds:Signature ---
        // Check this BEFORE certificate parsing so a forged document with duplicate
        // SignedInfo elements is rejected even if its certificate is unparseable.
        val signedInfoElem = findUniqueDirectChild(sigElement, NAMESPACE_DSIG, "SignedInfo") ?: return null

        // --- XSW hardening: reject documents with duplicate SignedInfo elements anywhere ---
        if (hasMultipleSignedInfoElements(sigElement)) {
            return null
        }

        val certNodes = sigElement.getElementsByTagNameNS("*", "X509Certificate")
        if (certNodes.length == 0) return null
        val certBase64 = certNodes.item(0).textContent.replace("\\s+".toRegex(), "")
        val certBytes =
            try {
                Base64.getDecoder().decode(certBase64)
            } catch (_: Exception) {
                return null
            }
        val signerCert =
            try {
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
            } catch (_: Exception) {
                return null
            }

        val timeNodes = sigElement.getElementsByTagNameNS("*", "SigningTime")
        val signingTime = if (timeNodes.length > 0) timeNodes.item(0).textContent.trim() else null

        val sigMethodElem = signedInfoElem.getElementsByTagNameNS("*", "SignatureMethod").item(0) as? Element
        val sigMethodUri = sigMethodElem?.getAttribute("Algorithm") ?: ""
        val (sigAlgorithm, digestAlgorithm) = mapAlgorithm(sigMethodUri)

        val refNodes = signedInfoElem.getElementsByTagNameNS("*", "Reference")
        var allDigestsMatch = true
        var hasFileReferences = false
        var hasSignedPropertiesRef = false
        val referencedFileNames = mutableSetOf<String>()

        for (j in 0 until refNodes.length) {
            val refElem = refNodes.item(j) as? Element ?: continue
            val uri = refElem.getAttribute("URI") ?: ""
            val digestValElem = refElem.getElementsByTagNameNS("*", "DigestValue").item(0) as? Element ?: continue
            val expectedDigest =
                try {
                    Base64.getDecoder().decode(digestValElem.textContent.replace("\\s+".toRegex(), ""))
                } catch (_: Exception) {
                    allDigestsMatch = false
                    continue
                }
            val digestMethodElem = refElem.getElementsByTagNameNS("*", "DigestMethod").item(0) as? Element
            val refDigestAlg = mapDigestAlgorithm(digestMethodElem?.getAttribute("Algorithm"))

            if (uri.startsWith("#")) {
                // --- Fix: validate #SignedProperties reference ---
                val refType = refElem.getAttribute("Type") ?: ""
                if (refType == SIGNED_PROPERTIES_TYPE) {
                    hasSignedPropertiesRef = true
                    val targetId = uri.removePrefix("#")
                    val signedPropsElem = findElementById(sigElement, targetId)
                    if (signedPropsElem == null) {
                        allDigestsMatch = false
                    } else {
                        // Verify that this element is in the correct namespace
                        if (signedPropsElem.namespaceURI != NAMESPACE_XADES ||
                            signedPropsElem.localName != "SignedProperties"
                        ) {
                            allDigestsMatch = false
                        } else {
                            // Verify that SignedProperties is a descendant of this Signature
                            if (!isDescendant(signedPropsElem, sigElement)) {
                                allDigestsMatch = false
                            } else {
                                val canonicalBytes = XmlCanonicalizer.canonicalize(signedPropsElem)
                                val computedDigest = MessageDigest.getInstance(refDigestAlg).digest(canonicalBytes)
                                if (!computedDigest.contentEquals(expectedDigest)) {
                                    allDigestsMatch = false
                                }
                            }
                        }
                    }
                }
                // Other # references (e.g. timestamp) are accepted but not separately verified here
            } else {
                hasFileReferences = true
                val decodedName =
                    try {
                        URLDecoder.decode(uri, "UTF-8")
                    } catch (_: Exception) {
                        uri
                    }
                referencedFileNames.add(decodedName)
                val fileContent = archiveEntries[decodedName] ?: archiveEntries[uri]
                if (fileContent == null) {
                    allDigestsMatch = false
                } else {
                    val computedDigest = MessageDigest.getInstance(refDigestAlg).digest(fileContent)
                    if (!computedDigest.contentEquals(expectedDigest)) {
                        allDigestsMatch = false
                    }
                }
            }
        }

        // --- Fix: require that #SignedProperties was present and verified ---
        if (!hasSignedPropertiesRef) {
            allDigestsMatch = false
        }

        // --- Fix: reject unsigned data entries not covered by any reference ---
        if (hasFileReferences) {
            val uncoveredEntries = dataEntryNames - referencedFileNames
            if (uncoveredEntries.isNotEmpty()) {
                allDigestsMatch = false
            }
        }

        // --- XSW hardening: reject documents with duplicate SignedInfo elements anywhere ---
        if (hasMultipleSignedInfoElements(sigElement)) {
            return DocumentSignatureVerdict(
                signerCommonName = commonNameOf(signerCert.subjectX500Principal.getName("RFC2253")),
                signerIssuer = commonNameOf(signerCert.issuerX500Principal.getName("RFC2253")),
                signerSerialNumber = serialNumberOf(signerCert),
                signingTime = signingTime,
                digestAlgorithm = digestAlgorithm,
                signatureAlgorithm = sigAlgorithm,
                coversWholeDocument = false,
                digestMatches = false,
                signatureValid = false,
                chainTrusted = false,
                hasSignatureTimestamp = false,
                isDocumentTimestamp = false,
                revocationStatus = RevocationStatus.UNCHECKED,
            )
        }

        val sigValNodes = sigElement.getElementsByTagNameNS("*", "SignatureValue")
        if (sigValNodes.length == 0) return null
        val sigValBase64 = sigValNodes.item(0).textContent.replace("\\s+".toRegex(), "")
        val sigValBytes =
            try {
                Base64.getDecoder().decode(sigValBase64)
            } catch (_: Exception) {
                return null
            }

        // --- XSW fix: canonicalize parsed SignedInfo element via Exclusive XML Canonicalization ---
        val signedInfoCanonical = XmlCanonicalizer.canonicalize(signedInfoElem)
        val signatureValid =
            verifySignatureBytes(
                algorithm = sigAlgorithm,
                publicKey = signerCert.publicKey,
                data = signedInfoCanonical,
                signatureBytes = sigValBytes,
            )

        val chainTrusted = isChainTrusted(signerCert, trustAnchors)
        val revocationStatus = if (chainTrusted) checkRevocation(signerCert) else RevocationStatus.UNCHECKED

        return DocumentSignatureVerdict(
            signerCommonName = commonNameOf(signerCert.subjectX500Principal.getName("RFC2253")),
            signerIssuer = commonNameOf(signerCert.issuerX500Principal.getName("RFC2253")),
            signerSerialNumber = serialNumberOf(signerCert),
            signingTime = signingTime,
            digestAlgorithm = digestAlgorithm,
            signatureAlgorithm = sigAlgorithm,
            coversWholeDocument = hasFileReferences,
            digestMatches = allDigestsMatch,
            signatureValid = signatureValid,
            chainTrusted = chainTrusted,
            hasSignatureTimestamp = sigElement.getElementsByTagNameNS("*", "EncapsulatedTimeStamp").length > 0,
            isDocumentTimestamp = false,
            revocationStatus = revocationStatus,
        )
    }

    /**
     * Find a unique direct child element in the given namespace with the given local name.
     * Returns null if there are zero or more than one such child (XSW hardening).
     */
    private fun findUniqueDirectChild(
        parent: Element,
        namespaceUri: String,
        localName: String,
    ): Element? {
        var found: Element? = null
        val children = parent.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            if (child is Element && child.namespaceURI == namespaceUri && child.localName == localName) {
                if (found != null) return null // Duplicate — refuse
                found = child
            }
        }
        return found
    }

    /**
     * Checks whether a Signature element contains multiple SignedInfo elements
     * anywhere in its subtree (even under different namespaces), which is a
     * hallmark of an XSW attack.
     */
    private fun hasMultipleSignedInfoElements(sigElement: Element): Boolean {
        val allSignedInfo = sigElement.getElementsByTagNameNS("*", "SignedInfo")
        return allSignedInfo.length > 1
    }

    /**
     * Checks whether [descendant] is a descendant of [ancestor] in the DOM tree.
     */
    private fun isDescendant(
        descendant: Node,
        ancestor: Node,
    ): Boolean {
        var current: Node? = descendant.parentNode
        while (current != null) {
            if (current === ancestor) return true
            current = current.parentNode
        }
        return false
    }

    /**
     * Find an element by its Id attribute within the subtree of [root].
     * Searches both `Id` and `id` attributes.
     */
    private fun findElementById(
        root: Element,
        id: String,
    ): Element? {
        // First try the standard getElementById (requires DTD/schema)
        // Fall back to manual traversal
        return findElementByIdRecursive(root, id)
    }

    private fun findElementByIdRecursive(
        element: Element,
        id: String,
    ): Element? {
        val idAttr = element.getAttribute("Id")
        val idAttrLower = element.getAttribute("id")
        if (idAttr == id || idAttrLower == id) return element
        val children = element.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            if (child is Element) {
                val found = findElementByIdRecursive(child, id)
                if (found != null) return found
            }
        }
        return null
    }

    private fun mapAlgorithm(uri: String): Pair<String, String> =
        when {
            uri.contains("rsa-sha384", ignoreCase = true) -> "SHA384withRSA" to "SHA-384"
            uri.contains("ecdsa-sha384", ignoreCase = true) -> "SHA384withECDSA" to "SHA-384"
            uri.contains("rsa-sha256", ignoreCase = true) -> "SHA256withRSA" to "SHA-256"
            uri.contains("ecdsa-sha256", ignoreCase = true) -> "SHA256withECDSA" to "SHA-256"
            uri.contains("rsa-sha512", ignoreCase = true) -> "SHA512withRSA" to "SHA-512"
            uri.contains("ecdsa-sha512", ignoreCase = true) -> "SHA512withECDSA" to "SHA-512"
            uri.contains("rsa-sha1", ignoreCase = true) -> "SHA1withRSA" to "SHA-1"
            else -> "SHA384withRSA" to "SHA-384"
        }

    private fun mapDigestAlgorithm(uri: String?): String =
        when {
            uri == null -> "SHA-384"
            uri.contains("sha384", ignoreCase = true) -> "SHA-384"
            uri.contains("sha256", ignoreCase = true) -> "SHA-256"
            uri.contains("sha512", ignoreCase = true) -> "SHA-512"
            uri.contains("sha1", ignoreCase = true) -> "SHA-1"
            else -> "SHA-384"
        }

    private fun isChainTrusted(
        certificate: X509Certificate,
        trustAnchors: List<X509Certificate>,
    ): Boolean =
        trustAnchors.any { anchor ->
            (
                certificate.issuerX500Principal == anchor.subjectX500Principal &&
                    runCatching { certificate.verify(anchor.publicKey) }.isSuccess
            ) ||
                (
                    certificate.subjectX500Principal == anchor.subjectX500Principal &&
                        certificate.encoded.contentEquals(anchor.encoded)
                )
        }

    private fun commonNameOf(rfc2253: String): String? {
        val match = "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)
        return match?.groupValues?.get(1)?.trim()
    }

    private fun serialNumberOf(certificate: X509Certificate): String? {
        val rfc2253 = certificate.subjectX500Principal.getName("RFC2253")
        val match = "(?:^|,)\\s*SERIALNUMBER=([^,]+)".toRegex(RegexOption.IGNORE_CASE).find(rfc2253)
        return match?.groupValues?.get(1)?.trim() ?: certificate.serialNumber?.toString(16)
    }

    private fun verifySignatureBytes(
        algorithm: String,
        publicKey: PublicKey,
        data: ByteArray,
        signatureBytes: ByteArray,
    ): Boolean {
        val candidates =
            if (algorithm.contains("ECDSA", ignoreCase = true)) {
                val der = p1363ToDer(signatureBytes)
                if (der != null && !der.contentEquals(signatureBytes)) {
                    listOf(der, signatureBytes)
                } else {
                    listOf(signatureBytes)
                }
            } else {
                listOf(signatureBytes)
            }
        for (candidate in candidates) {
            try {
                val sig = Signature.getInstance(algorithm)
                sig.initVerify(publicKey)
                sig.update(data)
                if (sig.verify(candidate)) return true
            } catch (_: Exception) {
                // Try next candidate
            }
        }
        return false
    }

    private fun p1363ToDer(sigBytes: ByteArray): ByteArray? {
        if (sigBytes.isEmpty() || sigBytes.size % 2 != 0) return null
        if (sigBytes[0] == 0x30.toByte()) return sigBytes
        val half = sigBytes.size / 2
        val rBytes = sigBytes.copyOfRange(0, half)
        val sBytes = sigBytes.copyOfRange(half, sigBytes.size)
        val r = BigInteger(1, rBytes)
        val s = BigInteger(1, sBytes)
        val rArr = r.toByteArray()
        val sArr = s.toByteArray()
        val totalLen = 2 + rArr.size + 2 + sArr.size
        val out = ByteArrayOutputStream()
        out.write(0x30)
        if (totalLen < 128) {
            out.write(totalLen)
        } else {
            out.write(0x81)
            out.write(totalLen)
        }
        out.write(0x02)
        out.write(rArr.size)
        out.write(rArr)
        out.write(0x02)
        out.write(sArr.size)
        out.write(sArr)
        return out.toByteArray()
    }
}
