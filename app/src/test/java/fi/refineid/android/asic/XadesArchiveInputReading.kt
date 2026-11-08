// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipInputStream

/**
 * Reads a finished ASiC-E container back the way a verifier would and
 * recomputes the archive timestamp's input from the written bytes alone
 * (ETSI EN 319 132-1 V1.3.1 clause 5.5.2.3), independently of the
 * writer's own digest: every part is sliced out of `signatures0.xml`.
 */
internal object XadesArchiveInputReading {
    const val SIGNATURE_ENTRY = "META-INF/signatures0.xml"
    const val ARCHIVE_TIMESTAMP_START = "<xadesv141:ArchiveTimeStamp "
    const val ARCHIVE_TIMESTAMP_END = "</xadesv141:ArchiveTimeStamp>"
    const val UNSIGNED_SIGNATURE_PROPERTIES_START = "<xades:UnsignedSignatureProperties>\n"
    const val UNSIGNED_SIGNATURE_PROPERTIES_END = "</xades:UnsignedSignatureProperties>"
    const val CERTIFICATE_VALUES_END = "</xades:CertificateValues>"
    const val REVOCATION_VALUES_END = "</xades:RevocationValues>"
    private const val DIGEST_ALGORITHM = "SHA-384"
    private const val LINE_BREAK = "\n"
    private const val TAG_OPEN = "<"
    private const val TAG_CLOSE_OPEN = "</"
    private const val TAG_END = ">"
    private const val ATTRIBUTE_SEPARATOR = " "
    private const val SAME_DOCUMENT_REFERENCE = "#"
    private const val ENCAPSULATED_TIMESTAMP_END = "</xades:EncapsulatedTimeStamp>"
    private val DATA_REFERENCE = Regex("<ds:Reference Id=\"[^\"]*\" URI=\"([^\"]*)\">")

    fun entries(container: ByteArray): Map<String, ByteArray> {
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(container.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                entries[entry.name] = zip.readBytes()
                entry = zip.nextEntry
            }
        }
        return entries
    }

    fun signatureXml(container: ByteArray): String = checkNotNull(entries(container)[SIGNATURE_ENTRY]).decodeToString()

    /** SHA-384 over the archive input recomputed from [container]. */
    fun archiveDigest(container: ByteArray): ByteArray =
        MessageDigest.getInstance(DIGEST_ALGORITHM).digest(archiveInput(container))

    fun archiveInput(container: ByteArray): ByteArray {
        val entries = entries(container)
        val xml = checkNotNull(entries[SIGNATURE_ENTRY]).decodeToString()
        val signedInfo = element(xml, "ds:SignedInfo")
        val out = ByteArrayOutputStream()
        for (match in DATA_REFERENCE.findAll(signedInfo)) {
            val uri = unescapeAttribute(match.groupValues[1])
            check(!uri.startsWith(SAME_DOCUMENT_REFERENCE))
            out.write(checkNotNull(entries[uri]))
        }
        out.write(element(xml, "xades:SignedProperties").encodeToByteArray())
        out.write(signedInfo.encodeToByteArray())
        out.write(element(xml, "ds:SignatureValue").encodeToByteArray())
        out.write(element(xml, "ds:KeyInfo").encodeToByteArray())
        precedingUnsignedProperties(xml).forEach { property -> out.write(property.encodeToByteArray()) }
        return out.toByteArray()
    }

    /** Every top-level unsigned signature property before the archive timestamp, in document order. */
    fun precedingUnsignedProperties(xml: String): List<String> {
        val start = xml.indexOf(UNSIGNED_SIGNATURE_PROPERTIES_START) + UNSIGNED_SIGNATURE_PROPERTIES_START.length
        val end = xml.indexOf(ARCHIVE_TIMESTAMP_START)
        check(start > UNSIGNED_SIGNATURE_PROPERTIES_START.length && end > start)
        val properties = mutableListOf<String>()
        var position = start
        while (position < end) {
            check(xml.startsWith(TAG_OPEN, position))
            val nameEnd =
                listOf(xml.indexOf(ATTRIBUTE_SEPARATOR, position), xml.indexOf(TAG_END, position))
                    .filter { index -> index >= 0 }
                    .min()
            val name = xml.substring(position + TAG_OPEN.length, nameEnd)
            val close = TAG_CLOSE_OPEN + name + TAG_END
            val elementEnd = xml.indexOf(close, position) + close.length
            properties += xml.substring(position, elementEnd)
            check(xml.startsWith(LINE_BREAK, elementEnd))
            position = elementEnd + LINE_BREAK.length
        }
        return properties
    }

    /** The token inside the one archive timestamp. */
    fun archiveTimestampToken(xml: String): ByteArray {
        val archive = element(xml, "xadesv141:ArchiveTimeStamp")
        val tokenEnd = archive.indexOf(ENCAPSULATED_TIMESTAMP_END)
        val tokenStart = archive.lastIndexOf(TAG_END, tokenEnd) + TAG_END.length
        return Base64.getDecoder().decode(archive.substring(tokenStart, tokenEnd))
    }

    /** The first element named [name], from its start tag through its end tag. */
    fun element(
        xml: String,
        name: String,
    ): String {
        val start =
            xml.indexOf(TAG_OPEN + name + ATTRIBUTE_SEPARATOR).takeIf { index -> index >= 0 }
                ?: xml.indexOf(TAG_OPEN + name + TAG_END)
        check(start >= 0) { name }
        val close = TAG_CLOSE_OPEN + name + TAG_END
        return xml.substring(start, xml.indexOf(close, start) + close.length)
    }

    fun occurrences(
        xml: String,
        text: String,
    ): Int = xml.split(text).size - SINGLE_PIECE

    private const val SINGLE_PIECE = 1

    private fun unescapeAttribute(value: String): String =
        value
            .replace("&lt;", "<")
            .replace("&quot;", "\"")
            .replace("&#x9;", "\t")
            .replace("&#xA;", "\n")
            .replace("&#xD;", "\r")
            .replace("&amp;", "&")
}
