package fi.refineid.android.asic

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.document.PdfValidationMaterial
import java.security.MessageDigest
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Base64

/** One file carried and signed inside an ASiC-E container. */
internal class AsicDataObject(
    val name: String,
    val content: ByteArray,
    val mimeType: String,
)

/** The two signed subtrees plus the certificate they name. */
internal class XadesPlan(
    val signedInfo: String,
    private val signedProperties: String,
    private val certificateDer: ByteArray,
    private val objects: List<AsicDataObject>,
) {
    /**
     * The finished `signatures0.xml` at level B-B, B-T, B-LT or, with
     * [archiveTimestampToken], B-LTA: the SignedInfo and SignedProperties
     * are inserted byte-for-byte as they were signed and digested, so a
     * verifier canonicalises them to the same bytes.
     */
    fun document(
        xmlSignature: ByteArray,
        timestampTokens: List<ByteArray> = emptyList(),
        material: PdfValidationMaterial? = null,
        archiveTimestampToken: ByteArray? = null,
    ): String {
        val properties = XadesUnsignedProperties.signatureProperties(timestampTokens, material).toMutableList()
        archiveTimestampToken?.let { token -> properties += XadesUnsignedProperties.archiveTimestampElement(token) }
        val out = StringBuilder()
        out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        out.append("<asic:XAdESSignatures xmlns:asic=\"").append(XadesSignature.NAMESPACE_ASIC).append("\">\n")
        out.append("<ds:Signature xmlns:ds=\"").append(XadesSignature.NAMESPACE_DSIG)
        out.append("\" Id=\"").append(XadesSignature.SIGNATURE_ID).append("\">\n")
        out.append(signedInfo).append("\n")
        out.append(XadesSignature.signatureValueElement(xmlSignature)).append("\n")
        out.append(keyInfo()).append("\n")
        out.append("<ds:Object>\n")
        out.append("<xades:QualifyingProperties xmlns:xades=\"").append(XadesSignature.NAMESPACE_XADES)
        out.append("\" Target=\"#").append(XadesSignature.SIGNATURE_ID).append("\">\n")
        out.append(signedProperties).append("\n")
        out.append(XadesUnsignedProperties.wrapped(properties))
        out.append("</xades:QualifyingProperties>\n")
        out.append("</ds:Object>\n")
        out.append("</ds:Signature>\n")
        out.append("</asic:XAdESSignatures>\n")
        return out.toString()
    }

    /**
     * The message imprint of an archive timestamp placed after the
     * unsigned properties [document] writes for the same arguments
     * (ETSI EN 319 132-1 V1.3.1 clause 5.5.2.3, not the distributed
     * case), digested with the signature timestamp's algorithm.
     *
     * In order: what each `ds:Reference` digests (every data object's
     * content, which a detached reference without transforms
     * dereferences to as an octet stream, then the canonical
     * SignedProperties), the canonical SignedInfo, SignatureValue and
     * KeyInfo, then every unsigned signature property in document
     * order. The only `ds:Object` holds the QualifyingProperties, so
     * step 6 adds nothing. Every element is written in exclusive
     * canonical form, so these are the document's own bytes.
     */
    fun archiveTimestampDigest(
        xmlSignature: ByteArray,
        timestampTokens: List<ByteArray>,
        material: PdfValidationMaterial,
    ): ByteArray {
        val digest = XadesSignature.timestampMessageDigest()
        objects.forEach { obj -> digest.update(obj.content) }
        digest.update(signedProperties.encodeToByteArray())
        digest.update(signedInfo.encodeToByteArray())
        digest.update(XadesSignature.signatureValueElement(xmlSignature).encodeToByteArray())
        digest.update(keyInfo().encodeToByteArray())
        for (property in XadesUnsignedProperties.signatureProperties(timestampTokens, material)) {
            digest.update(property.encodeToByteArray())
        }
        return digest.digest()
    }

    /**
     * `ds:KeyInfo` with the signer's certificate. It declares the `ds`
     * prefix itself, as the apex of a subset it digests alone must
     * (Exclusive XML Canonicalization 1.0 section 3).
     */
    private fun keyInfo(): String =
        "<ds:KeyInfo xmlns:ds=\"" + XadesSignature.NAMESPACE_DSIG + "\">\n<ds:X509Data>\n" +
            "<ds:X509Certificate>" + base64(certificateDer) + "</ds:X509Certificate>\n" +
            "</ds:X509Data>\n</ds:KeyInfo>"

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}

/**
 * XAdES signature assembly for ASiC-E, ported from the reference
 * implementation. There is no canonicaliser here on purpose: every
 * element is emitted already in Exclusive XML Canonicalization form —
 * never self-closed, attributes in canonical order, namespace
 * declarations repeated on each subtree digested alone, and text
 * escaped by the canonicalisation rules — so canonicalising the output
 * is the identity function and the bytes are digested where they stand.
 */
internal object XadesSignature {
    const val NAMESPACE_DSIG = "http://www.w3.org/2000/09/xmldsig#"
    const val NAMESPACE_XADES = "http://uri.etsi.org/01903/v1.3.2#"

    // XAdES 1.4.1, home of ArchiveTimeStamp (ETSI EN 319 132-1 V1.3.1 clause 5.5.2).
    const val NAMESPACE_XADES_141 = "http://uri.etsi.org/01903/v1.4.1#"
    const val NAMESPACE_ASIC = "http://uri.etsi.org/02918/v1.2.1#"
    const val DIGEST_METHOD_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    const val CANONICALIZATION_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
    const val SIGNATURE_METHOD_RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
    const val SIGNATURE_METHOD_ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"

    // The SignedProperties type has no minor version: it is a fixed
    // string in EN 319 132-1 and verifiers match it literally.
    const val SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"
    const val SIGNATURE_ID = "SIG-1"
    const val SIGNED_PROPERTIES_ID = "SIG-1-SIGNEDPROPS"
    const val SIGNATURE_VALUE_ID = "SIG-1-SIGVAL"
    const val ARCHIVE_TIMESTAMP_ID = "SIG-1-ATS-0"

    /** Joins [SIGNATURE_ID] and a signature timestamp's index into its Id. */
    const val SIGNATURE_TIMESTAMP_ID_INFIX = "-TS-"

    // The Java name of the digest DIGEST_METHOD_SHA384 identifies.
    private const val SHA384_ALGORITHM = "SHA-384"

    // Every timestamp of this signature, signature and archive alike, imprints SHA-384.
    private const val TIMESTAMP_DIGEST_ALGORITHM = SHA384_ALGORITHM

    /** Build the plan: the SignedProperties digest feeds the SignedInfo. */
    fun plan(
        profile: NativeCardKeyProfile,
        objects: List<AsicDataObject>,
        certificateDer: ByteArray,
        signedAt: Instant,
    ): XadesPlan {
        val signedProperties = signedProperties(objects, certificateDer, signedAt)
        val signedInfo = signedInfo(profile, objects, sha384(signedProperties.encodeToByteArray()))
        return XadesPlan(
            signedInfo = signedInfo,
            signedProperties = signedProperties,
            certificateDer = certificateDer,
            objects = objects,
        )
    }

    /** The SignedInfo: what the card signs, SHA-384 over these UTF-8 octets. */
    fun signedInfo(
        profile: NativeCardKeyProfile,
        objects: List<AsicDataObject>,
        signedPropertiesDigest: ByteArray,
    ): String {
        val out = StringBuilder()
        out.append("<ds:SignedInfo xmlns:ds=\"").append(NAMESPACE_DSIG).append("\">\n")
        out.append("<ds:CanonicalizationMethod Algorithm=\"").append(CANONICALIZATION_EXCLUSIVE)
        out.append("\"></ds:CanonicalizationMethod>\n")
        out.append("<ds:SignatureMethod Algorithm=\"").append(signatureMethod(profile))
        out.append("\"></ds:SignatureMethod>\n")
        objects.forEachIndexed { index, obj ->
            out.append("<ds:Reference Id=\"").append(referenceId(index)).append("\" ")
            out.append("URI=\"").append(escapeAttribute(obj.name)).append("\">\n")
            out.append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
            out.append("<ds:DigestValue>").append(base64(sha384(obj.content))).append("</ds:DigestValue>\n")
            out.append("</ds:Reference>\n")
        }
        out.append("<ds:Reference Id=\"").append(SIGNATURE_ID).append("-REF-SP\" ")
        out.append("Type=\"").append(SIGNED_PROPERTIES_TYPE).append("\" ")
        out.append("URI=\"#").append(SIGNED_PROPERTIES_ID).append("\">\n")
        out.append("<ds:Transforms>\n")
        out.append("<ds:Transform Algorithm=\"").append(CANONICALIZATION_EXCLUSIVE).append("\"></ds:Transform>\n")
        out.append("</ds:Transforms>\n")
        out.append("<ds:DigestMethod Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
        out.append("<ds:DigestValue>").append(base64(signedPropertiesDigest)).append("</ds:DigestValue>\n")
        out.append("</ds:Reference>\n")
        out.append("</ds:SignedInfo>")
        return out.toString()
    }

    /** The SignedProperties subtree, digested on its own into the SignedInfo. */
    fun signedProperties(
        objects: List<AsicDataObject>,
        certificateDer: ByteArray,
        signedAt: Instant,
    ): String {
        val out = StringBuilder()
        out.append("<xades:SignedProperties xmlns:xades=\"").append(NAMESPACE_XADES)
        out.append("\" Id=\"").append(SIGNED_PROPERTIES_ID).append("\">\n")
        out.append("<xades:SignedSignatureProperties>\n")
        out.append("<xades:SigningTime>").append(dateTime(signedAt)).append("</xades:SigningTime>\n")
        out.append("<xades:SigningCertificateV2>\n<xades:Cert>\n<xades:CertDigest>\n")
        out.append("<ds:DigestMethod xmlns:ds=\"").append(NAMESPACE_DSIG)
        out.append("\" Algorithm=\"").append(DIGEST_METHOD_SHA384).append("\"></ds:DigestMethod>\n")
        out.append("<ds:DigestValue xmlns:ds=\"").append(NAMESPACE_DSIG).append("\">")
        out.append(base64(sha384(certificateDer))).append("</ds:DigestValue>\n")
        out.append("</xades:CertDigest>\n</xades:Cert>\n</xades:SigningCertificateV2>\n")
        out.append("</xades:SignedSignatureProperties>\n")
        out.append("<xades:SignedDataObjectProperties>\n")
        objects.forEachIndexed { index, obj ->
            out.append("<xades:DataObjectFormat ObjectReference=\"#").append(referenceId(index)).append("\">\n")
            out.append("<xades:MimeType>").append(escapeText(obj.mimeType)).append("</xades:MimeType>\n")
            out.append("</xades:DataObjectFormat>\n")
        }
        out.append("</xades:SignedDataObjectProperties>\n")
        out.append("</xades:SignedProperties>")
        return out.toString()
    }

    /** The `ds:SignatureValue` element, canonical and standalone. */
    fun signatureValueElement(xmlSignature: ByteArray): String =
        "<ds:SignatureValue xmlns:ds=\"" + NAMESPACE_DSIG + "\" Id=\"" +
            SIGNATURE_VALUE_ID + "\">" + base64(xmlSignature) + "</ds:SignatureValue>"

    /** SHA-384 over the canonicalised SignatureValue element (EN 319 132-1). */
    fun timestampDigest(xmlSignature: ByteArray): ByteArray =
        sha384(signatureValueElement(xmlSignature).encodeToByteArray())

    /** A fresh digest of the algorithm every timestamp of this signature imprints. */
    fun timestampMessageDigest(): MessageDigest = MessageDigest.getInstance(TIMESTAMP_DIGEST_ALGORITHM)

    fun signatureMethod(profile: NativeCardKeyProfile): String =
        when (profile) {
            NativeCardKeyProfile.ECDSA_P256, NativeCardKeyProfile.ECDSA_P384 -> SIGNATURE_METHOD_ECDSA_SHA384
            NativeCardKeyProfile.RSA_2048, NativeCardKeyProfile.RSA_3072 -> SIGNATURE_METHOD_RSA_SHA384
        }

    fun referenceId(index: Int): String = SIGNATURE_ID + "-REF-" + index

    /**
     * Attribute-value escaping under Canonical XML: `&`, `<`, `"` and the
     * three whitespace controls — but never `>` and never `'`.
     */
    fun escapeAttribute(value: String): String {
        val out = StringBuilder(value.length)
        for (character in value) {
            when (character) {
                '&' -> out.append("&amp;")
                '<' -> out.append("&lt;")
                '"' -> out.append("&quot;")
                '\t' -> out.append("&#x9;")
                '\n' -> out.append("&#xA;")
                '\r' -> out.append("&#xD;")
                else -> out.append(character)
            }
        }
        return out.toString()
    }

    /** Text-node escaping under Canonical XML: `&`, `<`, `>` and `\r`. */
    fun escapeText(value: String): String {
        val out = StringBuilder(value.length)
        for (character in value) {
            when (character) {
                '&' -> out.append("&amp;")
                '<' -> out.append("&lt;")
                '>' -> out.append("&gt;")
                '\r' -> out.append("&#xD;")
                else -> out.append(character)
            }
        }
        return out.toString()
    }

    /**
     * Percent-encode a reference URI over UTF-8 bytes, leaving RFC 3986
     * unreserved characters and `/` untouched, uppercase hex elsewhere.
     */
    fun percentEncodePath(name: String): String {
        val out = StringBuilder(name.length)
        for (byte in name.encodeToByteArray()) {
            val value = byte.toInt() and BYTE_MASK
            if (value.toChar() in UNRESERVED) {
                out.append(value.toChar())
            } else {
                out.append('%').append(HEX[value ushr HALF_BYTE_BITS]).append(HEX[value and LOW_NIBBLE_MASK])
            }
        }
        return out.toString()
    }

    /** UTC xsd:dateTime, second precision, `Z` suffix, no fraction. */
    fun dateTime(instant: Instant): String =
        DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS))

    private fun sha384(content: ByteArray): ByteArray = MessageDigest.getInstance(SHA384_ALGORITHM).digest(content)

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private const val BYTE_MASK = 0xFF
    private const val HALF_BYTE_BITS = 4
    private const val LOW_NIBBLE_MASK = 0x0F
    private const val HEX = "0123456789ABCDEF"
    private val UNRESERVED =
        (('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '.', '_', '~', '/')).toSet()
}
