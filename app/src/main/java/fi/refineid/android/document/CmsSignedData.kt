package fi.refineid.android.document

import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * A parsed CMS SignedData taken from a detached PAdES signature. Only
 * the fields an independent verifier needs are retained; every value
 * comes from the untrusted document and is validated by shape before
 * use (RFC 5652).
 */
internal class CmsSignedData private constructor(
    private val certificates: List<X509Certificate>,
    private val signerIssuer: X500Principal,
    private val signerSerial: BigInteger,
    val digestJcaName: String,
    val signatureJcaName: String?,
    val messageDigest: ByteArray?,
    val signingTime: String?,
    val signedAttributesForVerification: ByteArray,
    val signatureBytes: ByteArray,
    val hasSignatureTimestamp: Boolean,
    val isDocumentTimestamp: Boolean = false,
) {
    fun signerCertificate(): X509Certificate? =
        certificates.firstOrNull { certificate ->
            certificate.serialNumber == signerSerial &&
                certificate.issuerX500Principal == signerIssuer
        } ?: certificates.singleOrNull()

    fun allCertificates(): List<X509Certificate> = certificates

    companion object {
        fun parse(cms: ByteArray): CmsSignedData? =
            try {
                parseChecked(cms)
            } catch (_: RuntimeException) {
                null
            }

        private fun parseChecked(cms: ByteArray): CmsSignedData? {
            val outer = DerReader(cms)
            val contentInfo = outer.next() ?: return null
            val ci = outer.children(contentInfo)
            ci.next() ?: return null // contentType OID (signedData)
            val explicit = ci.next() ?: return null // [0] EXPLICIT SignedData
            val sdReader = ci.children(explicit)
            val signedData = sdReader.next() ?: return null
            val sd = sdReader.children(signedData)
            sd.next() ?: return null // version
            sd.next() ?: return null // digestAlgorithms

            val remaining = generateSequence { sd.next() }.toList()
            val encapContentInfo = remaining.firstOrNull { it.tag == DerValues.TAG_SEQUENCE }
            var isDocumentTimestamp = false
            var tstMessageDigest: ByteArray? = null
            var tstDigestJcaName: String? = null
            var tstInfoBytes: ByteArray? = null
            if (encapContentInfo != null) {
                val eci = sd.children(encapContentInfo)
                val contentTypeElem = eci.next()
                if (contentTypeElem != null && oidOf(sd.content(contentTypeElem)) == ID_CT_TST_INFO) {
                    isDocumentTimestamp = true
                    val eContent = eci.next()
                    if (eContent != null) {
                        val contentBytes = sd.content(eContent)
                        val contentReader = DerReader(contentBytes)
                        val contentElem = contentReader.next()
                        val tstBytes =
                            if (contentElem?.tag == DerValues.TAG_OCTET_STRING) {
                                contentReader.content(contentElem)
                            } else {
                                contentBytes
                            }
                        val (digest, jca) = parseTstMessageImprint(tstBytes)
                        tstMessageDigest = digest
                        tstDigestJcaName = jca
                        tstInfoBytes = tstBytes
                    }
                }
            }

            val certificatesElement =
                remaining.firstOrNull { it.tag == DerValues.TAG_CONTEXT_0_CONSTRUCTED }
            val signerInfos =
                remaining.firstOrNull { it.tag == DerValues.TAG_SET } ?: return null

            val certificates =
                certificatesElement?.let { element ->
                    parseCertificates(sd.children(element))
                } ?: emptyList()

            val signerInfoReader = sd.children(signerInfos)
            val signerInfo = signerInfoReader.next() ?: return null
            return parseSignerInfo(
                si = signerInfoReader.children(signerInfo),
                certificates = certificates,
                isDocumentTimestamp = isDocumentTimestamp,
                tstMessageDigest = tstMessageDigest,
                tstDigestJcaName = tstDigestJcaName,
                tstInfoBytes = tstInfoBytes,
            )
        }

        private fun parseTstMessageImprint(tstBytes: ByteArray): Pair<ByteArray?, String?> =
            try {
                val reader = DerReader(tstBytes)
                val seq = reader.next()
                if (seq != null) {
                    val children = reader.children(seq)
                    children.next() // version
                    children.next() // policy
                    val msgImprint = children.next()
                    if (msgImprint != null) {
                        val miChildren = reader.children(msgImprint)
                        val hashAlgo = miChildren.next()
                        val hashAlgoOid = hashAlgo?.let { firstOid(reader.children(it)) }
                        val hashedMessage = miChildren.next()
                        val digest = hashedMessage?.let { reader.content(it) }
                        val jcaName = hashAlgoOid?.let(::digestJcaName)
                        digest to jcaName
                    } else {
                        null to null
                    }
                } else {
                    null to null
                }
            } catch (_: RuntimeException) {
                null to null
            }

        private fun parseCertificates(reader: DerReader): List<X509Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            return generateSequence { reader.next() }
                .mapNotNull { element ->
                    runCatching {
                        factory.generateCertificate(reader.raw(element).inputStream()) as X509Certificate
                    }.getOrNull()
                }.toList()
        }

        private fun parseSignerInfo(
            si: DerReader,
            certificates: List<X509Certificate>,
            isDocumentTimestamp: Boolean,
            tstMessageDigest: ByteArray?,
            tstDigestJcaName: String?,
            tstInfoBytes: ByteArray?,
        ): CmsSignedData? {
            si.next() ?: return null // version
            val sid = si.next() ?: return null // issuerAndSerialNumber
            val digestAlgorithm = si.next() ?: return null
            val signedAttributes = si.next() ?: return null
            if (signedAttributes.tag != DerValues.TAG_CONTEXT_0_CONSTRUCTED) {
                return null // PAdES requires signed attributes
            }
            val signatureAlgorithm = si.next() ?: return null
            val signature = si.next() ?: return null
            val unsignedAttributes = si.next()

            val (issuer, serial) = parseSignerIdentifier(si.children(sid), sid) ?: return null
            val digestOid = firstOid(si.children(digestAlgorithm)) ?: return null
            val standardDigestJcaName = digestJcaName(digestOid) ?: return null
            val signatureOid = firstOid(si.children(signatureAlgorithm)) ?: return null

            val attributes = parseSignedAttributes(si.children(signedAttributes))
            if (isDocumentTimestamp) {
                val contentDigest =
                    attributes.messageDigest
                        ?: return null
                if (attributes.contentType != ID_CT_TST_INFO) {
                    return null
                }
                val authenticated = tstInfoBytes ?: return null
                val contentDigestMatches =
                    MessageDigest.getInstance(standardDigestJcaName).digest(authenticated).contentEquals(contentDigest)
                if (!contentDigestMatches) {
                    return null
                }
            } else if (attributes.contentType != null && attributes.contentType != ID_DATA) {
                return null
            }
            val effectiveMessageDigest =
                if (isDocumentTimestamp && tstMessageDigest != null) {
                    tstMessageDigest
                } else {
                    attributes.messageDigest
                }
            val effectiveDigestJcaName =
                if (isDocumentTimestamp && tstDigestJcaName != null) {
                    tstDigestJcaName
                } else {
                    standardDigestJcaName
                }

            return CmsSignedData(
                certificates = certificates,
                signerIssuer = issuer,
                signerSerial = serial,
                digestJcaName = effectiveDigestJcaName,
                signatureJcaName = signatureJcaName(signatureOid, digestOid),
                messageDigest = effectiveMessageDigest,
                signingTime = attributes.signingTime,
                signedAttributesForVerification =
                    DerEncoder.retagged(si.raw(signedAttributes), DerValues.TAG_SET),
                signatureBytes = si.content(signature),
                hasSignatureTimestamp =
                    unsignedAttributes?.let { element ->
                        containsSignatureTimestamp(si.children(element))
                    } ?: false,
                isDocumentTimestamp = isDocumentTimestamp,
            )
        }

        private fun parseSignerIdentifier(
            reader: DerReader,
            sid: DerReader.Element,
        ): Pair<X500Principal, BigInteger>? {
            if (sid.tag != DerValues.TAG_SEQUENCE) {
                return null // subjectKeyIdentifier form is not used by FINEID
            }
            val issuer = reader.next() ?: return null
            val serial = reader.next() ?: return null
            val issuerPrincipal = runCatching { X500Principal(reader.raw(issuer)) }.getOrNull() ?: return null
            return issuerPrincipal to BigInteger(reader.content(serial))
        }

        private data class SignedAttributeFacts(
            val messageDigest: ByteArray?,
            val signingTime: String?,
            val contentType: String?,
        )

        private fun parseSignedAttributes(reader: DerReader): SignedAttributeFacts {
            var messageDigest: ByteArray? = null
            var signingTime: String? = null
            var contentType: String? = null
            generateSequence { reader.next() }.forEach { attribute ->
                val attributeReader = reader.children(attribute)
                val typeElement = attributeReader.next() ?: return@forEach
                val values = attributeReader.next() ?: return@forEach
                when (oidOf(attributeReader.content(typeElement))) {
                    QualifiedCmsOids.MESSAGE_DIGEST -> {
                        val valueReader = attributeReader.children(values)
                        valueReader.next()?.let { messageDigest = attributeReader.content(it) }
                    }

                    SIGNING_TIME -> {
                        val valueReader = attributeReader.children(values)
                        valueReader.next()?.let { signingTime = attributeReader.content(it).decodeToString() }
                    }

                    CONTENT_TYPE -> {
                        val valueReader = attributeReader.children(values)
                        valueReader.next()?.let { contentType = oidOf(attributeReader.content(it)) }
                    }

                    else -> {
                        // Other signed attributes are not read here.
                    }
                }
            }
            return SignedAttributeFacts(messageDigest, signingTime, contentType)
        }

        private fun containsSignatureTimestamp(reader: DerReader): Boolean =
            generateSequence { reader.next() }.any { attribute ->
                val attributeReader = reader.children(attribute)
                val typeElement = attributeReader.next()
                typeElement != null &&
                    oidOf(attributeReader.content(typeElement)) == QualifiedCmsOids.SIGNATURE_TIMESTAMP_TOKEN
            }

        private fun firstOid(reader: DerReader): String? {
            val element = reader.next() ?: return null
            if (element.tag != DerValues.TAG_OBJECT_IDENTIFIER) {
                return null
            }
            return oidOf(reader.content(element))
        }

        private fun digestJcaName(oid: String): String? =
            when (oid) {
                QualifiedCmsOids.SHA384 -> "SHA-384"
                SHA256 -> "SHA-256"
                else -> null
            }

        private fun signatureJcaName(
            signatureOid: String,
            digestOid: String,
        ): String? =
            when (signatureOid) {
                QualifiedCmsOids.ECDSA_WITH_SHA384 -> {
                    "SHA384withECDSA"
                }

                QualifiedCmsOids.SHA384_WITH_RSA -> {
                    "SHA384withRSA"
                }

                RSA_ENCRYPTION -> {
                    when (digestOid) {
                        QualifiedCmsOids.SHA384 -> "SHA384withRSA"
                        SHA256 -> "SHA256withRSA"
                        else -> null
                    }
                }

                else -> {
                    null
                }
            }

        /** Decode an OID's content octets into dotted form (X.690 §8.19). */
        private fun oidOf(content: ByteArray): String? {
            if (content.isEmpty()) {
                return null
            }
            val arcs = StringBuilder()
            val first = content[0].toInt() and 0xFF
            arcs.append(first / OID_FIRST_ARC_SCALE).append('.').append(first % OID_FIRST_ARC_SCALE)
            var value = 0L
            var pending = false
            for (index in 1 until content.size) {
                val byte = content[index].toInt() and 0xFF
                value = (value shl OID_ARC_SHIFT) or (byte and OID_ARC_MASK).toLong()
                pending = true
                if (byte and OID_CONTINUATION_BIT == 0) {
                    arcs.append('.').append(value)
                    value = 0L
                    pending = false
                }
            }
            return if (pending) null else arcs.toString()
        }

        private const val SIGNING_TIME = "1.2.840.113549.1.9.5"
        private const val CONTENT_TYPE = "1.2.840.113549.1.9.3"
        private const val ID_DATA = "1.2.840.113549.1.7.1"
        private const val SHA256 = "2.16.840.1.101.3.4.2.1"
        private const val RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
        private const val ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
        private const val OID_FIRST_ARC_SCALE = 40
        private const val OID_ARC_SHIFT = 7
        private const val OID_ARC_MASK = 0x7F
        private const val OID_CONTINUATION_BIT = 0x80
    }
}
