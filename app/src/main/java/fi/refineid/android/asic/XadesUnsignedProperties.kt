// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.asic

import fi.refineid.android.document.PdfValidationMaterial
import java.util.Base64

/**
 * The unsigned signature properties of the XAdES signature, written in
 * Exclusive XML Canonicalization form like the rest of [XadesSignature].
 */
internal object XadesUnsignedProperties {
    /**
     * The UnsignedProperties wrapping [properties], each followed by a
     * line break; empty when there are none.
     */
    fun wrapped(properties: List<String>): String {
        if (properties.isEmpty()) {
            return ""
        }
        val out = StringBuilder()
        out.append("<xades:UnsignedProperties>\n")
        out.append("<xades:UnsignedSignatureProperties>\n")
        properties.forEach { property -> out.append(property).append("\n") }
        out.append("</xades:UnsignedSignatureProperties>\n")
        out.append("</xades:UnsignedProperties>\n")
        return out.toString()
    }

    /**
     * The unsigned signature properties before any archive timestamp, in
     * schema order, each in exclusive canonical form and without a
     * trailing line break: one SignatureTimeStamp per token, then
     * CertificateValues, then RevocationValues with CRLs before OCSP
     * responses. Each is the apex of a subset an archive timestamp
     * canonicalises on its own (ETSI EN 319 132-1 V1.3.1 clause 5.5.2.3
     * step 5), so it declares the prefixes it visibly uses, and a
     * descendant declares one no ancestor in the subset uses.
     */
    fun signatureProperties(
        timestampTokens: List<ByteArray>,
        material: PdfValidationMaterial?,
    ): List<String> {
        val properties = mutableListOf<String>()
        timestampTokens.forEachIndexed { index, token ->
            properties +=
                "<xades:SignatureTimeStamp xmlns:xades=\"" + XadesSignature.NAMESPACE_XADES + "\" Id=\"" +
                timestampId(index) + "\">\n" +
                canonicalizationMethodElement() + "\n" +
                "<xades:EncapsulatedTimeStamp>" + base64(token) + "</xades:EncapsulatedTimeStamp>\n" +
                "</xades:SignatureTimeStamp>"
        }
        if (material != null && !material.isEmpty) {
            material.useCopies { certificates, ocspResponses, revocationLists ->
                if (certificates.isNotEmpty()) {
                    properties += certificateValues(certificates)
                }
                if (revocationLists.isNotEmpty() || ocspResponses.isNotEmpty()) {
                    properties += revocationValues(revocationLists, ocspResponses)
                }
            }
        }
        return properties
    }

    /**
     * The `xadesv141:ArchiveTimeStamp` holding [token], without a trailing
     * line break (ETSI EN 319 132-1 V1.3.1 clause 5.5.2; table 2 of clause
     * 6.3 requires this 1.4.1-namespace element at B-LTA and forbids the
     * 1.3.2-namespace one). Its EncapsulatedTimeStamp declares the 1.3.2
     * prefix itself, since no ancestor in this subset uses it.
     */
    fun archiveTimestampElement(token: ByteArray): String =
        "<xadesv141:ArchiveTimeStamp xmlns:xadesv141=\"" + XadesSignature.NAMESPACE_XADES_141 + "\" Id=\"" +
            XadesSignature.ARCHIVE_TIMESTAMP_ID + "\">\n" +
            canonicalizationMethodElement() + "\n" +
            "<xades:EncapsulatedTimeStamp xmlns:xades=\"" + XadesSignature.NAMESPACE_XADES + "\">" + base64(token) +
            "</xades:EncapsulatedTimeStamp>\n" +
            "</xadesv141:ArchiveTimeStamp>"

    private fun certificateValues(certificates: List<ByteArray>): String {
        val out = StringBuilder()
        out.append("<xades:CertificateValues xmlns:xades=\"").append(XadesSignature.NAMESPACE_XADES).append("\">\n")
        for (cert in certificates) {
            out
                .append("<xades:EncapsulatedX509Certificate>")
                .append(base64(cert))
                .append("</xades:EncapsulatedX509Certificate>\n")
        }
        out.append("</xades:CertificateValues>")
        return out.toString()
    }

    private fun revocationValues(
        revocationLists: List<ByteArray>,
        ocspResponses: List<ByteArray>,
    ): String {
        val out = StringBuilder()
        out.append("<xades:RevocationValues xmlns:xades=\"").append(XadesSignature.NAMESPACE_XADES).append("\">\n")
        if (revocationLists.isNotEmpty()) {
            out.append("<xades:CRLValues>\n")
            for (crl in revocationLists) {
                out
                    .append("<xades:EncapsulatedCRLValue>")
                    .append(base64(crl))
                    .append("</xades:EncapsulatedCRLValue>\n")
            }
            out.append("</xades:CRLValues>\n")
        }
        if (ocspResponses.isNotEmpty()) {
            out.append("<xades:OCSPValues>\n")
            for (ocsp in ocspResponses) {
                out
                    .append("<xades:EncapsulatedOCSPValue>")
                    .append(base64(ocsp))
                    .append("</xades:EncapsulatedOCSPValue>\n")
            }
            out.append("</xades:OCSPValues>\n")
        }
        out.append("</xades:RevocationValues>")
        return out.toString()
    }

    /** The exclusive canonicalisation a timestamp's verifier applies, declaring `ds` itself. */
    private fun canonicalizationMethodElement(): String =
        "<ds:CanonicalizationMethod xmlns:ds=\"" + XadesSignature.NAMESPACE_DSIG + "\" Algorithm=\"" +
            XadesSignature.CANONICALIZATION_EXCLUSIVE + "\"></ds:CanonicalizationMethod>"

    private fun timestampId(index: Int): String = XadesSignature.SIGNATURE_ID + "-TS-" + index

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}
