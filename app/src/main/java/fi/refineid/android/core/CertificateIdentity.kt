package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * The holder identity a paired computer is told, read off the
 * authentication certificate: the holder line, the card number, and
 * the validity window as calendar dates in UTC.
 */
internal data class CertificateIdentity(
    val holderName: String,
    val cardId: String,
    val issuanceDate: String,
    val expirationDate: String,
) {
    companion object {
        private const val SERIAL_NUMBER_OID = "2.5.4.5"
        private const val SERIAL_NUMBER_KEYWORD = "SERIALNUMBER"
        private val calendarDate = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC)
        private val serialNumberPattern = "(?:^|,)\\s*$SERIAL_NUMBER_KEYWORD=([^,]+)".toRegex()
        private val commonNamePattern = "(?:^|,)\\s*CN=([^,]+)".toRegex()

        fun fromDer(der: ByteArray): CertificateIdentity? =
            try {
                val factory = CertificateFactory.getInstance("X.509")
                val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                val holderName = CertificateHolderName.fromDer(der)
                val cardId = subjectIdentifier(x509)
                if (holderName == null || cardId == null) {
                    null
                } else {
                    CertificateIdentity(
                        holderName = holderName,
                        cardId = cardId,
                        issuanceDate = calendarDate.format(x509.notBefore.toInstant()),
                        expirationDate = calendarDate.format(x509.notAfter.toInstant()),
                    )
                }
            } catch (_: Exception) {
                null
            }

        /** The subject's serial number, or the identifier its common name ends with. */
        private fun subjectIdentifier(x509: X509Certificate): String? {
            val keywords = mapOf(SERIAL_NUMBER_OID to SERIAL_NUMBER_KEYWORD)
            val rfc2253 = x509.subjectX500Principal.getName("RFC2253", keywords)
            serialNumberPattern
                .find(rfc2253)
                ?.groupValues
                ?.get(1)
                ?.let { return it }
            val cn = commonNamePattern.find(rfc2253)?.groupValues?.get(1) ?: return null
            return CertificateHolderName.trailingIdentifier(cn)
        }
    }
}
