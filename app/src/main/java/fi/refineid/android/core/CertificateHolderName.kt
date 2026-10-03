package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

internal object CertificateHolderName {
    fun fromDer(der: ByteArray): String? =
        try {
            val factory = CertificateFactory.getInstance("X.509")
            val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
            val cn = "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1) ?: return null
            stripIdentifier(cn)
        } catch (_: Exception) {
            null
        }

    fun fromCertificate(certificate: NativeAuthenticationCertificate): String? =
        try {
            fromDer(certificate.copyDer())
        } catch (_: Exception) {
            null
        }

    internal fun stripIdentifier(cn: String): String {
        val tokens = cn.split(" ").filter { it.isNotBlank() }
        if (tokens.isNotEmpty() &&
            tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
            tokens.last().any { it.isDigit() }
        ) {
            val nameTokens = tokens.dropLast(1)
            if (nameTokens.isNotEmpty()) {
                return nameTokens.joinToString(" ")
            }
        }
        return cn
    }
}
