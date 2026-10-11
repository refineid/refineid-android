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
        if (trailingIdentifier(tokens) != null) {
            return tokens.dropLast(1).joinToString(" ")
        }
        return cn
    }

    /** The identifier a common name ends with, after at least one name token. */
    internal fun trailingIdentifier(cn: String): String? = trailingIdentifier(cn.split(" ").filter { it.isNotBlank() })

    private fun trailingIdentifier(tokens: List<String>): String? {
        if (tokens.size < 2) return null
        val last = tokens.last()
        val isIdentifier = last.matches(IDENTIFIER_TOKEN) && last.any { it.isDigit() }
        return if (isIdentifier) last else null
    }

    private val IDENTIFIER_TOKEN = "[0-9A-Za-z]{6,12}".toRegex()
}
