package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * The holder as the authentication certificate's subject names them.
 *
 * The holder name is the common name without its trailing identifier;
 * a paired computer is sent that. The holder line a screen shows adds
 * the organisation after a comma when the subject names one, as an
 * organisation card's certificate does; a citizen certificate names none.
 */
internal object CertificateHolderName {
    /** The holder name a paired computer is sent. */
    fun fromDer(der: ByteArray): String? = subjectOf(der)?.let(::nameFromSubject)

    /** The holder line a screen shows. */
    fun lineFromDer(der: ByteArray): String? = subjectOf(der)?.let(::lineFromSubject)

    /** The holder line a screen shows, from the card's certificate. */
    fun lineFromCertificate(certificate: NativeAuthenticationCertificate): String? =
        try {
            lineFromDer(certificate.copyDer())
        } catch (_: Exception) {
            null
        }

    internal fun nameFromSubject(subject: X500Principal): String? {
        val rfc2253 = subject.getName(X500Principal.RFC2253)
        val cn = COMMON_NAME.find(rfc2253)?.groupValues?.get(1) ?: return null
        return stripIdentifier(cn)
    }

    internal fun lineFromSubject(subject: X500Principal): String? {
        val name = nameFromSubject(subject) ?: return null
        val organization = organizationName(subject) ?: return name
        return name + ORGANIZATION_SEPARATOR + organization
    }

    /** The organisation the subject names, verbatim, or null when it names none. */
    internal fun organizationName(subject: X500Principal): String? {
        val rfc2253 = subject.getName(X500Principal.RFC2253)
        val escaped = ORGANIZATION_NAME.find(rfc2253)?.groupValues?.get(1) ?: return null
        return ESCAPED_CHARACTER.replace(escaped, "$1").takeIf { it.isNotEmpty() }
    }

    private fun subjectOf(der: ByteArray): X500Principal? =
        try {
            val factory = CertificateFactory.getInstance("X.509")
            val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            x509.subjectX500Principal
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
    private val COMMON_NAME = "(?:^|,)\\s*CN=([^,]+)".toRegex()

    /** An RFC 2253 organizationName value, its backslash escapes kept. */
    private val ORGANIZATION_NAME = "(?:^|,)\\s*O=((?:[^,\\\\]|\\\\.)*)".toRegex()
    private val ESCAPED_CHARACTER = "\\\\(.)".toRegex()
    private const val ORGANIZATION_SEPARATOR = ", "
}
