package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale

internal data class PersonCardDetails(
    val holderName: String,
    val fullName: String,
    val identifier: String? = null,
    val dateOfBirth: String? = null,
    val nationality: String = "Suomi (FIN)",
    val issuedDate: String? = null,
    val expiryDate: String? = null,
    val issuer: String? = null,
    val signatureAlgorithm: String? = null,
) {
    companion object {
        fun fromDer(der: ByteArray): PersonCardDetails? =
            try {
                val factory = CertificateFactory.getInstance("X.509")
                val x509 = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                val rfc2253 = x509.subjectX500Principal.getName("RFC2253")
                val cn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1)
                        ?: return null

                val tokens = cn.split(" ").filter { it.isNotBlank() }
                val (nameTokens, idToken) =
                    if (tokens.isNotEmpty() &&
                        tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                        tokens.last().any { it.isDigit() }
                    ) {
                        tokens.dropLast(1) to tokens.last()
                    } else {
                        tokens to null
                    }
                val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else cn

                val countryCode =
                    "(?:^|,)\\s*C=([^,]+)".toRegex().find(rfc2253)?.groupValues?.get(1) ?: "FI"
                val nationalityStr =
                    when (countryCode.uppercase(Locale.ROOT)) {
                        "FI" -> "Suomi (FIN)"
                        "SE" -> "Ruotsi (SWE)"
                        "EE" -> "Viro (EST)"
                        "NO" -> "Norja (NOR)"
                        else -> countryCode
                    }

                val issuerRfc = x509.issuerX500Principal.getName("RFC2253")
                val issuerCn =
                    "(?:^|,)\\s*CN=([^,]+)".toRegex().find(issuerRfc)?.groupValues?.get(1)
                        ?: "Digi- ja väestötietovirasto (DVV)"
                val cleanIssuer =
                    if (issuerCn.contains("VRK", ignoreCase = true) ||
                        issuerCn.contains("DVV", ignoreCase = true) ||
                        issuerCn.contains("FINEID", ignoreCase = true)
                    ) {
                        "Digi- ja väestötietovirasto (DVV)"
                    } else {
                        issuerCn
                    }

                val dateFormat = SimpleDateFormat("d.M.yyyy", Locale.ROOT)
                val issued =
                    try {
                        dateFormat.format(x509.notBefore)
                    } catch (_: Exception) {
                        null
                    }
                val expires =
                    try {
                        dateFormat.format(x509.notAfter)
                    } catch (_: Exception) {
                        null
                    }

                PersonCardDetails(
                    holderName = CertificateHolderName.lineFromSubject(x509.subjectX500Principal) ?: formattedName,
                    fullName = formattedName,
                    identifier = idToken,
                    dateOfBirth = null,
                    nationality = nationalityStr,
                    issuedDate = issued,
                    expiryDate = expires,
                    issuer = cleanIssuer,
                    signatureAlgorithm = x509.sigAlgName,
                )
            } catch (_: Exception) {
                null
            }

        fun fromHolderName(holderName: String): PersonCardDetails {
            val tokens = holderName.split(" ").filter { it.isNotBlank() }
            val (nameTokens, idToken) =
                if (tokens.isNotEmpty() &&
                    tokens.last().matches("[0-9A-Za-z]{6,12}".toRegex()) &&
                    tokens.last().any { it.isDigit() }
                ) {
                    tokens.dropLast(1) to tokens.last()
                } else {
                    tokens to null
                }
            val formattedName = if (nameTokens.isNotEmpty()) nameTokens.joinToString(" ") else holderName

            return PersonCardDetails(
                holderName = holderName,
                fullName = formattedName,
                identifier = idToken,
                dateOfBirth = null,
                nationality = "Suomi (FIN)",
                issuedDate = null,
                expiryDate = null,
                issuer = "Digi- ja väestötietovirasto (DVV)",
                signatureAlgorithm = "ECDSA_P384 / SHA-384",
            )
        }
    }
}
