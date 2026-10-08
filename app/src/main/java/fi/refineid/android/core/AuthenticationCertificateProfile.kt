package fi.refineid.android.core

import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/** Copies public primed material; the browser independently validates the certificate chain. */
internal fun primedAuthenticationCertificate(der: ByteArray): NativeAuthenticationCertificate? =
    try {
        val certificate =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
        val key = certificate?.publicKey
        val profile =
            when (key) {
                is RSAPublicKey -> {
                    when (key.modulus.bitLength()) {
                        RSA_2048_BITS -> NativeCardKeyProfile.RSA_2048
                        RSA_3072_BITS -> NativeCardKeyProfile.RSA_3072
                        else -> null
                    }
                }

                is ECPublicKey -> {
                    when (key.params.curve.field.fieldSize) {
                        EC_256_BITS -> NativeCardKeyProfile.ECDSA_P256
                        EC_384_BITS -> NativeCardKeyProfile.ECDSA_P384
                        else -> null
                    }
                }

                else -> {
                    null
                }
            }
        profile?.let { NativeAuthenticationCertificate(it, der.copyOf()) }
    } catch (_: CertificateException) {
        null
    } finally {
        der.fill(0)
    }

private const val RSA_2048_BITS = 2048
private const val RSA_3072_BITS = 3072
private const val EC_256_BITS = 256
private const val EC_384_BITS = 384
