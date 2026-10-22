@file:Suppress(
    "TooGenericExceptionCaught",
    "SwallowedException",
    "MagicNumber",
    "MaxLineLength",
)

package fi.refineid.android.rapp

import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeAuthenticationSignature
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.P384EcdsaSignature
import fi.refineid.android.core.Pin1Submission
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappSignatureAlgorithm
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * AuthenticationCardService backed by a paired remote proxy phone over RAPP.
 */
internal class RemoteAuthenticationCardService(
    private val scope: CoroutineScope,
    private val remoteCardModel: RemoteCardModel,
) : AuthenticationCardService {
    override val requiresLocalPin: Boolean
        get() = false

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
        val cachedDer = remoteCardModel.cachedCertificateDer
        if (cachedDer != null) {
            val keyProfile = determineKeyProfile(cachedDer)
            onResult(NativeAuthenticationCertificate(keyProfile = keyProfile, ownedDer = cachedDer.copyOf()))
            return
        }

        scope.launch(Dispatchers.IO) {
            val client = remoteCardModel.createRequesterClient()
            val certDer = client?.readAuthenticationCertificate()?.toWire()
            if (certDer != null) {
                remoteCardModel.setCertificateDer(certDer)
                val keyProfile = determineKeyProfile(certDer)
                mainHandler.post {
                    onResult(NativeAuthenticationCertificate(keyProfile = keyProfile, ownedDer = certDer.copyOf()))
                }
            } else {
                mainHandler.post { onResult(null) }
            }
        }
    }

    override fun signAuthenticationMessage(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult {
        pin1.close()
        val digest =
            try {
                MessageDigest.getInstance(algorithm.digest.jcaName).digest(message)
            } catch (_: Exception) {
                return AuthenticationSignResult.Failure(AuthenticationSignFailure.BRIDGE_ERROR)
            }
        return signDigest(algorithm, digest)
    }

    override fun signAuthenticationDigest(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult {
        pin1.close()
        return signDigest(algorithm, digest)
    }

    private fun signDigest(
        algorithm: AuthenticationSigningAlgorithm,
        digest: ByteArray,
    ): AuthenticationSignResult {
        val client =
            remoteCardModel.createRequesterClient()
                ?: return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)

        val rappAlgorithm =
            when (algorithm) {
                AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> RappSignatureAlgorithm.ECDSA_SHA256
                AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> RappSignatureAlgorithm.ECDSA_SHA384
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> RappSignatureAlgorithm.RSA_PKCS1_SHA256
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384 -> RappSignatureAlgorithm.RSA_PKCS1_SHA384
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512 -> RappSignatureAlgorithm.RSA_PKCS1_SHA512
                AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> RappSignatureAlgorithm.RSA_PSS_SHA256
                else -> return AuthenticationSignResult.Failure(AuthenticationSignFailure.KEY_PROFILE_MISMATCH)
            }

        val rappKeyProfile =
            when (algorithm.keyProfile) {
                NativeCardKeyProfile.ECDSA_P384 -> RappCardKeyProfile.ECDSA_P384
                NativeCardKeyProfile.ECDSA_P256 -> RappCardKeyProfile.ECDSA_P256
                NativeCardKeyProfile.RSA_3072 -> RappCardKeyProfile.RSA3072
                NativeCardKeyProfile.RSA_2048 -> RappCardKeyProfile.RSA2048
            }

        val wireSig =
            runBlocking(Dispatchers.IO) {
                client.browserAuthenticate(
                    origin = "Web Browser",
                    keyProfile = rappKeyProfile,
                    algorithm = rappAlgorithm,
                    digest = digest,
                )
            } ?: return AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)

        val rawSig =
            if (algorithm.keyProfile == NativeCardKeyProfile.ECDSA_P384) {
                try {
                    P384EcdsaSignature.fromDer(wireSig)
                } catch (_: Exception) {
                    return AuthenticationSignResult.Failure(AuthenticationSignFailure.BRIDGE_ERROR)
                }
            } else {
                wireSig
            }

        return AuthenticationSignResult.Success(
            NativeAuthenticationSignature(
                algorithm = algorithm,
                ownedBytes = rawSig,
            ),
        )
    }

    private fun determineKeyProfile(certDer: ByteArray): NativeCardKeyProfile =
        try {
            val cert =
                CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(certDer.inputStream()) as? X509Certificate
            when (val pub = cert?.publicKey) {
                is ECPublicKey -> {
                    val fieldSize =
                        pub.params
                            ?.curve
                            ?.field
                            ?.fieldSize ?: 384
                    if (fieldSize <= 256) NativeCardKeyProfile.ECDSA_P256 else NativeCardKeyProfile.ECDSA_P384
                }

                is RSAPublicKey -> {
                    val bitLength = pub.modulus?.bitLength() ?: 3072
                    if (bitLength <= 2048) NativeCardKeyProfile.RSA_2048 else NativeCardKeyProfile.RSA_3072
                }

                else -> {
                    NativeCardKeyProfile.ECDSA_P384
                }
            }
        } catch (_: Exception) {
            NativeCardKeyProfile.ECDSA_P384
        }
}
