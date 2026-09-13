package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH
import fi.refineid.android.core.P384EcdsaSignature
import java.security.InvalidKeyException
import java.security.InvalidParameterException
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.SignatureException
import java.security.SignatureSpi
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** JCA provider consumed by Chromium's Android client-certificate bridge. */
@Suppress("DEPRECATION")
internal class ReFineIdCardProvider : Provider(NAME, VERSION, DESCRIPTION) {
    init {
        register(
            jcaName = JCA_SHA256_WITH_RSA,
            implementation = Sha256WithRsaCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA256_WITH_RSA_PSS,
            implementation = Sha256WithRsaPssCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA384_WITH_RSA,
            implementation = Sha384WithRsaCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA384_WITH_RSA_PSS,
            implementation = Sha384WithRsaPssCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA512_WITH_RSA,
            implementation = Sha512WithRsaCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA512_WITH_RSA_PSS,
            implementation = Sha512WithRsaPssCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA256_WITH_ECDSA,
            implementation = Sha256WithEcdsaCardSignature::class.java,
        )
        register(
            jcaName = JCA_SHA384_WITH_ECDSA,
            implementation = Sha384WithEcdsaCardSignature::class.java,
        )
    }

    private fun register(
        jcaName: String,
        implementation: Class<out SignatureSpi>,
    ) {
        putService(
            Service(
                this,
                SIGNATURE_SERVICE,
                jcaName,
                implementation.name,
                emptyList(),
                mapOf(SUPPORTED_KEY_CLASSES_ATTRIBUTE to CardBackedPrivateKey::class.java.name),
            ),
        )
    }

    internal companion object {
        const val NAME = "RefineIDCard"
        const val JCA_SHA256_WITH_RSA = "SHA256withRSA"
        const val JCA_SHA256_WITH_RSA_PSS = "SHA256withRSA/PSS"
        const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
        const val JCA_SHA384_WITH_RSA_PSS = "SHA384withRSA/PSS"
        const val JCA_SHA512_WITH_RSA = "SHA512withRSA"
        const val JCA_SHA512_WITH_RSA_PSS = "SHA512withRSA/PSS"
        const val JCA_SHA256_WITH_ECDSA = "SHA256withECDSA"
        const val JCA_SHA384_WITH_ECDSA = "SHA384withECDSA"

        private const val SIGNATURE_SERVICE = "Signature"
        private const val SUPPORTED_KEY_CLASSES_ATTRIBUTE = "SupportedKeyClasses"
        private const val VERSION = 1.0
        private const val DESCRIPTION = "RefineID external smart-card signatures"
    }
}

/** Installs the provider only when no different provider owns its reserved name. */
internal object ReFineIdCardProviderRegistration {
    @Synchronized
    fun install(): Boolean {
        val existing = Security.getProvider(ReFineIdCardProvider.NAME)
        if (existing != null) {
            return existing is ReFineIdCardProvider
        }
        val position =
            Security.insertProviderAt(
                ReFineIdCardProvider(),
                FIRST_PROVIDER_POSITION,
            )
        return position == FIRST_PROVIDER_POSITION
    }

    private const val FIRST_PROVIDER_POSITION = 1
}

internal class Sha256WithRsaCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256)

internal class Sha256WithRsaPssCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PSS_SHA256)

internal class Sha384WithRsaCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384)

internal class Sha384WithRsaPssCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PSS_SHA384)

internal class Sha512WithRsaCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512)

internal class Sha512WithRsaPssCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.RSA_PSS_SHA512)

internal class Sha256WithEcdsaCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.ECDSA_P384_SHA256)

internal class Sha384WithEcdsaCardSignature : CardBackedSignatureSpi(AuthenticationSigningAlgorithm.ECDSA_P384_SHA384)

@Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
internal abstract class CardBackedSignatureSpi(
    private val algorithm: AuthenticationSigningAlgorithm,
) : SignatureSpi() {
    private var key: CardBackedPrivateKey? = null
    private val message = ZeroizingMessageBuffer(MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH)
    private var hasSigned = false

    final override fun engineInitVerify(publicKey: PublicKey) {
        reset()
        throw InvalidKeyException("card-backed signatures do not verify")
    }

    final override fun engineInitSign(privateKey: PrivateKey) {
        initSign(privateKey)
    }

    final override fun engineInitSign(
        privateKey: PrivateKey,
        random: SecureRandom,
    ) {
        initSign(privateKey)
    }

    private fun initSign(privateKey: PrivateKey) {
        reset()
        val cardKey =
            privateKey as? CardBackedPrivateKey
                ?: throw InvalidKeyException("a RefineID card key is required")
        if (cardKey.algorithm != algorithm.jcaKeyAlgorithm()) {
            throw InvalidKeyException("card key algorithm does not match the signature")
        }
        key = cardKey
    }

    final override fun engineUpdate(input: Byte) {
        requireReady()
        message.append(input)
    }

    final override fun engineUpdate(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        requireReady()
        try {
            message.append(input, offset, length)
        } catch (error: IndexOutOfBoundsException) {
            throw SignatureException("invalid message range", error)
        } catch (error: IllegalArgumentException) {
            throw SignatureException("authentication message is too large", error)
        }
    }

    final override fun engineSign(): ByteArray {
        val cardKey = requireReady()
        val ownedMessage = message.take()
        hasSigned = true
        return try {
            val signature = cardKey.operation.sign(algorithm, ownedMessage)
            try {
                when (algorithm) {
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
                    -> signature.useBytes(P384EcdsaSignature::toDer)

                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
                    -> signature.copyBytes()
                }
            } finally {
                signature.close()
            }
        } finally {
            ownedMessage.fill(ZERO_BYTE)
        }
    }

    final override fun engineVerify(signature: ByteArray): Boolean {
        throw SignatureException("card-backed signatures do not verify")
    }

    final override fun engineSetParameter(
        parameter: String,
        value: Any,
    ): Unit = throw InvalidParameterException("signature parameters are fixed")

    final override fun engineGetParameter(parameter: String): Any? {
        throw InvalidParameterException("signature parameters are fixed")
    }

    // TLS 1.3 signs its CertificateVerify with RSA-PSS, and the platform
    // TLS stack sets an explicit PSSParameterSpec on the delegated
    // signature before signing. The card's PSS profile is fixed, so a
    // spec naming exactly that profile is accepted as a no-op and any
    // other parameters are refused.
    final override fun engineSetParameter(parameters: AlgorithmParameterSpec) {
        val pss =
            parameters as? PSSParameterSpec
                ?: throw InvalidParameterException("signature parameters are fixed")
        if (!algorithm.acceptsPssParameters(pss)) {
            throw InvalidParameterException("PSS parameters do not match the card profile")
        }
    }

    private fun requireReady(): CardBackedPrivateKey {
        if (hasSigned) {
            throw SignatureException("card signature operation was already consumed")
        }
        return key ?: throw SignatureException("card signature is not initialized")
    }

    private fun reset() {
        message.clear()
        key = null
        hasSigned = false
    }

    private fun AuthenticationSigningAlgorithm.jcaKeyAlgorithm(): String =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
            -> JCA_KEY_ALGORITHM_RSA

            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            -> JCA_KEY_ALGORITHM_EC
        }

    private companion object {
        const val JCA_KEY_ALGORITHM_RSA = "RSA"
        const val JCA_KEY_ALGORITHM_EC = "EC"
        const val ZERO_BYTE: Byte = 0
    }
}

/**
 * Whether an externally supplied PSS parameter spec is consistent with
 * this card variant. The card computes the whole PSS block itself with a
 * fixed profile, so the JCA spec is advisory: the only thing that must
 * agree is the outer digest, which pins which TLS signature scheme the
 * peer chose. MGF, salt length, and trailer are left to the card, so a
 * mismatch there is not grounds to fail the handshake before it starts.
 */
internal fun AuthenticationSigningAlgorithm.acceptsPssParameters(parameters: PSSParameterSpec): Boolean {
    val digestName =
        when (this) {
            AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> MGF1ParameterSpec.SHA256.digestAlgorithm

            AuthenticationSigningAlgorithm.RSA_PSS_SHA384 -> MGF1ParameterSpec.SHA384.digestAlgorithm

            AuthenticationSigningAlgorithm.RSA_PSS_SHA512 -> MGF1ParameterSpec.SHA512.digestAlgorithm

            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
            AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
            AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            -> return false
        }
    return sameDigestName(parameters.digestAlgorithm, digestName)
}

/** `SHA-256` and `SHA256` name the same digest across JCA providers. */
private fun sameDigestName(
    left: String,
    right: String,
): Boolean = left.replace("-", "").equals(right.replace("-", ""), ignoreCase = true)

private class ZeroizingMessageBuffer(
    private val maximumLength: Int,
) {
    private var bytes = ByteArray(INITIAL_CAPACITY)
    private var length = 0

    fun append(value: Byte) {
        ensureCapacity(length + Byte.SIZE_BYTES)
        bytes[length] = value
        length += Byte.SIZE_BYTES
    }

    fun append(
        source: ByteArray,
        offset: Int,
        count: Int,
    ) {
        if (offset < 0 || count < 0 || offset > source.size || count > source.size - offset) {
            throw IndexOutOfBoundsException("message range is outside the source")
        }
        ensureCapacity(length + count)
        source.copyInto(
            destination = bytes,
            destinationOffset = length,
            startIndex = offset,
            endIndex = offset + count,
        )
        length += count
    }

    fun take(): ByteArray =
        bytes.copyOf(length).also {
            clear()
        }

    fun clear() {
        bytes.fill(ZERO_BYTE)
        length = 0
    }

    private fun ensureCapacity(requiredLength: Int) {
        require(requiredLength <= maximumLength) {
            "message exceeds its maximum length"
        }
        if (requiredLength <= bytes.size) {
            return
        }
        var capacity = bytes.size
        while (capacity < requiredLength) {
            capacity = (capacity * CAPACITY_GROWTH_FACTOR).coerceAtMost(maximumLength)
        }
        val replacement = bytes.copyOf(capacity)
        bytes.fill(ZERO_BYTE)
        bytes = replacement
    }

    private companion object {
        const val INITIAL_CAPACITY = 256
        const val CAPACITY_GROWTH_FACTOR = 2
        const val ZERO_BYTE: Byte = 0
    }
}
