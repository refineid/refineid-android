package fi.refineid.android.browser

import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH
import fi.refineid.android.core.NativeAuthenticationSignature
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.SignatureException

class CardSignatureProviderTest {
    @Before
    fun installProviderAheadOfPlatformProviders() {
        Security.removeProvider(RefineIdCardProvider.NAME)
        assertEquals(
            FIRST_PROVIDER_POSITION,
            Security.insertProviderAt(RefineIdCardProvider(), FIRST_PROVIDER_POSITION),
        )
    }

    @After
    fun removeProvider() {
        Security.removeProvider(RefineIdCardProvider.NAME)
    }

    @Test
    fun chromiumRsaNamesReachTheNonExportableCardKey() {
        for ((jcaName, expectedAlgorithm) in RSA_CASES) {
            var observedAlgorithm: AuthenticationSigningAlgorithm? = null
            var observedMessage: ByteArray? = null
            val key =
                CardBackedPrivateKey(JCA_KEY_ALGORITHM_RSA) { algorithm, message ->
                    observedAlgorithm = algorithm
                    observedMessage = message.copyOf()
                    NativeAuthenticationSignature(
                        algorithm = algorithm,
                        ownedBytes = ByteArray(algorithm.signatureLength) { RSA_SIGNATURE_FILL },
                    )
                }
            val signer = Signature.getInstance(jcaName)

            signer.initSign(key)
            signer.update(MESSAGE_PREFIX)
            signer.update(MESSAGE_SUFFIX)
            val signature = signer.sign()

            assertEquals(RefineIdCardProvider.NAME, signer.provider.name)
            assertEquals(expectedAlgorithm, observedAlgorithm)
            assertArrayEquals(MESSAGE, observedMessage)
            assertTrue(signature.all { byte -> byte == RSA_SIGNATURE_FILL })
            assertThrows(SignatureException::class.java, signer::sign)
            signature.fill(ZERO_BYTE)
            observedMessage?.fill(ZERO_BYTE)
        }
    }

    @Test
    fun chromiumEcdsaNamesReturnDerInsteadOfTheCardsRawShape() {
        for ((jcaName, expectedAlgorithm) in ECDSA_CASES) {
            val rawSignature = syntheticRawEcdsaSignature(expectedAlgorithm)
            val key =
                CardBackedPrivateKey(JCA_KEY_ALGORITHM_EC) { algorithm, _ ->
                    assertEquals(expectedAlgorithm, algorithm)
                    NativeAuthenticationSignature(algorithm, rawSignature.copyOf())
                }
            val signer = Signature.getInstance(jcaName)

            signer.initSign(key)
            signer.update(MESSAGE)
            val signature = signer.sign()

            assertEquals(RefineIdCardProvider.NAME, signer.provider.name)
            assertArrayEquals(SYNTHETIC_DER_ECDSA_SIGNATURE, signature)
            signature.fill(ZERO_BYTE)
            rawSignature.fill(ZERO_BYTE)
        }
    }

    @Test
    fun keyHandleNeverExportsPrivateMaterial() {
        val key =
            CardBackedPrivateKey(JCA_KEY_ALGORITHM_RSA) { algorithm, _ ->
                NativeAuthenticationSignature(
                    algorithm,
                    ByteArray(algorithm.signatureLength),
                )
            }

        assertEquals(JCA_KEY_ALGORITHM_RSA, key.algorithm)
        assertNull(key.format)
        assertNull(key.encoded)
        assertFalse(key.toString().contains("encoded", ignoreCase = true))
    }

    @Test
    fun normalSoftwareKeysFallThroughToAPlatformProvider() {
        val keyPair =
            KeyPairGenerator
                .getInstance(JCA_KEY_ALGORITHM_RSA)
                .apply { initialize(SYNTHETIC_RSA_KEY_LENGTH_BITS) }
                .generateKeyPair()
        val signer = Signature.getInstance(RefineIdCardProvider.JCA_SHA256_WITH_RSA)

        signer.initSign(keyPair.private)
        signer.update(MESSAGE)
        val signature = signer.sign()

        assertFalse(signer.provider.name == RefineIdCardProvider.NAME)
        val verifier = Signature.getInstance(RefineIdCardProvider.JCA_SHA256_WITH_RSA)
        verifier.initVerify(keyPair.public)
        verifier.update(MESSAGE)
        assertTrue(verifier.verify(signature))
        signature.fill(ZERO_BYTE)
    }

    @Test
    fun rejectsMessagesAboveTheNativeBoundaryBeforeCardUse() {
        var cardWasUsed = false
        val key =
            CardBackedPrivateKey(JCA_KEY_ALGORITHM_RSA) { algorithm, _ ->
                cardWasUsed = true
                NativeAuthenticationSignature(
                    algorithm,
                    ByteArray(algorithm.signatureLength),
                )
            }
        val signer = Signature.getInstance(RefineIdCardProvider.JCA_SHA256_WITH_RSA)
        signer.initSign(key)
        val overlengthMessage =
            ByteArray(MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH + SINGLE_EXCESS_BYTE_COUNT)

        assertThrows(SignatureException::class.java) {
            signer.update(overlengthMessage)
        }
        assertFalse(cardWasUsed)
        overlengthMessage.fill(ZERO_BYTE)
    }

    private fun syntheticRawEcdsaSignature(algorithm: AuthenticationSigningAlgorithm): ByteArray {
        val coordinateLength = algorithm.signatureLength / ECDSA_COORDINATE_COUNT
        return ByteArray(algorithm.signatureLength).also { raw ->
            raw[coordinateLength - LAST_ELEMENT_DISTANCE] = ECDSA_R_VALUE
            raw[raw.size - LAST_ELEMENT_DISTANCE] = ECDSA_S_VALUE
        }
    }

    private companion object {
        const val FIRST_PROVIDER_POSITION = 1
        const val SINGLE_EXCESS_BYTE_COUNT = 1
        const val LAST_ELEMENT_DISTANCE = 1
        const val ECDSA_COORDINATE_COUNT = 2
        const val SYNTHETIC_RSA_KEY_LENGTH_BITS = 2_048
        const val JCA_KEY_ALGORITHM_RSA = "RSA"
        const val JCA_KEY_ALGORITHM_EC = "EC"
        const val RSA_SIGNATURE_FILL: Byte = 0x5A
        const val ECDSA_R_VALUE: Byte = 1
        const val ECDSA_S_VALUE: Byte = 2
        const val DER_SEQUENCE_TAG: Byte = 0x30
        const val DER_SEQUENCE_LENGTH: Byte = 6
        const val DER_INTEGER_TAG: Byte = 0x02
        const val DER_INTEGER_LENGTH: Byte = 1
        const val ZERO_BYTE: Byte = 0
        val MESSAGE_PREFIX = "browser ".encodeToByteArray()
        val MESSAGE_SUFFIX = "authentication".encodeToByteArray()
        val MESSAGE = MESSAGE_PREFIX + MESSAGE_SUFFIX
        val RSA_CASES =
            listOf(
                RefineIdCardProvider.JCA_SHA256_WITH_RSA to
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                RefineIdCardProvider.JCA_SHA256_WITH_RSA_PSS to
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
                RefineIdCardProvider.JCA_SHA384_WITH_RSA to
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
                RefineIdCardProvider.JCA_SHA384_WITH_RSA_PSS to
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
                RefineIdCardProvider.JCA_SHA512_WITH_RSA to
                    AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
                RefineIdCardProvider.JCA_SHA512_WITH_RSA_PSS to
                    AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
            )
        val ECDSA_CASES =
            listOf(
                RefineIdCardProvider.JCA_SHA256_WITH_ECDSA to
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
                RefineIdCardProvider.JCA_SHA384_WITH_ECDSA to
                    AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
            )
        val SYNTHETIC_DER_ECDSA_SIGNATURE =
            byteArrayOf(
                DER_SEQUENCE_TAG,
                DER_SEQUENCE_LENGTH,
                DER_INTEGER_TAG,
                DER_INTEGER_LENGTH,
                ECDSA_R_VALUE,
                DER_INTEGER_TAG,
                DER_INTEGER_LENGTH,
                ECDSA_S_VALUE,
            )
    }
}
