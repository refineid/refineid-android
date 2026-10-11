package fi.refineid.android.browser

import androidx.test.ext.junit.runners.AndroidJUnit4
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationSignature
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.Security
import java.security.Signature

@RunWith(AndroidJUnit4::class)
internal class CardSignatureProviderInstrumentedTest {
    @Before
    fun installProviderThroughTheProductionRegistrationPath() {
        Security.removeProvider(RefineIdCardProvider.NAME)
        assertTrue(RefineIdCardProviderRegistration.install())
        assertTrue(RefineIdCardProviderRegistration.install())
    }

    @After
    fun removeProvider() {
        Security.removeProvider(RefineIdCardProvider.NAME)
    }

    @Test
    fun chromiumAlgorithmNamesSelectTheCardProviderOnAndroid() {
        for (case in SIGNATURE_CASES) {
            var observedAlgorithm: AuthenticationSigningAlgorithm? = null
            var observedMessage: ByteArray? = null
            val key =
                CardBackedPrivateKey(case.keyAlgorithm) { algorithm, message ->
                    observedAlgorithm = algorithm
                    observedMessage = message.copyOf()
                    NativeAuthenticationSignature(
                        algorithm = algorithm,
                        ownedBytes = case.cardSignature(algorithm),
                    )
                }
            val signer = Signature.getInstance(case.jcaName)

            signer.initSign(key)
            signer.update(SYNTHETIC_MESSAGE)
            val encodedSignature = signer.sign()

            try {
                assertEquals(RefineIdCardProvider.NAME, signer.provider.name)
                assertEquals(case.cardAlgorithm, observedAlgorithm)
                assertArrayEquals(SYNTHETIC_MESSAGE, observedMessage)
                assertArrayEquals(case.expectedSignature(case.cardAlgorithm), encodedSignature)
            } finally {
                encodedSignature.fill(ZERO_BYTE)
                observedMessage?.fill(ZERO_BYTE)
            }
        }
    }

    private data class SignatureCase(
        val jcaName: String,
        val cardAlgorithm: AuthenticationSigningAlgorithm,
        val keyAlgorithm: String,
        val cardSignature: (AuthenticationSigningAlgorithm) -> ByteArray,
        val expectedSignature: (AuthenticationSigningAlgorithm) -> ByteArray,
    )

    private companion object {
        const val JCA_KEY_ALGORITHM_RSA = "RSA"
        const val JCA_KEY_ALGORITHM_EC = "EC"
        const val ECDSA_COORDINATE_COUNT = 2
        const val LAST_ELEMENT_DISTANCE = 1
        const val RSA_SIGNATURE_FILL: Byte = 0x5A
        const val ECDSA_R_VALUE: Byte = 1
        const val ECDSA_S_VALUE: Byte = 2
        const val DER_SEQUENCE_TAG: Byte = 0x30
        const val DER_SEQUENCE_LENGTH: Byte = 6
        const val DER_INTEGER_TAG: Byte = 0x02
        const val DER_INTEGER_LENGTH: Byte = 1
        const val ZERO_BYTE: Byte = 0

        val SYNTHETIC_MESSAGE = "browser authentication".encodeToByteArray()

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

        val SIGNATURE_CASES =
            listOf(
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA256_WITH_RSA,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA256_WITH_RSA_PSS,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PSS_SHA256,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA384_WITH_RSA,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA384_WITH_RSA_PSS,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PSS_SHA384,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA512_WITH_RSA,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA512_WITH_RSA_PSS,
                    cardAlgorithm = AuthenticationSigningAlgorithm.RSA_PSS_SHA512,
                    keyAlgorithm = JCA_KEY_ALGORITHM_RSA,
                    cardSignature = ::syntheticRsaSignature,
                    expectedSignature = ::syntheticRsaSignature,
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA256_WITH_ECDSA,
                    cardAlgorithm = AuthenticationSigningAlgorithm.ECDSA_P384_SHA256,
                    keyAlgorithm = JCA_KEY_ALGORITHM_EC,
                    cardSignature = ::syntheticRawEcdsaSignature,
                    expectedSignature = { SYNTHETIC_DER_ECDSA_SIGNATURE.copyOf() },
                ),
                SignatureCase(
                    jcaName = RefineIdCardProvider.JCA_SHA384_WITH_ECDSA,
                    cardAlgorithm = AuthenticationSigningAlgorithm.ECDSA_P384_SHA384,
                    keyAlgorithm = JCA_KEY_ALGORITHM_EC,
                    cardSignature = ::syntheticRawEcdsaSignature,
                    expectedSignature = { SYNTHETIC_DER_ECDSA_SIGNATURE.copyOf() },
                ),
            )

        fun syntheticRsaSignature(algorithm: AuthenticationSigningAlgorithm): ByteArray =
            ByteArray(algorithm.signatureLength) { RSA_SIGNATURE_FILL }

        fun syntheticRawEcdsaSignature(algorithm: AuthenticationSigningAlgorithm): ByteArray {
            val coordinateLength = algorithm.signatureLength / ECDSA_COORDINATE_COUNT
            return ByteArray(algorithm.signatureLength).also { raw ->
                raw[coordinateLength - LAST_ELEMENT_DISTANCE] = ECDSA_R_VALUE
                raw[raw.size - LAST_ELEMENT_DISTANCE] = ECDSA_S_VALUE
            }
        }
    }
}
