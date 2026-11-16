// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fi.refineid.android.core

import fi.refineid.android.document.DerEncoder
import fi.refineid.android.document.DerValues
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

class VerifiedSigningResultsTest {
    @Test
    fun verifiedAuthenticationResultAcceptsValidMessageAndPrehashedSignatures() {
        val certificate =
            NativeAuthenticationCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )
        val rawSignature =
            signRsa(
                jcaAlgorithm = JCA_SHA256_WITH_RSA,
                keyPair = KEY_PAIR,
                input = AUTHENTICATION_MESSAGE,
            )
        val digest = MessageDigest.getInstance(SHA256_JCA_NAME).digest(AUTHENTICATION_MESSAGE)

        certificate.use {
            val messageSignature =
                NativeAuthenticationSignature(
                    algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    ownedBytes = rawSignature.copyOf(),
                )
            val messageResult =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.MESSAGE,
                    input = AUTHENTICATION_MESSAGE,
                    nativeResult = NativeAuthenticationSignResult.Success(messageSignature),
                    paceRejectedFailure = AuthenticationSignFailure.TRANSPORT_ERROR,
                )
            assertTrue(messageResult is AuthenticationSignResult.Success)
            val verifiedMessage = messageResult as AuthenticationSignResult.Success
            assertSame(messageSignature, verifiedMessage.signature)
            assertArrayEquals(rawSignature, verifiedMessage.signature.copyBytes())
            verifiedMessage.signature.close()

            val prehashedSignature =
                NativeAuthenticationSignature(
                    algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    ownedBytes = rawSignature.copyOf(),
                )
            val prehashedResult =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.PREHASHED,
                    input = digest,
                    nativeResult = NativeAuthenticationSignResult.Success(prehashedSignature),
                    paceRejectedFailure = AuthenticationSignFailure.BRIDGE_ERROR,
                )
            assertTrue(prehashedResult is AuthenticationSignResult.Success)
            val verifiedPrehashed = prehashedResult as AuthenticationSignResult.Success
            assertSame(prehashedSignature, verifiedPrehashed.signature)
            assertArrayEquals(rawSignature, verifiedPrehashed.signature.copyBytes())
            verifiedPrehashed.signature.close()
        }
    }

    @Test
    fun verifiedAuthenticationResultClosesSignatureOnLocalVerificationFailure() {
        val certificate =
            NativeAuthenticationCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )
        val corruptedBytes =
            corruptedCopy(
                signRsa(
                    jcaAlgorithm = JCA_SHA256_WITH_RSA,
                    keyPair = KEY_PAIR,
                    input = AUTHENTICATION_MESSAGE,
                ),
            )
        val digest = MessageDigest.getInstance(SHA256_JCA_NAME).digest(AUTHENTICATION_MESSAGE)

        certificate.use {
            val messageSignature =
                NativeAuthenticationSignature(
                    algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    ownedBytes = corruptedBytes.copyOf(),
                )
            val messageResult =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.MESSAGE,
                    input = AUTHENTICATION_MESSAGE,
                    nativeResult = NativeAuthenticationSignResult.Success(messageSignature),
                    paceRejectedFailure = AuthenticationSignFailure.TRANSPORT_ERROR,
                )
            assertEquals(
                AuthenticationSignResult.Failure(AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED),
                messageResult,
            )
            assertThrows(IllegalStateException::class.java) {
                messageSignature.copyBytes()
            }

            val prehashedSignature =
                NativeAuthenticationSignature(
                    algorithm = AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256,
                    ownedBytes = corruptedBytes.copyOf(),
                )
            val prehashedResult =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.PREHASHED,
                    input = digest,
                    nativeResult = NativeAuthenticationSignResult.Success(prehashedSignature),
                    paceRejectedFailure = AuthenticationSignFailure.BRIDGE_ERROR,
                )
            assertEquals(
                AuthenticationSignResult.Failure(AuthenticationSignFailure.LOCAL_VERIFICATION_FAILED),
                prehashedResult,
            )
            assertThrows(IllegalStateException::class.java) {
                prehashedSignature.copyBytes()
            }
        }
    }

    @Test
    fun verifiedAuthenticationResultMapsPaceRejectedPerTransportAndPreservesRetries() {
        val certificate =
            NativeAuthenticationCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )

        certificate.use {
            val nfcPaceRejected =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.MESSAGE,
                    input = AUTHENTICATION_MESSAGE,
                    nativeResult =
                        NativeAuthenticationSignResult.Failure(
                            NativeAuthenticationSignFailure.PACE_REJECTED,
                        ),
                    paceRejectedFailure = AuthenticationSignFailure.TRANSPORT_ERROR,
                )
            assertEquals(
                AuthenticationSignResult.Failure(AuthenticationSignFailure.TRANSPORT_ERROR),
                nfcPaceRejected,
            )

            val usbPaceRejected =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.MESSAGE,
                    input = AUTHENTICATION_MESSAGE,
                    nativeResult =
                        NativeAuthenticationSignResult.Failure(
                            NativeAuthenticationSignFailure.PACE_REJECTED,
                        ),
                    paceRejectedFailure = AuthenticationSignFailure.BRIDGE_ERROR,
                )
            assertEquals(
                AuthenticationSignResult.Failure(AuthenticationSignFailure.BRIDGE_ERROR),
                usbPaceRejected,
            )

            val wrongPin =
                verifiedAuthenticationResult(
                    certificate = certificate,
                    inputMode = AuthenticationSigningInputMode.MESSAGE,
                    input = AUTHENTICATION_MESSAGE,
                    nativeResult =
                        NativeAuthenticationSignResult.Failure(
                            kind = NativeAuthenticationSignFailure.WRONG_PIN,
                            remainingRetries = REMAINING_RETRIES_AFTER_WRONG_PIN,
                        ),
                    paceRejectedFailure = AuthenticationSignFailure.TRANSPORT_ERROR,
                )
            assertEquals(
                AuthenticationSignResult.Failure(
                    kind = AuthenticationSignFailure.WRONG_PIN,
                    remainingRetries = REMAINING_RETRIES_AFTER_WRONG_PIN,
                ),
                wrongPin,
            )

            val expectedPairs =
                listOf(
                    NativeAuthenticationSignFailure.CARD_UNAVAILABLE to AuthenticationSignFailure.CARD_UNAVAILABLE,
                    NativeAuthenticationSignFailure.TRANSPORT_ERROR to AuthenticationSignFailure.TRANSPORT_ERROR,
                    NativeAuthenticationSignFailure.INVALID_PIN to AuthenticationSignFailure.INVALID_PIN,
                    NativeAuthenticationSignFailure.SAFETY_REFUSED to AuthenticationSignFailure.SAFETY_REFUSED,
                    NativeAuthenticationSignFailure.PIN_LOCKED to AuthenticationSignFailure.PIN_LOCKED,
                    NativeAuthenticationSignFailure.VERIFICATION_REJECTED to
                        AuthenticationSignFailure.VERIFICATION_REJECTED,
                    NativeAuthenticationSignFailure.SIGNING_REJECTED to AuthenticationSignFailure.SIGNING_REJECTED,
                    NativeAuthenticationSignFailure.BRIDGE_ERROR to AuthenticationSignFailure.BRIDGE_ERROR,
                )
            for ((nativeFailure, expectedFailure) in expectedPairs) {
                val mapped =
                    verifiedAuthenticationResult(
                        certificate = certificate,
                        inputMode = AuthenticationSigningInputMode.MESSAGE,
                        input = AUTHENTICATION_MESSAGE,
                        nativeResult = NativeAuthenticationSignResult.Failure(nativeFailure),
                        paceRejectedFailure = AuthenticationSignFailure.TRANSPORT_ERROR,
                    ) as AuthenticationSignResult.Failure
                assertEquals(expectedFailure, mapped.kind)
                assertNull(mapped.remainingRetries)
            }
        }
    }

    @Test
    fun verifiedQualifiedResultAcceptsValidMessageAndPrehashedSignatures() {
        val certificate =
            NativeQualifiedCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )
        val rawSignature =
            signRsa(
                jcaAlgorithm = JCA_SHA384_WITH_RSA,
                keyPair = KEY_PAIR,
                input = QUALIFIED_CONTENT,
            )
        val digest = MessageDigest.getInstance(SHA384_JCA_NAME).digest(QUALIFIED_CONTENT)

        certificate.use {
            val messageSignature =
                NativeQualifiedSignature(
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    ownedBytes = rawSignature.copyOf(),
                )
            val messageResult =
                verifiedQualifiedResult(
                    expectedCertificate = certificate,
                    inputMode = QualifiedSigningInputMode.MESSAGE,
                    input = QUALIFIED_CONTENT,
                    nativeResult = NativeQualifiedSignResult.Success(messageSignature),
                )
            assertTrue(messageResult is QualifiedSignResult.Success)
            val verifiedMessage = messageResult as QualifiedSignResult.Success
            assertSame(messageSignature, verifiedMessage.signature)
            assertArrayEquals(rawSignature, verifiedMessage.signature.copyBytes())
            verifiedMessage.signature.close()

            val prehashedSignature =
                NativeQualifiedSignature(
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    ownedBytes = rawSignature.copyOf(),
                )
            val prehashedResult =
                verifiedQualifiedResult(
                    expectedCertificate = certificate,
                    inputMode = QualifiedSigningInputMode.PREHASHED,
                    input = digest,
                    nativeResult = NativeQualifiedSignResult.Success(prehashedSignature),
                )
            assertTrue(prehashedResult is QualifiedSignResult.Success)
            val verifiedPrehashed = prehashedResult as QualifiedSignResult.Success
            assertSame(prehashedSignature, verifiedPrehashed.signature)
            assertArrayEquals(rawSignature, verifiedPrehashed.signature.copyBytes())
            verifiedPrehashed.signature.close()
        }
    }

    @Test
    fun verifiedQualifiedResultClosesSignatureOnLocalVerificationFailure() {
        val certificate =
            NativeQualifiedCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )
        val corruptedBytes =
            corruptedCopy(
                signRsa(
                    jcaAlgorithm = JCA_SHA384_WITH_RSA,
                    keyPair = KEY_PAIR,
                    input = QUALIFIED_CONTENT,
                ),
            )
        val digest = MessageDigest.getInstance(SHA384_JCA_NAME).digest(QUALIFIED_CONTENT)

        certificate.use {
            val messageSignature =
                NativeQualifiedSignature(
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    ownedBytes = corruptedBytes.copyOf(),
                )
            val messageResult =
                verifiedQualifiedResult(
                    expectedCertificate = certificate,
                    inputMode = QualifiedSigningInputMode.MESSAGE,
                    input = QUALIFIED_CONTENT,
                    nativeResult = NativeQualifiedSignResult.Success(messageSignature),
                )
            assertEquals(
                QualifiedSignResult.Failure(QualifiedSignFailure.LOCAL_VERIFICATION_FAILED),
                messageResult,
            )
            assertThrows(IllegalStateException::class.java) {
                messageSignature.copyBytes()
            }

            val prehashedSignature =
                NativeQualifiedSignature(
                    algorithm = QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
                    ownedBytes = corruptedBytes.copyOf(),
                )
            val prehashedResult =
                verifiedQualifiedResult(
                    expectedCertificate = certificate,
                    inputMode = QualifiedSigningInputMode.PREHASHED,
                    input = digest,
                    nativeResult = NativeQualifiedSignResult.Success(prehashedSignature),
                )
            assertEquals(
                QualifiedSignResult.Failure(QualifiedSignFailure.LOCAL_VERIFICATION_FAILED),
                prehashedResult,
            )
            assertThrows(IllegalStateException::class.java) {
                prehashedSignature.copyBytes()
            }
        }
    }

    @Test
    fun verifiedQualifiedResultMapsEveryFailureKindAndPreservesRetries() {
        val certificate =
            NativeQualifiedCertificate(
                keyProfile = NativeCardKeyProfile.RSA_3072,
                ownedDer = CERTIFICATE_DER.copyOf(),
            )

        certificate.use {
            val wrongPin =
                verifiedQualifiedResult(
                    expectedCertificate = certificate,
                    inputMode = QualifiedSigningInputMode.MESSAGE,
                    input = QUALIFIED_CONTENT,
                    nativeResult =
                        NativeQualifiedSignResult.Failure(
                            kind = NativeQualifiedSignFailure.WRONG_PIN,
                            remainingRetries = REMAINING_RETRIES_AFTER_WRONG_PIN,
                        ),
                )
            assertEquals(
                QualifiedSignResult.Failure(
                    kind = QualifiedSignFailure.WRONG_PIN,
                    remainingRetries = REMAINING_RETRIES_AFTER_WRONG_PIN,
                ),
                wrongPin,
            )

            val expectedPairs =
                listOf(
                    NativeQualifiedSignFailure.CARD_UNAVAILABLE to QualifiedSignFailure.CARD_UNAVAILABLE,
                    NativeQualifiedSignFailure.TRANSPORT_ERROR to QualifiedSignFailure.TRANSPORT_ERROR,
                    NativeQualifiedSignFailure.INVALID_PIN to QualifiedSignFailure.INVALID_PIN,
                    NativeQualifiedSignFailure.SAFETY_REFUSED to QualifiedSignFailure.SAFETY_REFUSED,
                    NativeQualifiedSignFailure.PIN_LOCKED to QualifiedSignFailure.PIN_LOCKED,
                    NativeQualifiedSignFailure.VERIFICATION_REJECTED to QualifiedSignFailure.VERIFICATION_REJECTED,
                    NativeQualifiedSignFailure.CERTIFICATE_REJECTED to QualifiedSignFailure.CERTIFICATE_REJECTED,
                    NativeQualifiedSignFailure.INVALID_CERTIFICATE to QualifiedSignFailure.INVALID_CERTIFICATE,
                    NativeQualifiedSignFailure.CERTIFICATE_MISMATCH to QualifiedSignFailure.CERTIFICATE_MISMATCH,
                    NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH to QualifiedSignFailure.KEY_PROFILE_MISMATCH,
                    NativeQualifiedSignFailure.SIGNING_REJECTED to QualifiedSignFailure.SIGNING_REJECTED,
                    NativeQualifiedSignFailure.BRIDGE_ERROR to QualifiedSignFailure.BRIDGE_ERROR,
                )
            for ((nativeFailure, expectedFailure) in expectedPairs) {
                val mapped =
                    verifiedQualifiedResult(
                        expectedCertificate = certificate,
                        inputMode = QualifiedSigningInputMode.MESSAGE,
                        input = QUALIFIED_CONTENT,
                        nativeResult = NativeQualifiedSignResult.Failure(nativeFailure),
                    ) as QualifiedSignResult.Failure
                assertEquals(expectedFailure, mapped.kind)
                assertNull(mapped.remainingRetries)
            }
        }
    }

    private companion object {
        const val RSA_KEY_ALGORITHM = "RSA"
        const val JCA_SHA256_WITH_RSA = "SHA256withRSA"
        const val JCA_SHA384_WITH_RSA = "SHA384withRSA"
        const val SHA256_JCA_NAME = "SHA-256"
        const val SHA384_JCA_NAME = "SHA-384"
        const val SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"
        const val COMMON_NAME_OID = "2.5.4.3"
        const val CERTIFICATE_COMMON_NAME = "RefineID synthetic signing verifier"
        const val CERTIFICATE_NOT_BEFORE = "20250101000000Z"
        const val CERTIFICATE_NOT_AFTER = "20300101000000Z"
        const val X509_VERSION_THREE = 2
        const val CERTIFICATE_SERIAL_NUMBER = 1
        const val NO_UNUSED_BITS: Byte = 0
        const val FIRST_SIGNATURE_BYTE_OFFSET = 0
        const val SINGLE_BIT_CORRUPTION_MASK = 1
        const val REMAINING_RETRIES_AFTER_WRONG_PIN = 3

        val AUTHENTICATION_MESSAGE = "authentication challenge".encodeToByteArray()
        val QUALIFIED_CONTENT = "qualified signed attributes".encodeToByteArray()

        val KEY_PAIR: KeyPair by lazy {
            KeyPairGenerator
                .getInstance(RSA_KEY_ALGORITHM)
                .apply { initialize(RSA_3072_KEY_LENGTH_BITS) }
                .generateKeyPair()
        }

        val CERTIFICATE_DER: ByteArray by lazy {
            selfSignedRsaCertificateDer(KEY_PAIR)
        }

        fun signRsa(
            jcaAlgorithm: String,
            keyPair: KeyPair,
            input: ByteArray,
        ): ByteArray =
            Signature
                .getInstance(jcaAlgorithm)
                .apply {
                    initSign(keyPair.private)
                    update(input)
                }.sign()

        fun corruptedCopy(signature: ByteArray): ByteArray =
            signature.copyOf().also { copy ->
                copy[FIRST_SIGNATURE_BYTE_OFFSET] =
                    (
                        copy[FIRST_SIGNATURE_BYTE_OFFSET].toInt() xor
                            SINGLE_BIT_CORRUPTION_MASK
                    ).toByte()
            }

        fun selfSignedRsaCertificateDer(keyPair: KeyPair): ByteArray {
            val algorithm =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.objectIdentifier(SHA256_WITH_RSA_OID),
                        DerEncoder.nullValue(),
                    ),
                )
            val distinguishedName =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.setOf(
                            listOf(
                                DerEncoder.sequence(
                                    listOf(
                                        DerEncoder.objectIdentifier(COMMON_NAME_OID),
                                        DerEncoder.tlv(
                                            DerValues.TAG_UTF8_STRING,
                                            CERTIFICATE_COMMON_NAME.encodeToByteArray(),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                )
            val validity =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(
                            DerValues.TAG_GENERALIZED_TIME,
                            CERTIFICATE_NOT_BEFORE.encodeToByteArray(),
                        ),
                        DerEncoder.tlv(
                            DerValues.TAG_GENERALIZED_TIME,
                            CERTIFICATE_NOT_AFTER.encodeToByteArray(),
                        ),
                    ),
                )
            val tbsCertificate =
                DerEncoder.sequence(
                    listOf(
                        DerEncoder.tlv(
                            DerValues.TAG_CONTEXT_0_CONSTRUCTED,
                            DerEncoder.integer(X509_VERSION_THREE),
                        ),
                        DerEncoder.integer(CERTIFICATE_SERIAL_NUMBER),
                        algorithm,
                        distinguishedName,
                        validity,
                        distinguishedName,
                        keyPair.public.encoded,
                    ),
                )
            val signatureBytes = signRsa(JCA_SHA256_WITH_RSA, keyPair, tbsCertificate)
            return DerEncoder.sequence(
                listOf(
                    tbsCertificate,
                    algorithm,
                    DerEncoder.tlv(
                        DerValues.TAG_BIT_STRING,
                        byteArrayOf(NO_UNUSED_BITS) + signatureBytes,
                    ),
                ),
            )
        }
    }
}
