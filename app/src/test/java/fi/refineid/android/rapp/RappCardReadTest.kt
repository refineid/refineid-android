// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationCardReads
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativePin2Preflight
import fi.refineid.android.core.NativePin2PreflightFailure
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.core.QualifiedSigningService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * A card service that never answers cannot stall a session: a bounded read
 * ends with nothing, which the custodian reports as no card (RAPP v26.10.29
 * section 8.4 item 1) or as a count it cannot compare (section 10.2).
 */
class RappCardReadTest {
    private companion object {
        /** A bound short enough for a unit test. */
        const val TEST_TIMEOUT_MS = 50L
        const val UNPARSEABLE_TEXT = "not a certificate"

        /** Attempts a scripted card reports. */
        const val ATTEMPTS = 5
        const val BLOCKED = 0
        const val CERTIFICATE_A = "synthetic authentication certificate of card A"
        const val CERTIFICATE_B = "synthetic authentication certificate of card B"
    }

    /** A card service whose reads answer with the given values, or never when [answers] is false. */
    private class AuthenticationService(
        private val answers: Boolean,
        private val attempts: Int? = null,
        private val certificate: () -> NativeAuthenticationCertificate? = { null },
    ) : AuthenticationCardService {
        override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
            if (answers) onResult(certificate())
        }

        override fun requestPin1AttemptsLeft(onResult: (Int?) -> Unit) {
            if (answers) onResult(attempts)
        }

        override fun signAuthenticationMessage(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            message: ByteArray,
        ): AuthenticationSignResult = AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)

        override fun signAuthenticationDigest(
            algorithm: AuthenticationSigningAlgorithm,
            pin1: Pin1Submission,
            digest: ByteArray,
        ): AuthenticationSignResult = AuthenticationSignResult.Failure(AuthenticationSignFailure.CARD_UNAVAILABLE)
    }

    /** A signing service whose PIN 2 preflight answers with [result], or never when it is null. */
    private class SigningService(
        private val result: NativePin2PreflightResult?,
    ) : QualifiedSigningService {
        override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit) {
            result?.let(onResult)
        }

        override fun requestQualifiedSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            content: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) = onResult(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE))

        override fun requestQualifiedDigestSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            digest: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) = onResult(QualifiedSignResult.Failure(QualifiedSignFailure.CARD_UNAVAILABLE))
    }

    private fun preflight(state: NativePin2State) =
        NativePin2PreflightResult.Success(NativePin2Preflight(NativePinReferenceScheme.CITIZEN, state, true))

    @Test
    fun aServiceThatNeverAnswersEndsEachReadWithNothing() =
        runBlocking {
            val silent = AuthenticationService(answers = false)
            assertNull(RappCardRead.authenticationCertificate(silent, TEST_TIMEOUT_MS))
            assertNull(AuthenticationCardReads.pin1AttemptsLeft(silent, TEST_TIMEOUT_MS))
            assertNull(RappCardRead.pin2AttemptsLeft(SigningService(null), TEST_TIMEOUT_MS))
        }

    @Test
    fun aServiceWithoutACertificateOrWithAnUnparseableOneGivesNone() =
        runBlocking {
            assertNull(RappCardRead.authenticationCertificate(AuthenticationService(answers = true), TEST_TIMEOUT_MS))
            val unparseable =
                AuthenticationService(answers = true) {
                    NativeAuthenticationCertificate(
                        NativeCardKeyProfile.ECDSA_P256,
                        UNPARSEABLE_TEXT.encodeToByteArray(),
                    )
                }
            assertNull(RappCardRead.authenticationCertificate(unparseable, TEST_TIMEOUT_MS))
        }

    @Test
    fun aServiceThatAnswersInTimeGivesItsCertificate() =
        runBlocking {
            val der = RappTestCertificate.der
            assumeTrue("OpenSSL makes the synthetic certificate", der != null)
            val answering =
                AuthenticationService(answers = true) {
                    NativeAuthenticationCertificate(NativeCardKeyProfile.ECDSA_P256, checkNotNull(der).copyOf())
                }
            assertEquals(
                RappCertificate.fromDer(checkNotNull(der)),
                RappCardRead.authenticationCertificate(answering, TEST_TIMEOUT_MS),
            )
        }

    @Test
    fun theAttemptsAPinAllowsAreReadAsTheCardStatesThem() =
        runBlocking {
            assertEquals(
                ATTEMPTS,
                AuthenticationCardReads.pin1AttemptsLeft(AuthenticationService(true, ATTEMPTS), TEST_TIMEOUT_MS),
            )
            assertEquals(
                ATTEMPTS,
                RappCardRead.pin2AttemptsLeft(
                    SigningService(preflight(NativePin2State.Remaining(ATTEMPTS))),
                    TEST_TIMEOUT_MS,
                ),
            )
            assertEquals(
                BLOCKED,
                RappCardRead.pin2AttemptsLeft(SigningService(preflight(NativePin2State.Locked)), TEST_TIMEOUT_MS),
            )
            assertNull(
                RappCardRead.pin2AttemptsLeft(SigningService(preflight(NativePin2State.Verified)), TEST_TIMEOUT_MS),
            )
            assertNull(
                RappCardRead.pin2AttemptsLeft(
                    SigningService(NativePin2PreflightResult.Failure(NativePin2PreflightFailure.CARD_UNAVAILABLE)),
                    TEST_TIMEOUT_MS,
                ),
            )
        }

    @Test
    fun aCountReadForOneCardIsNeverTakenFromAnother() =
        runBlocking {
            val cardA = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_A.encodeToByteArray()))
            val cardB = checkNotNull(AuthenticationCardIdentity.of(CERTIFICATE_B.encodeToByteArray()))
            val serving =
                AuthenticationService(answers = true, attempts = ATTEMPTS) {
                    NativeAuthenticationCertificate(NativeCardKeyProfile.ECDSA_P256, CERTIFICATE_A.encodeToByteArray())
                }
            assertEquals(cardA, AuthenticationCardReads.identity(serving, TEST_TIMEOUT_MS))
            assertEquals(ATTEMPTS, AuthenticationCardReads.pin1AttemptsLeft(serving, cardA, TEST_TIMEOUT_MS))
            assertNull(AuthenticationCardReads.pin1AttemptsLeft(serving, cardB, TEST_TIMEOUT_MS))
        }
}
