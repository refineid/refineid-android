// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationSignFailure
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.Pin1Submission
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * A card service that never hands its certificate over cannot stall a
 * session: the bounded read ends with no certificate, which the custodian
 * reports as absence (RAPP v26.10.21 section 8.4 item 1).
 */
class RappCertificateReadTest {
    private companion object {
        /** A bound short enough for a unit test. */
        const val TEST_TIMEOUT_MS = 50L
        const val UNPARSEABLE_TEXT = "not a certificate"
    }

    /** A card service whose certificate request answers with [certificate], or never when [answers] is false. */
    private class CertificateService(
        private val answers: Boolean,
        private val certificate: () -> NativeAuthenticationCertificate?,
    ) : AuthenticationCardService {
        override fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit) {
            if (answers) onResult(certificate())
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

    @Test
    fun aServiceThatNeverAnswersEndsTheReadWithNoCertificate() =
        runBlocking {
            val silent = CertificateService(answers = false) { null }
            assertNull(RappCertificateRead.authentication(silent, TEST_TIMEOUT_MS))
        }

    @Test
    fun aServiceWithoutACertificateOrWithAnUnparseableOneGivesNone() =
        runBlocking {
            assertNull(RappCertificateRead.authentication(CertificateService(answers = true) { null }, TEST_TIMEOUT_MS))
            val unparseable =
                CertificateService(answers = true) {
                    NativeAuthenticationCertificate(
                        NativeCardKeyProfile.ECDSA_P256,
                        UNPARSEABLE_TEXT.encodeToByteArray(),
                    )
                }
            assertNull(RappCertificateRead.authentication(unparseable, TEST_TIMEOUT_MS))
        }

    @Test
    fun aServiceThatAnswersInTimeGivesItsCertificate() =
        runBlocking {
            val der = RappTestCertificate.der
            assumeTrue("OpenSSL makes the synthetic certificate", der != null)
            val answering =
                CertificateService(answers = true) {
                    NativeAuthenticationCertificate(NativeCardKeyProfile.ECDSA_P256, checkNotNull(der).copyOf())
                }
            assertEquals(
                RappCertificate.fromDer(checkNotNull(der)),
                RappCertificateRead.authentication(answering, TEST_TIMEOUT_MS),
            )
        }
}
