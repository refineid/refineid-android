// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import fi.refineid.android.core.NativeCardKeyProfile
import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativePin2PreflightResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.NativeQualifiedSignature
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignFailure
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.DigestBatch
import uniffi.refineid_doc_sign_android.DocumentDigest
import uniffi.refineid_doc_sign_android.KeyProfile
import uniffi.refineid_doc_sign_android.SignatureAlgorithm

class CardDigestSignerTest {
    private companion object {
        const val SIGNED_EVENT = "signed"
        const val SYNTHETIC_PIN2 = "135790"
        const val CORRECTED_PIN2 = "246802"
        const val ATTEMPTS_AT_FLOOR = 3
        const val ATTEMPTS_BELOW_FLOOR = 2
        const val NO_ANSWER_TIMEOUT_MS = 50L
        val CERTIFICATE_DER = "synthetic qualified certificate".encodeToByteArray()
        val DOCUMENT_NAMES = listOf("letter.pdf", "annex.pdf")

        fun digest(name: String): ByteArray = "digest of $name".encodeToByteArray()

        fun signature(digest: ByteArray): ByteArray = "signed ".encodeToByteArray() + digest

        fun batch(
            keyProfile: KeyProfile = KeyProfile.ECDSA_P384,
            algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA384,
        ) = DigestBatch(keyProfile, algorithm, DOCUMENT_NAMES.map { DocumentDigest(it, digest(it)) })
    }

    /** What the scripted card does with one signature request. */
    private sealed interface Step {
        data object Sign : Step

        data class Fail(
            val kind: QualifiedSignFailure,
            val retries: Int? = null,
        ) : Step

        data object Silent : Step
    }

    /** A card that answers the certificate read with [certificate] and each signature in turn as [steps] say. */
    private class ScriptedCard(
        private val certificate: NativeCertificateReadResult<NativeQualifiedCertificate>,
        steps: List<Step>,
    ) : QualifiedCardService {
        private val steps = ArrayDeque(steps)
        val algorithms = mutableListOf<QualifiedSigningAlgorithm>()
        val pins = mutableListOf<String>()
        val digests = mutableListOf<ByteArray>()
        var certificateReads = 0

        override fun requestQualifiedCertificate(
            onResult: (NativeCertificateReadResult<NativeQualifiedCertificate>) -> Unit,
        ) {
            certificateReads += 1
            onResult(certificate)
        }

        override fun requestPin2Preflight(onResult: (NativePin2PreflightResult) -> Unit) = error("not probed")

        override fun requestQualifiedSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            content: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) = error("the core signs digests")

        override fun requestQualifiedDigestSignature(
            algorithm: QualifiedSigningAlgorithm,
            pin2: Pin2Submission,
            digest: ByteArray,
            expectedCertificate: NativeQualifiedCertificate,
            onResult: (QualifiedSignResult) -> Unit,
        ) {
            algorithms += algorithm
            pins += pin2.consume { bytes -> bytes.decodeToString() }
            digests += digest
            when (val step = steps.removeFirst()) {
                Step.Sign -> {
                    onResult(QualifiedSignResult.Success(NativeQualifiedSignature(algorithm, signature(digest))))
                }

                is Step.Fail -> {
                    onResult(QualifiedSignResult.Failure(step.kind, step.retries))
                }

                Step.Silent -> {
                    // A card that never answers posts nothing.
                }
            }
        }
    }

    private fun certificate(profile: NativeCardKeyProfile = NativeCardKeyProfile.ECDSA_P384) =
        NativeCertificateReadResult.Success(NativeQualifiedCertificate(profile, CERTIFICATE_DER.copyOf()))

    /** PIN entries in order; null declines. */
    private class ScriptedEntry(
        entries: List<String?>,
    ) : Pin2Entry {
        private val entries = ArrayDeque(entries)
        val attemptsSeen = mutableListOf<Int?>()

        override fun pin2(attemptsLeft: Int?): Pin2Submission? {
            attemptsSeen += attemptsLeft
            return entries.removeFirst()?.let(Pin2Submission::from)
        }
    }

    @Test
    fun signsEveryDigestWithAFreshCopyOfOnePinEntry() {
        val card = ScriptedCard(certificate(), List(DOCUMENT_NAMES.size) { Step.Sign })
        val entry = ScriptedEntry(listOf(SYNTHETIC_PIN2))
        val signer = CardDigestSigner(card, entry)

        assertArrayEquals(CERTIFICATE_DER, signer.signatureCertificate())
        val signatures = signer.sign(batch())

        assertEquals(
            DOCUMENT_NAMES.map { signature(digest(it)) }.map(ByteArray::toList),
            signatures.map(ByteArray::toList),
        )
        assertEquals(List(DOCUMENT_NAMES.size) { QualifiedSigningAlgorithm.ECDSA_P384_SHA384 }, card.algorithms)
        assertEquals(List(DOCUMENT_NAMES.size) { SYNTHETIC_PIN2 }, card.pins)
        assertEquals(listOf<Int?>(null), entry.attemptsSeen)
        assertEquals(1, card.certificateReads)
        signer.close()
    }

    @Test
    fun theHolderSeesEachDocumentStartAndTheCardFinish() {
        val card = ScriptedCard(certificate(), List(DOCUMENT_NAMES.size) { Step.Sign })
        val seen = mutableListOf<String>()
        val events =
            object : SigningEvents {
                override fun signing(
                    index: Int,
                    total: Int,
                ) {
                    seen += "$index/$total"
                }

                override fun signed() {
                    seen += SIGNED_EVENT
                }
            }
        val signer = CardDigestSigner(card, ScriptedEntry(listOf(SYNTHETIC_PIN2)), events)
        signer.signatureCertificate()

        signer.sign(batch())

        assertEquals(DOCUMENT_NAMES.indices.map { "$it/${DOCUMENT_NAMES.size}" } + SIGNED_EVENT, seen)
    }

    @Test
    fun aWrongPinAtTheFloorIsAskedAgainForTheSameDigest() {
        val card =
            ScriptedCard(
                certificate(),
                listOf(Step.Fail(QualifiedSignFailure.WRONG_PIN, ATTEMPTS_AT_FLOOR), Step.Sign, Step.Sign),
            )
        val entry = ScriptedEntry(listOf(SYNTHETIC_PIN2, CORRECTED_PIN2))
        val signer = CardDigestSigner(card, entry)
        signer.signatureCertificate()

        val signatures = signer.sign(batch())

        assertEquals(DOCUMENT_NAMES.size, signatures.size)
        assertEquals(listOf(SYNTHETIC_PIN2, CORRECTED_PIN2, CORRECTED_PIN2), card.pins)
        assertArrayEquals(card.digests[0], card.digests[1])
        assertEquals(listOf(null, ATTEMPTS_AT_FLOOR), entry.attemptsSeen)
    }

    @Test
    fun aWrongPinBelowTheFloorEndsAtTheFloor() {
        val card = ScriptedCard(certificate(), listOf(Step.Fail(QualifiedSignFailure.WRONG_PIN, ATTEMPTS_BELOW_FLOOR)))
        val signer = CardDigestSigner(card, ScriptedEntry(listOf(SYNTHETIC_PIN2)))
        signer.signatureCertificate()

        assertThrows(CardSignRefusal.RetryFloor::class.java) { signer.sign(batch()) }
        assertEquals(1, card.pins.size)
    }

    @Test
    fun aDeclinedEntryAndAMissingCardAreRefusalsOfTheirOwnName() {
        val declined = CardDigestSigner(ScriptedCard(certificate(), emptyList()), ScriptedEntry(listOf(null)))
        declined.signatureCertificate()
        assertThrows(CardSignRefusal.Declined::class.java) { declined.sign(batch()) }

        val missing =
            CardDigestSigner(
                ScriptedCard(
                    NativeCertificateReadResult.Failure(NativeCertificateReadFailure.CARD_UNAVAILABLE),
                    emptyList(),
                ),
                ScriptedEntry(emptyList()),
            )
        assertThrows(CardSignRefusal.CardUnavailable::class.java) { missing.signatureCertificate() }

        val gone =
            CardDigestSigner(
                ScriptedCard(certificate(), listOf(Step.Fail(QualifiedSignFailure.CARD_UNAVAILABLE))),
                ScriptedEntry(listOf(SYNTHETIC_PIN2)),
            )
        gone.signatureCertificate()
        assertThrows(CardSignRefusal.CardUnavailable::class.java) { gone.sign(batch()) }
    }

    @Test
    fun aCardThatNeverAnswersExpires() {
        val card = ScriptedCard(certificate(), listOf(Step.Silent))
        val signer =
            CardDigestSigner(card, ScriptedEntry(listOf(SYNTHETIC_PIN2)), answerTimeoutMs = NO_ANSWER_TIMEOUT_MS)
        signer.signatureCertificate()

        assertThrows(CardSignRefusal.Expired::class.java) { signer.sign(batch()) }
    }

    @Test
    fun signingBeforeTheCertificateAndAnAlgorithmTheSessionLacksAreRefused() {
        val signer = CardDigestSigner(ScriptedCard(certificate(), emptyList()), ScriptedEntry(listOf(SYNTHETIC_PIN2)))
        assertThrows(CardSignRefusal.CardFailed::class.java) { signer.sign(batch()) }

        signer.signatureCertificate()
        assertThrows(CardSignRefusal.Unsupported::class.java) {
            signer.sign(batch(KeyProfile.RSA2048, SignatureAlgorithm.RSA_PKCS1_SHA256))
        }
    }

    @Test
    fun theSessionAlgorithmFollowsTheBatch() {
        assertEquals(QualifiedSigningAlgorithm.ECDSA_P384_SHA384, CardDigestSigner.algorithmOf(batch()))
        assertEquals(
            QualifiedSigningAlgorithm.RSA_PKCS1_SHA384,
            CardDigestSigner.algorithmOf(batch(KeyProfile.RSA3072, SignatureAlgorithm.RSA_PKCS1_SHA384)),
        )
        assertNull(CardDigestSigner.algorithmOf(batch(KeyProfile.RSA3072, SignatureAlgorithm.RSA_PKCS1_SHA256)))
        assertNull(CardDigestSigner.algorithmOf(batch(KeyProfile.RSA2048, SignatureAlgorithm.ECDSA_SHA384)))
        assertTrue(
            CardDigestSigner.certificateRefusal(
                NativeCertificateReadFailure.BRIDGE_ERROR,
            ) is CardSignRefusal.CardFailed,
        )
    }
}
