// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import fi.refineid.android.core.NativeCertificateReadFailure
import fi.refineid.android.core.NativeCertificateReadResult
import fi.refineid.android.core.NativeQualifiedCertificate
import fi.refineid.android.core.Pin2Submission
import fi.refineid.android.core.QualifiedCardService
import fi.refineid.android.core.QualifiedSignResult
import fi.refineid.android.core.QualifiedSigningAlgorithm
import fi.refineid.android.rapp.RappCardAnswer
import fi.refineid.android.rapp.RappCardFailure
import uniffi.refineid_doc_sign_android.CardSignRefusal
import uniffi.refineid_doc_sign_android.DigestBatch
import uniffi.refineid_doc_sign_android.KeyProfile
import uniffi.refineid_doc_sign_android.LocalCardSigner
import uniffi.refineid_doc_sign_android.SignatureAlgorithm
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * The holder's PIN 2 for the card signatures of one signing. [attemptsLeft]
 * is null for the first entry and the card's count after a rejected PIN;
 * null back means the holder declined.
 */
internal fun interface Pin2Entry {
    fun pin2(attemptsLeft: Int?): Pin2Submission?
}

/** What the holder sees of a signing while the card works. Called on the signing thread. */
internal interface SigningEvents {
    /** The card is about to sign document [index] (from zero) of [total]. */
    fun signing(
        index: Int,
        total: Int,
    ) = Unit

    /** The card has signed every document; the rest is the core's. */
    fun signed() = Unit
}

/**
 * The card in this phone as the core's signer: reads its signature
 * certificate, takes PIN 2 from [pin2Entry] and has the card sign every
 * digest of a batch, asking for the PIN again while the card still
 * allows it. The card forgets PIN 2 after each signature, so each digest
 * presents a fresh copy of the one entry.
 *
 * Both calls block until the card service answers, so the signing runs
 * off the main thread, which the card services post their answers on.
 */
internal class CardDigestSigner(
    private val card: QualifiedCardService,
    private val pin2Entry: Pin2Entry,
    private val events: SigningEvents = object : SigningEvents {},
    private val answerTimeoutMs: Long = CARD_ANSWER_TIMEOUT_MS,
) : LocalCardSigner,
    AutoCloseable {
    private var certificate: NativeQualifiedCertificate? = null

    override fun signatureCertificate(): ByteArray {
        val read =
            await<NativeCertificateReadResult<NativeQualifiedCertificate>> { card.requestQualifiedCertificate(it) }
                ?: throw CardSignRefusal.Expired()
        return when (read) {
            is NativeCertificateReadResult.Success -> {
                certificate?.close()
                certificate = read.certificate
                read.certificate.copyDer()
            }

            is NativeCertificateReadResult.Failure -> {
                throw certificateRefusal(read.kind)
            }
        }
    }

    override fun sign(batch: DigestBatch): List<ByteArray> {
        val certificate = this.certificate ?: throw CardSignRefusal.CardFailed()
        val algorithm = algorithmOf(batch) ?: throw CardSignRefusal.Unsupported()
        val pin = HeldPin(pin2Entry.pin2(null) ?: throw CardSignRefusal.Declined())
        try {
            val total = batch.documents.size
            val signatures =
                batch.documents.mapIndexed { index, document ->
                    events.signing(index, total)
                    signDigest(algorithm, certificate, document.digest, pin)
                }
            events.signed()
            return signatures
        } finally {
            pin.close()
        }
    }

    /** The card's signature over [digest], asking for PIN 2 again after each wrong one. */
    private fun signDigest(
        algorithm: QualifiedSigningAlgorithm,
        certificate: NativeQualifiedCertificate,
        digest: ByteArray,
        pin: HeldPin,
    ): ByteArray {
        while (true) {
            val attempt = Pin2Submission.fromOwnedBytes(pin.current.copyBytes())
            val result =
                await<QualifiedSignResult> {
                    card.requestQualifiedDigestSignature(algorithm, attempt, digest, certificate, it)
                } ?: throw CardSignRefusal.Expired()
            when (result) {
                is QualifiedSignResult.Success -> {
                    return try {
                        result.signature.copyBytes()
                    } finally {
                        result.signature.close()
                    }
                }

                is QualifiedSignResult.Failure -> {
                    pin.replace(nextPin(result))
                }
            }
        }
    }

    /** The holder's next PIN 2 after [failure], or the refusal that ends the signing. */
    private fun nextPin(failure: QualifiedSignResult.Failure): Pin2Submission =
        when (val answer = RappCardAnswer.of(failure.kind, failure.remainingRetries)) {
            is RappCardAnswer.WrongPin -> pin2Entry.pin2(answer.attemptsLeft) ?: throw CardSignRefusal.Declined()
            is RappCardAnswer.Ends -> throw refusal(answer.failure)
            RappCardAnswer.Done, RappCardAnswer.NotHeld -> throw CardSignRefusal.CardFailed()
        }

    /** The one PIN 2 entry of a signing, replaced after a wrong PIN. */
    private class HeldPin(
        first: Pin2Submission,
    ) : AutoCloseable {
        var current: Pin2Submission = first
            private set

        fun replace(next: Pin2Submission) {
            current.close()
            current = next
        }

        override fun close() {
            current.close()
        }
    }

    override fun close() {
        certificate?.close()
        certificate = null
    }

    /** One card service answer, or null when none arrives within [answerTimeoutMs]. */
    private fun <T : Any> await(request: ((T) -> Unit) -> Unit): T? {
        val answer = CompletableFuture<T>()
        request { answer.complete(it) }
        return try {
            answer.get(answerTimeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            null
        } catch (_: ExecutionException) {
            null
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }
    }

    internal companion object {
        /**
         * How long one card service answer may take. A service without a card
         * answers at once; this bounds a session that never answers.
         */
        const val CARD_ANSWER_TIMEOUT_MS = 30_000L

        /**
         * The card session's algorithm for the batch the core built on the
         * certificate; null when the session has none for it.
         */
        fun algorithmOf(batch: DigestBatch): QualifiedSigningAlgorithm? =
            when (batch.algorithm) {
                SignatureAlgorithm.ECDSA_SHA384 -> {
                    QualifiedSigningAlgorithm.ECDSA_P384_SHA384.takeIf { batch.keyProfile == KeyProfile.ECDSA_P384 }
                }

                SignatureAlgorithm.RSA_PKCS1_SHA384 -> {
                    QualifiedSigningAlgorithm.RSA_PKCS1_SHA384.takeIf { batch.keyProfile == KeyProfile.RSA3072 }
                }

                SignatureAlgorithm.RSA_PKCS1_SHA256, SignatureAlgorithm.ECDSA_SHA256 -> {
                    null
                }
            }

        /** The refusal a certificate read that ended with [kind] is. */
        fun certificateRefusal(kind: NativeCertificateReadFailure): CardSignRefusal =
            when (kind) {
                NativeCertificateReadFailure.CARD_UNAVAILABLE -> CardSignRefusal.CardUnavailable()

                NativeCertificateReadFailure.ORGANIZATION_CARD -> CardSignRefusal.Unsupported()

                NativeCertificateReadFailure.REJECTED,
                NativeCertificateReadFailure.TRANSPORT_ERROR,
                NativeCertificateReadFailure.INVALID_CERTIFICATE,
                NativeCertificateReadFailure.PACE_REJECTED,
                NativeCertificateReadFailure.BRIDGE_ERROR,
                NativeCertificateReadFailure.ACTIVATION_REQUIRED,
                -> CardSignRefusal.CardFailed()
            }

        /** The refusal a card command that ended the operation with [failure] is. */
        fun refusal(failure: RappCardFailure): CardSignRefusal =
            when (failure) {
                RappCardFailure.USER_CANCELLED -> CardSignRefusal.Declined()

                RappCardFailure.RETRY_FLOOR,
                RappCardFailure.PIN1_BLOCKED,
                RappCardFailure.PIN2_BLOCKED,
                -> CardSignRefusal.RetryFloor()

                RappCardFailure.CARD_ERROR -> CardSignRefusal.CardUnavailable()

                RappCardFailure.UNSUPPORTED -> CardSignRefusal.Unsupported()

                RappCardFailure.OPERATION_FAILED -> CardSignRefusal.CardFailed()
            }
    }
}
