// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import fi.refineid.android.core.QualifiedSignResult

/**
 * Signs the documents of one `batch_sign_documents` request in order
 * (RAPP v26.10.10 section 9.3).
 *
 * Each signature is recorded, and so journaled by the bridge, before the
 * next document is signed. The run stops at the first document that does not
 * sign; already signed documents are never signed again.
 */
internal class RappBatchSignatureRun(
    private val digests: List<ByteArray>,
    private val sign: suspend (digest: ByteArray) -> Step,
    private val record: (wireSignature: ByteArray) -> Unit,
) {
    /** What signing one document produced. */
    sealed interface Step {
        /** The card signed; [wireSignature] is the result's wire form. */
        class Signed(
            val wireSignature: ByteArray,
        ) : Step

        /**
         * The document did not sign: [failure] when the card answered, null
         * when the card was lost or the run was abandoned.
         */
        class Failed(
            val failure: QualifiedSignResult.Failure?,
        ) : Step
    }

    /** How the whole batch ended. */
    sealed interface Outcome {
        /** Every document is signed and recorded. */
        data object Completed : Outcome

        /** Signing stopped after [signedCount] recorded signatures. */
        class Stopped(
            val signedCount: Int,
            val failure: QualifiedSignResult.Failure?,
        ) : Outcome
    }

    suspend fun run(): Outcome {
        digests.forEachIndexed { index, digest ->
            when (val step = sign(digest)) {
                is Step.Signed -> record(step.wireSignature)
                is Step.Failed -> return Outcome.Stopped(index, step.failure)
            }
        }
        return Outcome.Completed
    }
}
