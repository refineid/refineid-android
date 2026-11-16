// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import fi.refineid.android.core.AuthenticationSignResult
import fi.refineid.android.core.AuthenticationSigningAlgorithm
import fi.refineid.android.core.AuthenticationSigningInputMode
import fi.refineid.android.core.CardManagementSessionOps
import fi.refineid.android.core.NativeAuthenticationCertificate
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1Verification
import fi.refineid.android.core.QualifiedCardSessionOps

/**
 * One holder-opened contactless card session, confined to the NFC worker
 * thread: a citizen card's channel opened by its access number
 * ([ContactlessSession]), or an organization card's, where each operation
 * opens its own with the credential it spends
 * ([OrganizationContactlessSession]).
 */
internal interface ContactlessCardSession :
    CardManagementSessionOps,
    QualifiedCardSessionOps,
    AutoCloseable {
    /** Replace the tag handle after the stack re-polled the resting card. */
    fun adopt(freshIsoDep: IsoDep)

    /** PIN 1 attempts the card allows, read without a VERIFY; null when not known. */
    fun pin1AttemptsLeft(): Int?

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate

    fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        isCurrent: () -> Boolean,
    ): Pin1Verification

    fun authenticateAndSignInput(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
    ): AuthenticationSignResult

    override fun close()
}
