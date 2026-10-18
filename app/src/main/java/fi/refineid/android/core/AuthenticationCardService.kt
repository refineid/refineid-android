package fi.refineid.android.core

/** Consumer-neutral boundary over one retained, locally verified card session. */
internal interface AuthenticationCardService {
    val requiresLocalPin: Boolean
        get() = true

    /**
     * Consumes PIN1; the default refuses services without local verification.
     * Naming [expectedGeneration] verifies only on that ready card session and
     * never waits or prompts for another card.
     */
    fun verifyAuthenticationPin(
        pin1: Pin1Submission,
        expectedGeneration: Int? = null,
    ): Pin1Verification {
        pin1.close()
        return Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
    }

    fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit)

    /** PIN 1 attempts the card allows, read without a VERIFY; null when no card answers or it does not say. */
    fun requestPin1AttemptsLeft(onResult: (Int?) -> Unit) = onResult(null)

    fun signAuthenticationMessage(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
    ): AuthenticationSignResult

    fun signAuthenticationDigest(
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
    ): AuthenticationSignResult
}
