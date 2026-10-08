package fi.refineid.android.core

/** Consumer-neutral boundary over one retained, locally verified card session. */
internal interface AuthenticationCardService {
    val requiresLocalPin: Boolean
        get() = true

    /** Consumes PIN1; the default refuses services without local verification. */
    fun verifyAuthenticationPin(pin1: Pin1Submission): Pin1VerificationResult {
        pin1.close()
        return Pin1VerificationResult.CARD_UNAVAILABLE
    }

    fun requestAuthenticationCertificate(onResult: (NativeAuthenticationCertificate?) -> Unit)

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
