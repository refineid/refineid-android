package fi.refineid.android.core

internal interface CardManagementService {
    /** The credential health with the card's PIN and PUK lengths, read where PINs are set. */
    fun probeCredentialHealth(onResult: (CardManagementResult<CredentialHealth>) -> Unit)

    fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    )

    fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    )

    fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    )

    fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    )

    fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        onResult: (CardManagementResult<ActivationReport>) -> Unit,
    )
}
