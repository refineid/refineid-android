package fi.refineid.android.core

/** The secure-channel steps of one contactless card session that PIN1 verification needs. */
internal interface HeldPin1Channel {
    /** True when a held secure channel is still live on a connected field. */
    val isLive: Boolean

    /** Clears a held channel's native keys and forgets it; no effect when none is held. */
    fun releaseHeld()

    /**
     * Connects the field and runs PACE, holding the new channel. Returns null
     * on success; on failure returns the result and has released everything
     * the attempt opened.
     */
    fun reopen(): Pin1VerificationResult?

    /** Drops the field. */
    fun closeField()

    /** Sends the one credential-bearing VERIFY on the held channel, consuming [pin1]. */
    fun verify(pin1: Pin1Submission): Pin1Verification
}

/**
 * Verifies PIN1 on [channel], reopening its secure channel when the held
 * one is gone. [isCurrent] is checked after any handshake and immediately
 * before the credential command: superseded work never presents the PIN,
 * and a channel opened only for it is released. Consumes [pin1].
 */
internal fun verifyPin1OnHeldChannel(
    channel: HeldPin1Channel,
    pin1: Pin1Submission,
    isCurrent: () -> Boolean,
): Pin1Verification {
    var reopened = false
    if (!channel.isLive) {
        // A held channel whose field dropped is dead; its keys go before reconnecting.
        channel.releaseHeld()
        channel.reopen()?.let { failure ->
            pin1.close()
            return Pin1Verification(failure)
        }
        reopened = true
    }
    if (!isCurrent()) {
        pin1.close()
        if (reopened) {
            channel.releaseHeld()
            channel.closeField()
        }
        return Pin1Verification(Pin1VerificationResult.CARD_UNAVAILABLE)
    }
    return channel.verify(pin1)
}
