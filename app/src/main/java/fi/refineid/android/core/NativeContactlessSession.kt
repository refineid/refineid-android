package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/**
 * Native boundary for a persistent contactless secure-messaging session.
 *
 * Where [NativeContactlessCore] runs one PACE handshake per operation and
 * discards the channel, this surface runs PACE once at [connect] and holds
 * the live session on the reader-held field: [authenticateAndSignOnSession]
 * rebuilds that channel and signs without a second handshake, and [close]
 * drops the held keys. It suits a transport that keeps the RF field up for
 * the session's whole lifetime, such as a USB PICC reader.
 */
internal object NativeContactlessSession {
    /**
     * Like [NativeContactlessCore.open], but retains the live
     * secure-messaging session on full success so a following
     * [authenticateAndSignOnSession] reuses this channel instead of running
     * PACE again. The CAN copy is cleared by the native border.
     */
    fun connect(
        canCopy: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeContactlessOpenResult {
        val startedAt = AppTrace.nativeContactlessOpenStarted()
        val result =
            if (!NativeCore.isLoaded) {
                canCopy.fill(0)
                NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativeContactlessOpenReply.decode(
                        contactlessConnectNative(
                            can = canCopy,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
                } finally {
                    canCopy.fill(0)
                }
            }
        AppTrace.nativeContactlessOpenCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * The authentication signature on the session a prior [connect] left
     * open: no CAN, no PACE, only a cheap re-select before VERIFY and
     * signing on the retained channel. The PIN transfers to exactly this
     * call. A dropped field between connect and this call surfaces as a
     * bridge fault, and the holder connects again.
     */
    fun authenticateAndSignOnSession(
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult {
        val startedAt =
            AppTrace.nativeContactlessSignStarted(
                algorithm = algorithm,
                inputMode = inputMode,
                inputLength = input.size,
            )
        val result =
            if (!algorithm.acceptsInputLength(inputMode, input.size)) {
                pin1.close()
                NativeAuthenticationSignResult.Failure(
                    NativeAuthenticationSignFailure.BRIDGE_ERROR,
                )
            } else {
                try {
                    pin1.consume { pinBytes ->
                        if (!NativeCore.isLoaded) {
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.BRIDGE_ERROR,
                            )
                        } else {
                            NativeAuthenticationSignReply.decode(
                                contactlessAuthenticateAndSignOnSessionNative(
                                    request = algorithm.requestWireValue(inputMode),
                                    pin = pinBytes,
                                    message = input,
                                    callback = exchange,
                                ),
                            )
                        }
                    }
                } catch (_: LinkageError) {
                    NativeAuthenticationSignResult.Failure(
                        NativeAuthenticationSignFailure.BRIDGE_ERROR,
                    )
                } catch (_: RuntimeException) {
                    NativeAuthenticationSignResult.Failure(
                        NativeAuthenticationSignFailure.BRIDGE_ERROR,
                    )
                }
            }
        AppTrace.nativeContactlessSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * Drop the held contactless session and its keys. Best-effort: with no
     * native library there is nothing to clean, and a bridge fault leaves
     * the session to expire with the field.
     */
    fun close() {
        if (!NativeCore.isLoaded) {
            return
        }
        try {
            contactlessCloseNative()
        } catch (_: LinkageError) {
            // Nothing to clean if the library never loaded.
        } catch (_: RuntimeException) {
            // A close fault leaves the session to expire with the field.
        }
    }

    @JvmStatic
    private external fun contactlessConnectNative(
        can: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessAuthenticateAndSignOnSessionNative(
        request: Int,
        pin: ByteArray,
        message: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessCloseNative(): Int
}
