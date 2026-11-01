package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/**
 * Native boundary for a persistent contactless secure-messaging session.
 *
 * Where [NativeContactlessCore] runs one PACE handshake per operation and
 * discards the channel, this surface runs PACE once at [connect] and holds
 * the live session on the reader-held field: the `OnSession` operations
 * rebuild that channel and run without a second handshake, and [close]
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
     * The EF.4332 read on the session a prior [connect] left open: no CAN,
     * no PACE, only a re-select inside the retained channel.
     */
    fun readQualifiedCertificateOnSession(
        exchange: NativeBlockExchange,
    ): NativeCertificateReadResult<NativeQualifiedCertificate> {
        val startedAt = AppTrace.nativeQualifiedCertificateReadStarted(NativeCardExchangeLevel.APDU)
        val result =
            if (!NativeCore.isLoaded) {
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativeCertificateReply.decode(
                        reply = contactlessReadQualifiedCertificateOnSessionNative(callback = exchange),
                        certificate = { profile, der ->
                            NativeQualifiedCertificate(
                                keyProfile = profile,
                                ownedDer = der,
                            )
                        },
                    )
                } catch (_: LinkageError) {
                    NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativeQualifiedCertificateReadCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /** The counter-safe PIN2 preflight on the session a prior [connect] left open. */
    fun probePin2OnSession(exchange: NativeBlockExchange): NativePin2PreflightResult {
        val startedAt = AppTrace.nativePin2StatusProbeStarted(NativeCardExchangeLevel.APDU)
        val result =
            if (!NativeCore.isLoaded) {
                NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin2PreflightReply.decode(
                        contactlessProbePin2OnSessionNative(callback = exchange),
                    )
                } catch (_: LinkageError) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativePin2StatusProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * One qualified signature on the session a prior [connect] left open:
     * the PIN2 preflight, VERIFY and signing inside the retained channel.
     * The PIN transfers to exactly this call.
     */
    fun qualifiedSignInputOnSession(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        exchange: NativeBlockExchange,
    ): NativeQualifiedSignResult {
        val startedAt =
            AppTrace.nativeQualifiedSignStarted(
                algorithm = algorithm,
                contentLength = input.size,
            )
        val expectedDer =
            if (algorithm.acceptsInputLength(inputMode, input.size)) {
                try {
                    expectedCertificate.copyDer()
                } catch (_: IllegalStateException) {
                    null
                }
            } else {
                null
            }
        val result =
            if (expectedDer == null) {
                pin2.close()
                NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
            } else {
                try {
                    pin2.consume { pinBytes ->
                        if (!NativeCore.isLoaded) {
                            NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                        } else {
                            NativeQualifiedSignReply.decode(
                                contactlessQualifiedSignOnSessionNative(
                                    algorithm = algorithm.requestWireValue(inputMode),
                                    pin = pinBytes,
                                    content = input,
                                    expectedCertificate = expectedDer,
                                    callback = exchange,
                                ),
                            )
                        }
                    }
                } catch (_: LinkageError) {
                    NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                } finally {
                    expectedDer.fill(0)
                }
            }
        AppTrace.nativeQualifiedSignCompleted(
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
    private external fun contactlessReadQualifiedCertificateOnSessionNative(callback: Any): ByteArray

    @JvmStatic
    private external fun contactlessProbePin2OnSessionNative(callback: Any): ByteArray

    @JvmStatic
    private external fun contactlessQualifiedSignOnSessionNative(
        algorithm: Int,
        pin: ByteArray,
        content: ByteArray,
        expectedCertificate: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessCloseNative(): Int
}
