package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/** Typed outcome of one credential-free contactless EF.CardAccess probe. */
internal data class NativeCardAccessSummary(
    val supportsPublishedPaceProfile: Boolean,
    val paceEntryCount: Int,
)

internal enum class NativeCardAccessFailure {
    CARD_UNAVAILABLE,
    REJECTED,
    TRANSPORT_ERROR,
    INVALID_CARD_ACCESS,
    BRIDGE_ERROR,
}

internal sealed interface NativeCardAccessResult {
    data class Success(
        val summary: NativeCardAccessSummary,
    ) : NativeCardAccessResult

    data class Failure(
        val kind: NativeCardAccessFailure,
    ) : NativeCardAccessResult
}

/** Native boundary for credential-free contactless card recognition. */
internal object NativeContactlessCore {
    fun probeCardAccess(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeCardAccessResult {
        val startedAt = AppTrace.nativeCardAccessProbeStarted(exchangeLevel)
        val result =
            if (!NativeCore.isLoaded) {
                NativeCardAccessResult.Failure(NativeCardAccessFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativeCardAccessReply.decode(
                        probeCardAccessNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativeCardAccessResult.Failure(NativeCardAccessFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativeCardAccessResult.Failure(NativeCardAccessFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativeCardAccessProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * One PACE handshake with the transferred CAN, then the PKCS#15
     * selection, certificate read, and counter-safe PIN1 preflight
     * inside the same secure-messaging session. The CAN copy is cleared
     * by the native border.
     */
    fun open(
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
                        contactlessOpenNative(
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
     * PACE, then the one-shot preflight, VERIFY, and signing sequence
     * inside secure messaging. The PIN transfers to exactly this call.
     */
    fun authenticateAndSign(
        canCopy: ByteArray,
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
                canCopy.fill(0)
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
                                contactlessAuthenticateAndSignNative(
                                    can = canCopy,
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
                } finally {
                    canCopy.fill(0)
                }
            }
        AppTrace.nativeContactlessSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * One PACE handshake with the transferred CAN, then the PKCS#15
     * selection and one EF.4332 read inside secure messaging. The CAN
     * copy is cleared by the native border.
     */
    fun readQualifiedCertificate(
        canCopy: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeCertificateReadResult<NativeQualifiedCertificate> {
        val startedAt = AppTrace.nativeQualifiedCertificateReadStarted(NativeCardExchangeLevel.APDU)
        val result =
            if (!NativeCore.isLoaded) {
                canCopy.fill(0)
                NativeCertificateReadResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativeCertificateReply.decode(
                        reply =
                            contactlessReadQualifiedCertificateNative(
                                can = canCopy,
                                callback = exchange,
                            ),
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
                } finally {
                    canCopy.fill(0)
                }
            }
        AppTrace.nativeQualifiedCertificateReadCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * One PACE handshake with the transferred CAN, then the PKCS#15
     * selection and a counter-safe PIN2 preflight inside secure
     * messaging. The CAN copy is cleared by the native border.
     */
    fun probePin2(
        canCopy: ByteArray,
        exchange: NativeBlockExchange,
    ): NativePin2PreflightResult {
        val startedAt = AppTrace.nativePin2StatusProbeStarted(NativeCardExchangeLevel.APDU)
        val result =
            if (!NativeCore.isLoaded) {
                canCopy.fill(0)
                NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin2PreflightReply.decode(
                        contactlessProbePin2Native(
                            can = canCopy,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                } finally {
                    canCopy.fill(0)
                }
            }
        AppTrace.nativePin2StatusProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    /**
     * PACE, then the PKCS#15 selection, PIN2 preflight, VERIFY, and one
     * qualified signature inside secure messaging. The PIN transfers to
     * exactly this call; the CAN copy is cleared by the native border.
     */
    fun qualifiedSign(
        canCopy: ByteArray,
        algorithm: QualifiedSigningAlgorithm,
        pin2: Pin2Submission,
        content: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        exchange: NativeBlockExchange,
    ): NativeQualifiedSignResult =
        qualifiedSignInput(
            canCopy = canCopy,
            algorithm = algorithm,
            inputMode = QualifiedSigningInputMode.MESSAGE,
            pin2 = pin2,
            input = content,
            expectedCertificate = expectedCertificate,
            exchange = exchange,
        )

    fun qualifiedSignInput(
        canCopy: ByteArray,
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
        val result =
            if (!algorithm.acceptsInputLength(inputMode, input.size)) {
                canCopy.fill(0)
                pin2.close()
                NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
            } else {
                val expectedDer =
                    try {
                        expectedCertificate.copyDer()
                    } catch (_: IllegalStateException) {
                        canCopy.fill(0)
                        pin2.close()
                        null
                    }
                if (expectedDer == null) {
                    NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                } else {
                    try {
                        pin2.consume { pinBytes ->
                            if (!NativeCore.isLoaded) {
                                canCopy.fill(0)
                                NativeQualifiedSignResult.Failure(
                                    NativeQualifiedSignFailure.BRIDGE_ERROR,
                                )
                            } else {
                                NativeQualifiedSignReply.decode(
                                    contactlessQualifiedSignNative(
                                        can = canCopy,
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
                        canCopy.fill(0)
                        expectedDer.fill(ZERO_BYTE)
                    }
                }
            }
        AppTrace.nativeQualifiedSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    @JvmStatic
    private external fun probeCardAccessNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessOpenNative(
        can: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessAuthenticateAndSignNative(
        can: ByteArray,
        request: Int,
        pin: ByteArray,
        message: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessReadQualifiedCertificateNative(
        can: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessProbePin2Native(
        can: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun contactlessQualifiedSignNative(
        can: ByteArray,
        algorithm: Int,
        pin: ByteArray,
        content: ByteArray,
        expectedCertificate: ByteArray,
        callback: Any,
    ): ByteArray

    private const val ZERO_BYTE: Byte = 0
}

/** Strict decoder for the bounded native card-access vocabulary. */
internal object NativeCardAccessReply {
    fun decode(reply: ByteArray): NativeCardAccessResult =
        try {
            if (reply.isEmpty()) {
                bridgeFailure()
            } else {
                when (reply[TAG_OFFSET].toUnsignedInt()) {
                    CARD_ACCESS_SUCCEEDED -> {
                        decodeSuccess(reply)
                    }

                    CARD_ACCESS_CARD_UNAVAILABLE -> {
                        decodeFailure(reply, NativeCardAccessFailure.CARD_UNAVAILABLE)
                    }

                    CARD_ACCESS_REJECTED -> {
                        decodeFailure(reply, NativeCardAccessFailure.REJECTED)
                    }

                    CARD_ACCESS_TRANSPORT_ERROR -> {
                        decodeFailure(reply, NativeCardAccessFailure.TRANSPORT_ERROR)
                    }

                    CARD_ACCESS_INVALID -> {
                        decodeFailure(reply, NativeCardAccessFailure.INVALID_CARD_ACCESS)
                    }

                    CARD_ACCESS_BRIDGE_ERROR -> {
                        decodeFailure(reply, NativeCardAccessFailure.BRIDGE_ERROR)
                    }

                    else -> {
                        bridgeFailure()
                    }
                }
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeSuccess(reply: ByteArray): NativeCardAccessResult {
        if (reply.size != SUCCESS_REPLY_LENGTH) {
            return bridgeFailure()
        }
        val supportsPublishedProfile =
            when (reply[PROFILE_OFFSET].toUnsignedInt()) {
                PUBLISHED_PROFILE_ABSENT -> false
                PUBLISHED_PROFILE_PRESENT -> true
                else -> return bridgeFailure()
            }
        val paceEntryCount = reply[ENTRY_COUNT_OFFSET].toUnsignedInt()
        // The native parser fails an EF.CardAccess with no recognized
        // entry, so a success carrying zero entries is malformed.
        if (paceEntryCount < MINIMUM_ENTRY_COUNT) {
            return bridgeFailure()
        }
        return NativeCardAccessResult.Success(
            NativeCardAccessSummary(
                supportsPublishedPaceProfile = supportsPublishedProfile,
                paceEntryCount = paceEntryCount,
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativeCardAccessFailure,
    ): NativeCardAccessResult =
        if (reply.size == FAILURE_REPLY_LENGTH) {
            NativeCardAccessResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun bridgeFailure(): NativeCardAccessResult.Failure =
        NativeCardAccessResult.Failure(NativeCardAccessFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toInt() and UNSIGNED_BYTE_MASK

    private const val CARD_ACCESS_BRIDGE_ERROR = 0
    private const val CARD_ACCESS_SUCCEEDED = 1
    private const val CARD_ACCESS_CARD_UNAVAILABLE = 2
    private const val CARD_ACCESS_REJECTED = 3
    private const val CARD_ACCESS_TRANSPORT_ERROR = 4
    private const val CARD_ACCESS_INVALID = 5

    private const val PUBLISHED_PROFILE_ABSENT = 0
    private const val PUBLISHED_PROFILE_PRESENT = 1

    private const val TAG_OFFSET = 0
    private const val PROFILE_OFFSET = 1
    private const val ENTRY_COUNT_OFFSET = 2

    private const val FAILURE_REPLY_LENGTH = 1
    private const val SUCCESS_REPLY_LENGTH = 3
    private const val MINIMUM_ENTRY_COUNT = 1
    private const val UNSIGNED_BYTE_MASK = 0xFF
}
