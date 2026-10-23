package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

internal enum class AtrValidation {
    VALID_T0_DIRECT,
    VALID_T0_INVERSE,
    VALID_NON_T0_DIRECT,
    VALID_NON_T0_INVERSE,
    INVALID,
    BRIDGE_ERROR,
}

internal enum class NativeCardExchangeLevel(
    val wireValue: Int,
) {
    APDU(0),
    T0_TPDU(1),
}

internal enum class NativeCardOperationResult {
    SUCCEEDED,
    CARD_UNAVAILABLE,
    REJECTED,
    TRANSPORT_ERROR,
    BRIDGE_ERROR,
}

internal enum class NativeCardKeyProfile {
    RSA_2048,
    RSA_3072,
    ECDSA_P256,
    ECDSA_P384,
}

internal class NativeAuthenticationCertificate(
    val keyProfile: NativeCardKeyProfile,
    private val ownedDer: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val derLength: Int
        get() = ownedDer.size

    fun copyDer(): ByteArray {
        check(!isClosed) {
            "authentication certificate is closed"
        }
        return ownedDer.copyOf()
    }

    fun copyOwned(): NativeAuthenticationCertificate =
        NativeAuthenticationCertificate(
            keyProfile = keyProfile,
            ownedDer = copyDer(),
        )

    override fun close() {
        if (!isClosed) {
            ownedDer.fill(0)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NativeAuthenticationCertificate(profile=" + keyProfile +
            ", length=" + derLength +
            ", closed=" + isClosed + ")"
}

internal class NativeQualifiedCertificate(
    val keyProfile: NativeCardKeyProfile,
    private val ownedDer: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val derLength: Int
        get() = ownedDer.size

    fun copyDer(): ByteArray {
        check(!isClosed) {
            "qualified certificate is closed"
        }
        return ownedDer.copyOf()
    }

    fun copyOwned(): NativeQualifiedCertificate =
        NativeQualifiedCertificate(
            keyProfile = keyProfile,
            ownedDer = copyDer(),
        )

    override fun close() {
        if (!isClosed) {
            ownedDer.fill(0)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NativeQualifiedCertificate(profile=" + keyProfile +
            ", length=" + derLength +
            ", closed=" + isClosed + ")"
}

internal enum class NativeCertificateReadFailure {
    CARD_UNAVAILABLE,
    REJECTED,
    TRANSPORT_ERROR,
    INVALID_CERTIFICATE,
    PACE_REJECTED,
    BRIDGE_ERROR,
    ACTIVATION_REQUIRED,
}

internal sealed interface NativeCertificateReadResult<out Certificate> {
    class Success<Certificate>(
        val certificate: Certificate,
    ) : NativeCertificateReadResult<Certificate> {
        override fun toString(): String = "Success(" + certificate + ")"
    }

    data class Failure(
        val kind: NativeCertificateReadFailure,
    ) : NativeCertificateReadResult<Nothing>
}

/** Synchronous byte-moving callback invoked only inside one native operation. */
internal interface NativeBlockExchange {
    fun exchangePublic(block: ByteArray): ByteArray

    fun exchangeCredential(block: ByteArray): ByteArray
}

/** Stable tags shared with the narrow Rust callback parser. */
internal enum class NativeExchangeReplyTag(
    val wireValue: Byte,
) {
    RESPONSE(0),
    NO_CARD(1),
    TIMEOUT_UNKNOWN_STATE(2),
    CARD_RESET(3),
    PROTOCOL_DESYNC(4),
    READER_REMOVED(5),
    BACKEND_FAILURE(6),
}

internal object NativeCore {
    private const val LIBRARY_NAME = "refineid_android_core"
    private const val ATR_INVALID = 0
    private const val ATR_VALID_T0_DIRECT = 1
    private const val ATR_VALID_T0_INVERSE = 2
    private const val ATR_VALID_NON_T0_DIRECT = 3
    private const val ATR_VALID_NON_T0_INVERSE = 4
    private const val CARD_OPERATION_BRIDGE_ERROR = 0
    private const val CARD_OPERATION_SUCCEEDED = 1
    private const val CARD_OPERATION_CARD_UNAVAILABLE = 2
    private const val CARD_OPERATION_REJECTED = 3
    private const val CARD_OPERATION_TRANSPORT_ERROR = 4

    internal val isLoaded =
        runCatching {
            System.loadLibrary(LIBRARY_NAME)
        }.also { result ->
            AppTrace.nativeLibraryLoadCompleted(isSuccessful = result.isSuccess)
        }.isSuccess

    fun validateAtr(atr: ByteArray): AtrValidation {
        val result =
            if (!isLoaded) {
                AtrValidation.BRIDGE_ERROR
            } else {
                try {
                    when (validateAtrNative(atr)) {
                        ATR_VALID_T0_DIRECT -> AtrValidation.VALID_T0_DIRECT
                        ATR_VALID_T0_INVERSE -> AtrValidation.VALID_T0_INVERSE
                        ATR_VALID_NON_T0_DIRECT -> AtrValidation.VALID_NON_T0_DIRECT
                        ATR_VALID_NON_T0_INVERSE -> AtrValidation.VALID_NON_T0_INVERSE
                        ATR_INVALID -> AtrValidation.INVALID
                        else -> AtrValidation.BRIDGE_ERROR
                    }
                } catch (_: LinkageError) {
                    AtrValidation.BRIDGE_ERROR
                }
            }
        AppTrace.nativeAtrValidationCompleted(result)
        return result
    }

    fun selectPkcs15Application(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeCardOperationResult {
        val startedAt = AppTrace.nativePkcs15SelectionStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativeCardOperationResult.BRIDGE_ERROR
            } else {
                try {
                    when (
                        selectPkcs15ApplicationNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        )
                    ) {
                        CARD_OPERATION_SUCCEEDED -> {
                            NativeCardOperationResult.SUCCEEDED
                        }

                        CARD_OPERATION_CARD_UNAVAILABLE -> {
                            NativeCardOperationResult.CARD_UNAVAILABLE
                        }

                        CARD_OPERATION_REJECTED -> {
                            NativeCardOperationResult.REJECTED
                        }

                        CARD_OPERATION_TRANSPORT_ERROR -> {
                            NativeCardOperationResult.TRANSPORT_ERROR
                        }

                        CARD_OPERATION_BRIDGE_ERROR -> {
                            NativeCardOperationResult.BRIDGE_ERROR
                        }

                        else -> {
                            NativeCardOperationResult.BRIDGE_ERROR
                        }
                    }
                } catch (_: LinkageError) {
                    NativeCardOperationResult.BRIDGE_ERROR
                } catch (_: RuntimeException) {
                    NativeCardOperationResult.BRIDGE_ERROR
                }
            }
        AppTrace.nativePkcs15SelectionCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun readAuthenticationCertificate(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativeCertificateReadResult<NativeAuthenticationCertificate> {
        val startedAt = AppTrace.nativeAuthenticationCertificateReadStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativeCertificateReadResult.Failure(
                    NativeCertificateReadFailure.BRIDGE_ERROR,
                )
            } else {
                try {
                    NativeCertificateReply.decode(
                        reply =
                            readAuthenticationCertificateNative(
                                exchangeLevel = exchangeLevel.wireValue,
                                callback = exchange,
                            ),
                        certificate = { profile, der ->
                            NativeAuthenticationCertificate(
                                keyProfile = profile,
                                ownedDer = der,
                            )
                        },
                    )
                } catch (_: LinkageError) {
                    NativeCertificateReadResult.Failure(
                        NativeCertificateReadFailure.BRIDGE_ERROR,
                    )
                } catch (_: RuntimeException) {
                    NativeCertificateReadResult.Failure(
                        NativeCertificateReadFailure.BRIDGE_ERROR,
                    )
                }
            }
        AppTrace.nativeAuthenticationCertificateReadCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun probePin1Status(
        exchangeLevel: NativeCardExchangeLevel,
        exchange: NativeBlockExchange,
    ): NativePin1PreflightResult {
        val startedAt = AppTrace.nativePin1StatusProbeStarted(exchangeLevel)
        val result =
            if (!isLoaded) {
                NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin1PreflightReply.decode(
                        probePin1StatusNative(
                            exchangeLevel = exchangeLevel.wireValue,
                            callback = exchange,
                        ),
                    )
                } catch (_: LinkageError) {
                    NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativePin1StatusProbeCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    fun authenticateAndSign(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        message: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult =
        authenticateAndSignInput(
            exchangeLevel = exchangeLevel,
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.MESSAGE,
            pin1 = pin1,
            input = message,
            exchange = exchange,
        )

    fun authenticateAndSignPrehashed(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        pin1: Pin1Submission,
        digest: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult =
        authenticateAndSignInput(
            exchangeLevel = exchangeLevel,
            algorithm = algorithm,
            inputMode = AuthenticationSigningInputMode.PREHASHED,
            pin1 = pin1,
            input = digest,
            exchange = exchange,
        )

    private fun authenticateAndSignInput(
        exchangeLevel: NativeCardExchangeLevel,
        algorithm: AuthenticationSigningAlgorithm,
        inputMode: AuthenticationSigningInputMode,
        pin1: Pin1Submission,
        input: ByteArray,
        exchange: NativeBlockExchange,
    ): NativeAuthenticationSignResult {
        val startedAt =
            AppTrace.nativeAuthenticationSignStarted(
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
                        if (!isLoaded) {
                            NativeAuthenticationSignResult.Failure(
                                NativeAuthenticationSignFailure.BRIDGE_ERROR,
                            )
                        } else {
                            NativeAuthenticationSignReply.decode(
                                authenticateAndSignNative(
                                    exchangeLevel = exchangeLevel.wireValue,
                                    request = algorithm.requestWireValue(inputMode),
                                    pin = pinBytes,
                                    input = input,
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
        AppTrace.nativeAuthenticationSignCompleted(
            startedAt = startedAt,
            result = result,
        )
        return result
    }

    @JvmStatic
    private external fun validateAtrNative(atr: ByteArray): Int

    @JvmStatic
    private external fun selectPkcs15ApplicationNative(
        exchangeLevel: Int,
        callback: Any,
    ): Int

    @JvmStatic
    private external fun readAuthenticationCertificateNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun probePin1StatusNative(
        exchangeLevel: Int,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun authenticateAndSignNative(
        exchangeLevel: Int,
        request: Int,
        pin: ByteArray,
        input: ByteArray,
        callback: Any,
    ): ByteArray
}

internal object NativeCertificateReply {
    fun <Certificate> decode(
        reply: ByteArray,
        certificate: (NativeCardKeyProfile, ByteArray) -> Certificate,
    ): NativeCertificateReadResult<Certificate> =
        try {
            if (reply.isEmpty() || reply.size > MAXIMUM_REPLY_LENGTH) {
                return bridgeFailure()
            }

            when (reply[CERTIFICATE_REPLY_TAG_OFFSET].toInt()) {
                CERTIFICATE_SUCCEEDED -> {
                    decodeSuccess(reply, certificate)
                }

                CERTIFICATE_CARD_UNAVAILABLE -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.CARD_UNAVAILABLE,
                    )
                }

                CERTIFICATE_REJECTED -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.REJECTED,
                    )
                }

                CERTIFICATE_TRANSPORT_ERROR -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.TRANSPORT_ERROR,
                    )
                }

                CERTIFICATE_INVALID -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.INVALID_CERTIFICATE,
                    )
                }

                CERTIFICATE_PACE_REJECTED -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.PACE_REJECTED,
                    )
                }

                CERTIFICATE_BRIDGE_ERROR -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.BRIDGE_ERROR,
                    )
                }

                CERTIFICATE_ACTIVATION_REQUIRED -> {
                    decodeFailure(
                        reply,
                        NativeCertificateReadFailure.ACTIVATION_REQUIRED,
                    )
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(0)
        }

    private fun <Certificate> decodeSuccess(
        reply: ByteArray,
        certificate: (NativeCardKeyProfile, ByteArray) -> Certificate,
    ): NativeCertificateReadResult<Certificate> {
        if (reply.size <= CERTIFICATE_REPLY_HEADER_LENGTH) {
            return bridgeFailure()
        }
        val profile =
            when (reply[KEY_PROFILE_OFFSET].toInt()) {
                KEY_PROFILE_RSA_2048 -> NativeCardKeyProfile.RSA_2048
                KEY_PROFILE_RSA_3072 -> NativeCardKeyProfile.RSA_3072
                KEY_PROFILE_ECDSA_P256 -> NativeCardKeyProfile.ECDSA_P256
                KEY_PROFILE_ECDSA_P384 -> NativeCardKeyProfile.ECDSA_P384
                else -> return bridgeFailure()
            }
        return NativeCertificateReadResult.Success(
            certificate(
                profile,
                reply.copyOfRange(CERTIFICATE_REPLY_HEADER_LENGTH, reply.size),
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativeCertificateReadFailure,
    ): NativeCertificateReadResult<Nothing> =
        if (reply.size == FAILURE_REPLY_LENGTH) {
            NativeCertificateReadResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun bridgeFailure(): NativeCertificateReadResult.Failure =
        NativeCertificateReadResult.Failure(
            NativeCertificateReadFailure.BRIDGE_ERROR,
        )

    private const val CERTIFICATE_BRIDGE_ERROR = 0
    private const val CERTIFICATE_SUCCEEDED = 1
    private const val CERTIFICATE_CARD_UNAVAILABLE = 2
    private const val CERTIFICATE_REJECTED = 3
    private const val CERTIFICATE_TRANSPORT_ERROR = 4
    private const val CERTIFICATE_INVALID = 5
    private const val CERTIFICATE_PACE_REJECTED = 6
    private const val CERTIFICATE_ACTIVATION_REQUIRED = 7

    private const val KEY_PROFILE_RSA_2048 = 0
    private const val KEY_PROFILE_RSA_3072 = 1
    private const val KEY_PROFILE_ECDSA_P256 = 2
    private const val KEY_PROFILE_ECDSA_P384 = 3

    private const val FAILURE_REPLY_LENGTH = 1
    private const val CERTIFICATE_REPLY_TAG_OFFSET = 0
    private const val KEY_PROFILE_OFFSET = 1
    private const val CERTIFICATE_REPLY_HEADER_LENGTH = 2
    private const val MAXIMUM_CERTIFICATE_LENGTH = 16 * 1_024
    private const val MAXIMUM_REPLY_LENGTH =
        CERTIFICATE_REPLY_HEADER_LENGTH + MAXIMUM_CERTIFICATE_LENGTH
}
