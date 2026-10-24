package fi.refineid.android.core

internal sealed interface NativeContactlessOpenResult {
    class Success(
        val certificate: NativeAuthenticationCertificate,
        val preflight: NativePin1Preflight,
    ) : NativeContactlessOpenResult {
        override fun toString(): String = "Success(" + certificate + ", " + preflight + ")"
    }

    /** The card still awaits activation: its scheme, and which PINs. */
    class ActivationRequired(
        val certificate: NativeAuthenticationCertificate,
        val scheme: CardManagementScheme,
        val needs: CardActivationNeeds,
    ) : NativeContactlessOpenResult {
        override fun toString(): String = "ActivationRequired(" + certificate + ", " + scheme + ", " + needs + ")"
    }

    data class Failure(
        val kind: NativeCertificateReadFailure,
    ) : NativeContactlessOpenResult
}

/**
 * Strict decoder for the nested contactless open reply:
 * `[succeeded tag, preflight-reply length, preflight reply, certificate
 * reply]`, `[activation-required tag, activation scheme, activation needs,
 * key profile, certificate DER]`, or one certificate-vocabulary failure
 * byte. The nested parts reuse the established strict sub-decoders
 * wholesale.
 */
internal object NativeContactlessOpenReply {
    fun decode(reply: ByteArray): NativeContactlessOpenResult =
        try {
            if (reply.isEmpty()) {
                bridgeFailure()
            } else if (reply[TAG_OFFSET].toUnsignedInt() == OPEN_SUCCEEDED) {
                decodeSuccess(reply)
            } else if (reply[TAG_OFFSET].toUnsignedInt() == OPEN_ACTIVATION_REQUIRED &&
                reply.size >= MINIMUM_ACTIVATION_REPLY_LENGTH
            ) {
                decodeActivationRequired(reply)
            } else {
                decodeFailure(reply)
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeSuccess(reply: ByteArray): NativeContactlessOpenResult {
        if (reply.size < MINIMUM_SUCCESS_REPLY_LENGTH) {
            return bridgeFailure()
        }
        if (reply[PREFLIGHT_LENGTH_OFFSET].toUnsignedInt() != PREFLIGHT_REPLY_LENGTH) {
            return bridgeFailure()
        }
        val preflightResult =
            NativePin1PreflightReply.decode(
                reply.copyOfRange(HEADER_LENGTH, HEADER_LENGTH + PREFLIGHT_REPLY_LENGTH),
            )
        val certificateResult =
            NativeCertificateReply.decode(
                reply = reply.copyOfRange(HEADER_LENGTH + PREFLIGHT_REPLY_LENGTH, reply.size),
                certificate = { profile, der ->
                    NativeAuthenticationCertificate(
                        keyProfile = profile,
                        ownedDer = der,
                    )
                },
            )
        if (
            preflightResult !is NativePin1PreflightResult.Success ||
            certificateResult !is NativeCertificateReadResult.Success
        ) {
            (certificateResult as? NativeCertificateReadResult.Success)?.certificate?.close()
            return bridgeFailure()
        }
        return NativeContactlessOpenResult.Success(
            certificate = certificateResult.certificate,
            preflight = preflightResult.preflight,
        )
    }

    private fun decodeActivationRequired(reply: ByteArray): NativeContactlessOpenResult {
        val scheme = decodeActivationScheme(reply[ACTIVATION_SCHEME_OFFSET].toUnsignedInt())
        val needs = decodeActivationNeeds(reply[ACTIVATION_NEEDS_OFFSET].toUnsignedInt())
        if (scheme == CardManagementScheme.UNKNOWN || !needs.any) {
            return bridgeFailure()
        }
        val certPayload =
            byteArrayOf(OPEN_SUCCEEDED.toByte()) +
                reply.copyOfRange(ACTIVATION_HEADER_LENGTH, reply.size)
        val certificateResult =
            NativeCertificateReply.decode(
                reply = certPayload,
                certificate = { profile, der ->
                    NativeAuthenticationCertificate(
                        keyProfile = profile,
                        ownedDer = der,
                    )
                },
            )
        return when (certificateResult) {
            is NativeCertificateReadResult.Success -> {
                NativeContactlessOpenResult.ActivationRequired(certificateResult.certificate, scheme, needs)
            }

            is NativeCertificateReadResult.Failure -> {
                NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.ACTIVATION_REQUIRED)
            }
        }
    }

    private fun decodeFailure(reply: ByteArray): NativeContactlessOpenResult =
        when (
            val result =
                NativeCertificateReply.decode(
                    reply = reply.copyOf(),
                    certificate = { profile, der ->
                        NativeAuthenticationCertificate(
                            keyProfile = profile,
                            ownedDer = der,
                        )
                    },
                )
        ) {
            is NativeCertificateReadResult.Success -> {
                result.certificate.close()
                bridgeFailure()
            }

            is NativeCertificateReadResult.Failure -> {
                NativeContactlessOpenResult.Failure(result.kind)
            }
        }

    private fun bridgeFailure(): NativeContactlessOpenResult.Failure =
        NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toInt() and UNSIGNED_BYTE_MASK

    private const val OPEN_SUCCEEDED = 1
    private const val OPEN_ACTIVATION_REQUIRED = 7

    private const val TAG_OFFSET = 0
    private const val PREFLIGHT_LENGTH_OFFSET = 1
    private const val HEADER_LENGTH = 2

    private const val PREFLIGHT_REPLY_LENGTH = 5
    private const val MINIMUM_CERTIFICATE_REPLY_LENGTH = 3

    private const val ACTIVATION_SCHEME_OFFSET = 1
    private const val ACTIVATION_NEEDS_OFFSET = 2
    private const val ACTIVATION_HEADER_LENGTH = 3
    private const val MINIMUM_ACTIVATION_REPLY_LENGTH =
        ACTIVATION_HEADER_LENGTH + MINIMUM_CERTIFICATE_REPLY_LENGTH - 1
    private const val MINIMUM_SUCCESS_REPLY_LENGTH =
        HEADER_LENGTH + PREFLIGHT_REPLY_LENGTH + MINIMUM_CERTIFICATE_REPLY_LENGTH
    private const val UNSIGNED_BYTE_MASK = 0xFF
}
