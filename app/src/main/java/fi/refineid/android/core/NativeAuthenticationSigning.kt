package fi.refineid.android.core

internal const val PIN1_MINIMUM_LENGTH = 4
internal const val PIN1_MAXIMUM_LENGTH = 12
internal val DIGIT_ZERO_BYTE = '0'.code.toByte()
internal val DIGIT_NINE_BYTE = '9'.code.toByte()
internal const val MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH = 1_024 * 1_024
internal const val RSA_3072_KEY_LENGTH_BITS = 3_072
internal const val P384_COORDINATE_LENGTH_BITS = 384
internal const val SHA256_DIGEST_LENGTH_BITS = 256
internal const val SHA384_DIGEST_LENGTH_BITS = 384
internal const val SHA512_DIGEST_LENGTH_BITS = 512
internal const val SHA256_DIGEST_LENGTH_BYTES = SHA256_DIGEST_LENGTH_BITS / Byte.SIZE_BITS
internal const val SHA384_DIGEST_LENGTH_BYTES = SHA384_DIGEST_LENGTH_BITS / Byte.SIZE_BITS
internal const val SHA512_DIGEST_LENGTH_BYTES = SHA512_DIGEST_LENGTH_BITS / Byte.SIZE_BITS
private const val RSA_3072_SIGNATURE_LENGTH_BYTES = RSA_3072_KEY_LENGTH_BITS / Byte.SIZE_BITS
private const val P384_RAW_SIGNATURE_LENGTH_BYTES =
    2 * P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS

internal object NativeAuthenticationSignWire {
    const val ALGORITHM_RSA_PKCS1_SHA256 = 0
    const val ALGORITHM_RSA_PSS_SHA256 = 1
    const val ALGORITHM_ECDSA_P384_SHA256 = 2
    const val ALGORITHM_ECDSA_P384_SHA384 = 3
    const val REQUEST_PREHASHED_RSA_PKCS1_SHA256 = 4
    const val REQUEST_PREHASHED_RSA_PSS_SHA256 = 5
    const val REQUEST_PREHASHED_ECDSA_P384_SHA256 = 6
    const val REQUEST_PREHASHED_ECDSA_P384_SHA384 = 7
    const val ALGORITHM_RSA_PKCS1_SHA384 = 8
    const val ALGORITHM_RSA_PSS_SHA384 = 9
    const val ALGORITHM_RSA_PKCS1_SHA512 = 10
    const val ALGORITHM_RSA_PSS_SHA512 = 11
    const val REQUEST_PREHASHED_RSA_PKCS1_SHA384 = 12
    const val REQUEST_PREHASHED_RSA_PSS_SHA384 = 13
    const val REQUEST_PREHASHED_RSA_PKCS1_SHA512 = 14
    const val REQUEST_PREHASHED_RSA_PSS_SHA512 = 15

    const val BRIDGE_ERROR_TAG = 0
    const val SUCCESS_TAG = 1
    const val CARD_UNAVAILABLE_TAG = 2
    const val TRANSPORT_ERROR_TAG = 3
    const val INVALID_PIN_TAG = 4
    const val SAFETY_REFUSED_TAG = 5
    const val PIN_LOCKED_TAG = 6
    const val WRONG_PIN_TAG = 7
    const val VERIFICATION_REJECTED_TAG = 8
    const val SIGNING_REJECTED_TAG = 9
    const val PACE_REJECTED_TAG = 10

    const val TAG_OFFSET = 0
    const val ALGORITHM_OFFSET = 1
    const val FAILURE_REPLY_LENGTH = 1
    const val SIGNATURE_REPLY_HEADER_LENGTH = 2
}

internal enum class AuthenticationSigningInputMode {
    MESSAGE,
    PREHASHED,
}

internal enum class AuthenticationDigest(
    val jcaName: String,
    val length: Int,
) {
    SHA256(
        jcaName = "SHA-256",
        length = SHA256_DIGEST_LENGTH_BYTES,
    ),
    SHA384(
        jcaName = "SHA-384",
        length = SHA384_DIGEST_LENGTH_BYTES,
    ),
    SHA512(
        jcaName = "SHA-512",
        length = SHA512_DIGEST_LENGTH_BYTES,
    ),
}

internal enum class AuthenticationSigningAlgorithm(
    val wireValue: Int,
    val keyProfile: NativeCardKeyProfile,
    val signatureLength: Int,
    val digest: AuthenticationDigest,
) {
    RSA_PKCS1_SHA256(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PKCS1_SHA256,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA256,
    ),
    RSA_PSS_SHA256(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PSS_SHA256,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA256,
    ),
    ECDSA_P384_SHA256(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_ECDSA_P384_SHA256,
        keyProfile = NativeCardKeyProfile.ECDSA_P384,
        signatureLength = P384_RAW_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA256,
    ),
    ECDSA_P384_SHA384(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_ECDSA_P384_SHA384,
        keyProfile = NativeCardKeyProfile.ECDSA_P384,
        signatureLength = P384_RAW_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA384,
    ),
    RSA_PKCS1_SHA384(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PKCS1_SHA384,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA384,
    ),
    RSA_PSS_SHA384(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PSS_SHA384,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA384,
    ),
    RSA_PKCS1_SHA512(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PKCS1_SHA512,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA512,
    ),
    RSA_PSS_SHA512(
        wireValue = NativeAuthenticationSignWire.ALGORITHM_RSA_PSS_SHA512,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_SIGNATURE_LENGTH_BYTES,
        digest = AuthenticationDigest.SHA512,
    ),
    ;

    val digestLength: Int
        get() = digest.length
}

internal fun AuthenticationSigningAlgorithm.requestWireValue(inputMode: AuthenticationSigningInputMode): Int =
    when (inputMode) {
        AuthenticationSigningInputMode.MESSAGE -> {
            wireValue
        }

        AuthenticationSigningInputMode.PREHASHED -> {
            when (this) {
                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA256 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA256
                }

                AuthenticationSigningAlgorithm.RSA_PSS_SHA256 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA256
                }

                AuthenticationSigningAlgorithm.ECDSA_P384_SHA256 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_ECDSA_P384_SHA256
                }

                AuthenticationSigningAlgorithm.ECDSA_P384_SHA384 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_ECDSA_P384_SHA384
                }

                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA384
                }

                AuthenticationSigningAlgorithm.RSA_PSS_SHA384 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA384
                }

                AuthenticationSigningAlgorithm.RSA_PKCS1_SHA512 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA512
                }

                AuthenticationSigningAlgorithm.RSA_PSS_SHA512 -> {
                    NativeAuthenticationSignWire.REQUEST_PREHASHED_RSA_PSS_SHA512
                }
            }
        }
    }

internal fun AuthenticationSigningAlgorithm.acceptsInputLength(
    inputMode: AuthenticationSigningInputMode,
    inputLength: Int,
): Boolean =
    when (inputMode) {
        AuthenticationSigningInputMode.MESSAGE -> {
            inputLength in 0..MAXIMUM_AUTHENTICATION_MESSAGE_LENGTH
        }

        AuthenticationSigningInputMode.PREHASHED -> {
            inputLength == digestLength
        }
    }

/** One manually entered PIN1 submission, transferred to at most one native call. */
internal class Pin1Submission private constructor(
    private var ownedBytes: ByteArray?,
) : AutoCloseable {
    fun <T> consume(operation: (ByteArray) -> T): T {
        val bytes =
            synchronized(this) {
                checkNotNull(ownedBytes) {
                    "PIN1 submission is no longer available"
                }.also {
                    ownedBytes = null
                }
            }
        return try {
            operation(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    /** Copy the digits without consuming the submission, or null if spent. */
    fun copyBytes(): ByteArray? =
        synchronized(this) {
            ownedBytes?.copyOf()
        }

    fun rawBytes(): ByteArray =
        synchronized(this) {
            checkNotNull(ownedBytes) { "PIN1 submission has already been closed" }.copyOf()
        }

    override fun close() {
        synchronized(this) {
            ownedBytes?.fill(0)
            ownedBytes = null
        }
    }

    override fun toString(): String = "Pin1Submission([redacted])"

    companion object {
        fun acceptsEntry(input: CharSequence): Boolean {
            return input.length <= PIN1_MAXIMUM_LENGTH && input.all { it in '0'..'9' }
        }

        fun isComplete(input: CharSequence): Boolean = input.length >= PIN1_MINIMUM_LENGTH && acceptsEntry(input)

        fun from(input: CharSequence): Pin1Submission {
            require(isComplete(input)) {
                "PIN1 has an invalid shape"
            }
            val bytes = ByteArray(input.length)
            for (index in input.indices) {
                val character = input[index]
                bytes[index] = character.code.toByte()
            }
            return Pin1Submission(bytes)
        }

        /** Wrap already-validated digit bytes, taking ownership of them. */
        fun fromOwnedBytes(bytes: ByteArray): Pin1Submission {
            val isValidShape =
                bytes.size in PIN1_MINIMUM_LENGTH..PIN1_MAXIMUM_LENGTH &&
                    bytes.all { it in DIGIT_ZERO_BYTE..DIGIT_NINE_BYTE }
            if (!isValidShape) {
                bytes.fill(0)
                throw IllegalArgumentException("PIN1 has an invalid shape")
            }
            return Pin1Submission(bytes)
        }
    }
}

internal class NativeAuthenticationSignature(
    val algorithm: AuthenticationSigningAlgorithm,
    private val ownedBytes: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val length: Int
        get() = ownedBytes.size

    fun <T> useBytes(operation: (ByteArray) -> T): T {
        check(!isClosed) {
            "authentication signature is closed"
        }
        return operation(ownedBytes)
    }

    fun copyBytes(): ByteArray = useBytes(ByteArray::copyOf)

    override fun close() {
        if (!isClosed) {
            ownedBytes.fill(0)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NativeAuthenticationSignature(algorithm=" + algorithm +
            ", length=" + length +
            ", closed=" + isClosed + ")"
}

internal enum class NativeAuthenticationSignFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    INVALID_PIN,
    SAFETY_REFUSED,
    PIN_LOCKED,
    WRONG_PIN,
    VERIFICATION_REJECTED,
    SIGNING_REJECTED,
    PACE_REJECTED,
    BRIDGE_ERROR,
}

internal sealed interface NativeAuthenticationSignResult {
    class Success(
        val signature: NativeAuthenticationSignature,
    ) : NativeAuthenticationSignResult {
        override fun toString(): String = "Success(" + signature + ")"
    }

    data class Failure(
        val kind: NativeAuthenticationSignFailure,
    ) : NativeAuthenticationSignResult
}

internal enum class AuthenticationSignFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    INVALID_PIN,
    SAFETY_REFUSED,
    PIN_LOCKED,
    WRONG_PIN,
    VERIFICATION_REJECTED,
    SIGNING_REJECTED,
    KEY_PROFILE_MISMATCH,
    LOCAL_VERIFICATION_FAILED,
    BRIDGE_ERROR,
}

internal sealed interface AuthenticationSignResult {
    class Success(
        val signature: NativeAuthenticationSignature,
    ) : AuthenticationSignResult {
        override fun toString(): String = "Success(" + signature + ")"
    }

    data class Failure(
        val kind: AuthenticationSignFailure,
    ) : AuthenticationSignResult
}

/** Strict decoder for the fixed native authentication-signature vocabulary. */
internal object NativeAuthenticationSignReply {
    fun decode(reply: ByteArray): NativeAuthenticationSignResult =
        try {
            if (reply.isEmpty()) {
                return bridgeFailure()
            }
            when (reply[NativeAuthenticationSignWire.TAG_OFFSET].toUnsignedInt()) {
                NativeAuthenticationSignWire.SUCCESS_TAG -> {
                    decodeSuccess(reply)
                }

                NativeAuthenticationSignWire.CARD_UNAVAILABLE_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.CARD_UNAVAILABLE)
                }

                NativeAuthenticationSignWire.TRANSPORT_ERROR_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.TRANSPORT_ERROR)
                }

                NativeAuthenticationSignWire.INVALID_PIN_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.INVALID_PIN)
                }

                NativeAuthenticationSignWire.SAFETY_REFUSED_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.SAFETY_REFUSED)
                }

                NativeAuthenticationSignWire.PIN_LOCKED_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.PIN_LOCKED)
                }

                NativeAuthenticationSignWire.WRONG_PIN_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.WRONG_PIN)
                }

                NativeAuthenticationSignWire.VERIFICATION_REJECTED_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.VERIFICATION_REJECTED)
                }

                NativeAuthenticationSignWire.SIGNING_REJECTED_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.SIGNING_REJECTED)
                }

                NativeAuthenticationSignWire.PACE_REJECTED_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.PACE_REJECTED)
                }

                NativeAuthenticationSignWire.BRIDGE_ERROR_TAG -> {
                    decodeFailure(reply, NativeAuthenticationSignFailure.BRIDGE_ERROR)
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeSuccess(reply: ByteArray): NativeAuthenticationSignResult {
        if (reply.size <= NativeAuthenticationSignWire.SIGNATURE_REPLY_HEADER_LENGTH) {
            return bridgeFailure()
        }
        val algorithm =
            AuthenticationSigningAlgorithm.entries.firstOrNull {
                it.wireValue ==
                    reply[NativeAuthenticationSignWire.ALGORITHM_OFFSET].toUnsignedInt()
            } ?: return bridgeFailure()
        if (
            reply.size !=
            NativeAuthenticationSignWire.SIGNATURE_REPLY_HEADER_LENGTH +
            algorithm.signatureLength
        ) {
            return bridgeFailure()
        }
        return NativeAuthenticationSignResult.Success(
            NativeAuthenticationSignature(
                algorithm = algorithm,
                ownedBytes =
                    reply.copyOfRange(
                        NativeAuthenticationSignWire.SIGNATURE_REPLY_HEADER_LENGTH,
                        reply.size,
                    ),
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativeAuthenticationSignFailure,
    ): NativeAuthenticationSignResult =
        if (reply.size == NativeAuthenticationSignWire.FAILURE_REPLY_LENGTH) {
            NativeAuthenticationSignResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun bridgeFailure(): NativeAuthenticationSignResult.Failure =
        NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()
}
