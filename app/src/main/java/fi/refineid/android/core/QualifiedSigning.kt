package fi.refineid.android.core

private const val PIN2_MINIMUM_LENGTH = 6
internal const val PIN2_MAXIMUM_LENGTH = 12
internal const val MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH = 1_024 * 1_024
private const val RSA_3072_QUALIFIED_SIGNATURE_LENGTH_BYTES =
    RSA_3072_KEY_LENGTH_BITS / Byte.SIZE_BITS
private const val ECDSA_COORDINATE_COUNT = 2
private const val P384_QUALIFIED_RAW_SIGNATURE_LENGTH_BYTES =
    ECDSA_COORDINATE_COUNT * P384_COORDINATE_LENGTH_BITS / Byte.SIZE_BITS
private const val ZERO_BYTE: Byte = 0

internal object NativeQualifiedSignWire {
    const val ALGORITHM_RSA_PKCS1_SHA384 = 0
    const val ALGORITHM_ECDSA_P384_SHA384 = 1
    const val REQUEST_PREHASHED_RSA_PKCS1_SHA384 = 2
    const val REQUEST_PREHASHED_ECDSA_P384_SHA384 = 3

    const val BRIDGE_ERROR_TAG = 0
    const val SUCCESS_TAG = 1
    const val CARD_UNAVAILABLE_TAG = 2
    const val TRANSPORT_ERROR_TAG = 3
    const val INVALID_PIN_TAG = 4
    const val SAFETY_REFUSED_TAG = 5
    const val PIN_LOCKED_TAG = 6
    const val WRONG_PIN_TAG = 7
    const val VERIFICATION_REJECTED_TAG = 8
    const val CERTIFICATE_REJECTED_TAG = 9
    const val INVALID_CERTIFICATE_TAG = 10
    const val CERTIFICATE_MISMATCH_TAG = 11
    const val KEY_PROFILE_MISMATCH_TAG = 12
    const val SIGNING_REJECTED_TAG = 13

    const val TAG_OFFSET = 0
    const val ALGORITHM_OFFSET = 1
    const val FAILURE_REPLY_LENGTH = 1
    const val SIGNATURE_REPLY_HEADER_LENGTH = 2
}

internal enum class QualifiedSigningInputMode {
    MESSAGE,
    PREHASHED,
}

internal enum class QualifiedSigningAlgorithm(
    val wireValue: Int,
    val keyProfile: NativeCardKeyProfile,
    val signatureLength: Int,
    val digestLength: Int = SHA384_DIGEST_LENGTH_BYTES,
) {
    RSA_PKCS1_SHA384(
        wireValue = NativeQualifiedSignWire.ALGORITHM_RSA_PKCS1_SHA384,
        keyProfile = NativeCardKeyProfile.RSA_3072,
        signatureLength = RSA_3072_QUALIFIED_SIGNATURE_LENGTH_BYTES,
    ),
    ECDSA_P384_SHA384(
        wireValue = NativeQualifiedSignWire.ALGORITHM_ECDSA_P384_SHA384,
        keyProfile = NativeCardKeyProfile.ECDSA_P384,
        signatureLength = P384_QUALIFIED_RAW_SIGNATURE_LENGTH_BYTES,
    ),
}

internal fun QualifiedSigningAlgorithm.requestWireValue(inputMode: QualifiedSigningInputMode): Int =
    when (inputMode) {
        QualifiedSigningInputMode.MESSAGE -> {
            wireValue
        }

        QualifiedSigningInputMode.PREHASHED -> {
            when (this) {
                QualifiedSigningAlgorithm.RSA_PKCS1_SHA384 -> {
                    NativeQualifiedSignWire.REQUEST_PREHASHED_RSA_PKCS1_SHA384
                }

                QualifiedSigningAlgorithm.ECDSA_P384_SHA384 -> {
                    NativeQualifiedSignWire.REQUEST_PREHASHED_ECDSA_P384_SHA384
                }
            }
        }
    }

internal fun QualifiedSigningAlgorithm.acceptsInputLength(
    inputMode: QualifiedSigningInputMode,
    length: Int,
): Boolean =
    when (inputMode) {
        QualifiedSigningInputMode.MESSAGE -> length in 0..MAXIMUM_QUALIFIED_SIGNING_CONTENT_LENGTH
        QualifiedSigningInputMode.PREHASHED -> length == digestLength
    }

internal fun QualifiedSigningAlgorithm.acceptsContentLength(length: Int): Boolean =
    acceptsInputLength(QualifiedSigningInputMode.MESSAGE, length)

/** One manually entered PIN2 submission, transferred to at most one native call. */
internal class Pin2Submission private constructor(
    private var ownedBytes: ByteArray?,
) : AutoCloseable {
    fun <T> consume(operation: (ByteArray) -> T): T {
        val bytes =
            synchronized(this) {
                checkNotNull(ownedBytes) {
                    "PIN2 submission is no longer available"
                }.also {
                    ownedBytes = null
                }
            }
        return try {
            operation(bytes)
        } finally {
            bytes.fill(ZERO_BYTE)
        }
    }

    fun copyBytes(): ByteArray =
        synchronized(this) {
            checkNotNull(ownedBytes) { "PIN2 submission has already been closed" }.copyOf()
        }

    /**
     * Borrows the owned byte buffer under lock for scoped inspection (e.g., hashing or fingerprinting).
     * The passed [operation] MUST NOT retain, leak, or mutate the borrowed array.
     */
    fun <T> peekBytes(operation: (ByteArray) -> T): T =
        synchronized(this) {
            val bytes = checkNotNull(ownedBytes) { "PIN2 submission has already been closed" }
            operation(bytes)
        }

    override fun close() {
        synchronized(this) {
            ownedBytes?.fill(ZERO_BYTE)
            ownedBytes = null
        }
    }

    override fun toString(): String = "Pin2Submission([redacted])"

    companion object {
        fun acceptsEntry(input: CharSequence): Boolean =
            input.length <= PIN2_MAXIMUM_LENGTH && input.all { it in '0'..'9' }

        fun isComplete(input: CharSequence): Boolean = input.length >= PIN2_MINIMUM_LENGTH && acceptsEntry(input)

        fun from(input: CharSequence): Pin2Submission {
            require(isComplete(input)) {
                "PIN2 has an invalid shape"
            }
            val bytes = ByteArray(input.length)
            for (index in input.indices) {
                bytes[index] = input[index].code.toByte()
            }
            return Pin2Submission(bytes)
        }

        /** Wrap already-validated digit bytes, taking ownership of them. */
        fun fromOwnedBytes(bytes: ByteArray): Pin2Submission {
            val isValidShape =
                bytes.size in PIN2_MINIMUM_LENGTH..PIN2_MAXIMUM_LENGTH &&
                    bytes.all { it in '0'.code.toByte()..'9'.code.toByte() }
            if (!isValidShape) {
                bytes.fill(0)
                throw IllegalArgumentException("PIN2 has an invalid shape")
            }
            return Pin2Submission(bytes)
        }
    }
}

internal class NativeQualifiedSignature(
    val algorithm: QualifiedSigningAlgorithm,
    private val ownedBytes: ByteArray,
) : AutoCloseable {
    private var isClosed = false

    val length: Int
        get() = ownedBytes.size

    fun <T> useBytes(operation: (ByteArray) -> T): T {
        check(!isClosed) {
            "qualified signature is closed"
        }
        return operation(ownedBytes)
    }

    fun copyBytes(): ByteArray = useBytes(ByteArray::copyOf)

    override fun close() {
        if (!isClosed) {
            ownedBytes.fill(ZERO_BYTE)
            isClosed = true
        }
    }

    override fun toString(): String =
        "NativeQualifiedSignature(algorithm=" + algorithm +
            ", length=" + length +
            ", closed=" + isClosed + ")"
}

internal enum class NativeQualifiedSignFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    INVALID_PIN,
    SAFETY_REFUSED,
    PIN_LOCKED,
    WRONG_PIN,
    VERIFICATION_REJECTED,
    CERTIFICATE_REJECTED,
    INVALID_CERTIFICATE,
    CERTIFICATE_MISMATCH,
    KEY_PROFILE_MISMATCH,
    SIGNING_REJECTED,
    BRIDGE_ERROR,
}

internal sealed interface NativeQualifiedSignResult {
    class Success(
        val signature: NativeQualifiedSignature,
    ) : NativeQualifiedSignResult {
        override fun toString(): String = "Success(" + signature + ")"
    }

    data class Failure(
        val kind: NativeQualifiedSignFailure,
    ) : NativeQualifiedSignResult
}

internal enum class QualifiedSignFailure {
    CARD_UNAVAILABLE,
    TRANSPORT_ERROR,
    INVALID_PIN,
    SAFETY_REFUSED,
    PIN_LOCKED,
    WRONG_PIN,
    VERIFICATION_REJECTED,
    CERTIFICATE_REJECTED,
    INVALID_CERTIFICATE,
    CERTIFICATE_MISMATCH,
    KEY_PROFILE_MISMATCH,
    SIGNING_REJECTED,
    LOCAL_VERIFICATION_FAILED,
    BRIDGE_ERROR,
}

internal sealed interface QualifiedSignResult {
    class Success(
        val signature: NativeQualifiedSignature,
    ) : QualifiedSignResult {
        override fun toString(): String = "Success(" + signature + ")"
    }

    data class Failure(
        val kind: QualifiedSignFailure,
    ) : QualifiedSignResult
}

/** Strict decoder for the fixed native qualified-signature vocabulary. */
internal object NativeQualifiedSignReply {
    fun decode(reply: ByteArray): NativeQualifiedSignResult =
        try {
            if (reply.isEmpty()) {
                return bridgeFailure()
            }
            when (reply[NativeQualifiedSignWire.TAG_OFFSET].toUnsignedInt()) {
                NativeQualifiedSignWire.SUCCESS_TAG -> {
                    decodeSuccess(reply)
                }

                NativeQualifiedSignWire.CARD_UNAVAILABLE_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.CARD_UNAVAILABLE)
                }

                NativeQualifiedSignWire.TRANSPORT_ERROR_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.TRANSPORT_ERROR)
                }

                NativeQualifiedSignWire.INVALID_PIN_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.INVALID_PIN)
                }

                NativeQualifiedSignWire.SAFETY_REFUSED_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.SAFETY_REFUSED)
                }

                NativeQualifiedSignWire.PIN_LOCKED_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.PIN_LOCKED)
                }

                NativeQualifiedSignWire.WRONG_PIN_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.WRONG_PIN)
                }

                NativeQualifiedSignWire.VERIFICATION_REJECTED_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.VERIFICATION_REJECTED)
                }

                NativeQualifiedSignWire.CERTIFICATE_REJECTED_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.CERTIFICATE_REJECTED)
                }

                NativeQualifiedSignWire.INVALID_CERTIFICATE_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.INVALID_CERTIFICATE)
                }

                NativeQualifiedSignWire.CERTIFICATE_MISMATCH_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.CERTIFICATE_MISMATCH)
                }

                NativeQualifiedSignWire.KEY_PROFILE_MISMATCH_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.KEY_PROFILE_MISMATCH)
                }

                NativeQualifiedSignWire.SIGNING_REJECTED_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.SIGNING_REJECTED)
                }

                NativeQualifiedSignWire.BRIDGE_ERROR_TAG -> {
                    decodeFailure(reply, NativeQualifiedSignFailure.BRIDGE_ERROR)
                }

                else -> {
                    bridgeFailure()
                }
            }
        } finally {
            reply.fill(ZERO_BYTE)
        }

    private fun decodeSuccess(reply: ByteArray): NativeQualifiedSignResult {
        if (reply.size <= NativeQualifiedSignWire.SIGNATURE_REPLY_HEADER_LENGTH) {
            return bridgeFailure()
        }
        val algorithm =
            QualifiedSigningAlgorithm.entries.firstOrNull {
                it.wireValue ==
                    reply[NativeQualifiedSignWire.ALGORITHM_OFFSET].toUnsignedInt()
            } ?: return bridgeFailure()
        if (
            reply.size !=
            NativeQualifiedSignWire.SIGNATURE_REPLY_HEADER_LENGTH + algorithm.signatureLength
        ) {
            return bridgeFailure()
        }
        return NativeQualifiedSignResult.Success(
            NativeQualifiedSignature(
                algorithm = algorithm,
                ownedBytes =
                    reply.copyOfRange(
                        NativeQualifiedSignWire.SIGNATURE_REPLY_HEADER_LENGTH,
                        reply.size,
                    ),
            ),
        )
    }

    private fun decodeFailure(
        reply: ByteArray,
        kind: NativeQualifiedSignFailure,
    ): NativeQualifiedSignResult =
        if (reply.size == NativeQualifiedSignWire.FAILURE_REPLY_LENGTH) {
            NativeQualifiedSignResult.Failure(kind)
        } else {
            bridgeFailure()
        }

    private fun bridgeFailure(): NativeQualifiedSignResult.Failure =
        NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)

    private fun Byte.toUnsignedInt(): Int = toUByte().toInt()
}
