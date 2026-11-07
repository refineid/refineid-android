package fi.refineid.android.usb.ccid

import fi.refineid.android.diagnostics.AppTrace

internal interface CcidBulkIo {
    fun write(frame: ByteArray): Int

    fun read(frame: ByteArray): Int
}

internal enum class CcidExchangeFailureKind {
    COMMAND_TOO_LONG,
    TRANSPORT,
    MALFORMED_RESPONSE,
    TIME_EXTENSION_LIMIT,
}

internal sealed interface CcidExchangeResult {
    data class Response(
        val value: CcidResponse,
    ) : CcidExchangeResult

    data class Failure(
        val kind: CcidExchangeFailureKind,
    ) : CcidExchangeResult
}

/** Moves one already-built CCID command without interpreting its transfer block. */
internal class CcidCommandExchange(
    private val bulkIo: CcidBulkIo,
    private val maximumMessageLength: Int,
    private val maximumTimeExtensions: Int = DEFAULT_MAXIMUM_TIME_EXTENSIONS,
) {
    private val responseCapacity =
        minOf(
            maximumMessageLength,
            CcidWire.HEADER_SIZE + CcidWire.MAX_RESPONSE_PAYLOAD_SIZE,
        )

    init {
        require(maximumMessageLength >= CcidWire.HEADER_SIZE) {
            "maximum CCID message length is smaller than the header"
        }
        require(maximumTimeExtensions >= 0) {
            "maximum time extensions must not be negative"
        }
    }

    fun exchange(command: CcidCommand): CcidExchangeResult {
        val commandBytes = command.encodedBytes()
        AppTrace.ccidExchangeStarted(
            messageType = command.messageType,
            slot = command.slot,
            sequence = command.sequence,
        )
        try {
            if (commandBytes.size > maximumMessageLength) {
                return failure(CcidExchangeFailureKind.COMMAND_TOO_LONG, command)
            }
            if (bulkIo.write(commandBytes) != commandBytes.size) {
                return failure(CcidExchangeFailureKind.TRANSPORT, command)
            }
        } finally {
            commandBytes.fill(0)
        }

        var timeExtensionCount = 0
        while (true) {
            when (val result = readResponse(command)) {
                is CcidExchangeResult.Failure -> {
                    return result
                }

                is CcidExchangeResult.Response -> {
                    if (result.value is CcidTimeExtension) {
                        timeExtensionCount += 1
                        AppTrace.ccidTimeExtension(
                            count = timeExtensionCount,
                            multiplier = result.value.multiplier,
                        )
                        if (timeExtensionCount > maximumTimeExtensions) {
                            return failure(CcidExchangeFailureKind.TIME_EXTENSION_LIMIT, command)
                        }
                    } else {
                        return result
                    }
                }
            }
        }
    }

    private fun readResponse(command: CcidCommand): CcidExchangeResult {
        val responseBytes = ByteArray(responseCapacity)
        var receivedFrame: ByteArray? = null
        return try {
            val bytesRead = bulkIo.read(responseBytes)
            if (bytesRead < 0) {
                return failure(CcidExchangeFailureKind.TRANSPORT, command)
            }
            if (bytesRead > responseBytes.size) {
                return failure(CcidExchangeFailureKind.MALFORMED_RESPONSE, command)
            }

            receivedFrame = responseBytes.copyOf(bytesRead)
            CcidExchangeResult.Response(
                CcidResponseParser.parse(
                    frame = receivedFrame,
                    command = command,
                ),
            )
        } catch (error: CcidProtocolException) {
            AppTrace.ccidResponseRejected(
                error.kind,
                expected = error.expected,
                actual = error.actual,
                frameLength = error.frameLength,
                detail = error.detail,
            )
            failure(CcidExchangeFailureKind.MALFORMED_RESPONSE, command)
        } finally {
            receivedFrame?.fill(0)
            responseBytes.fill(0)
        }
    }

    private fun failure(
        kind: CcidExchangeFailureKind,
        command: CcidCommand,
    ): CcidExchangeResult.Failure {
        AppTrace.ccidCommandExchangeFailed(
            kind,
            messageType = command.messageType,
            slot = command.slot,
            sequence = command.sequence,
        )
        return CcidExchangeResult.Failure(kind)
    }

    private companion object {
        const val DEFAULT_MAXIMUM_TIME_EXTENSIONS = 8
    }
}

internal enum class CcidBlockFailureKind {
    COMMAND_REJECTED,
    CARD_UNAVAILABLE,
    READER,
    TRANSPORT,
    PROTOCOL,
}

internal sealed interface CcidBlockResult {
    class Response(
        payload: ByteArray,
    ) : CcidBlockResult,
        AutoCloseable {
        private val ownedPayload = payload.copyOf()
        private var isClosed = false

        val payloadLength: Int
            get() = ownedPayload.size

        val responseBodyLength: Int
            get() {
                check(!isClosed) {
                    "transfer response is closed"
                }
                return ownedPayload.size - ISO_7816_STATUS_LENGTH
            }

        val statusWord: Int
            get() {
                check(!isClosed) {
                    "transfer response is closed"
                }
                val statusOffset = ownedPayload.size - ISO_7816_STATUS_LENGTH
                return ((ownedPayload[statusOffset].toInt() and UNSIGNED_BYTE_MASK) shl Byte.SIZE_BITS) or
                    (ownedPayload[statusOffset + 1].toInt() and UNSIGNED_BYTE_MASK)
            }

        fun copyPayload(): ByteArray {
            check(!isClosed) {
                "transfer response is closed"
            }
            return ownedPayload.copyOf()
        }

        override fun close() {
            ownedPayload.fill(0)
            isClosed = true
        }

        override fun toString(): String = "CcidBlockResult.Response(payloadLength=" + payloadLength + ")"

        private companion object {
            const val ISO_7816_STATUS_LENGTH = 2
            const val UNSIGNED_BYTE_MASK = 0xFF
        }
    }

    data class Failure(
        val kind: CcidBlockFailureKind,
    ) : CcidBlockResult
}

internal enum class CcidBlockTraceKind {
    PUBLIC,
    SENSITIVE,
}

/** Classifies trace treatment without parsing or authorizing the command. */
internal object CcidBlockTracePolicy {
    fun classify(block: ByteArray): CcidBlockTraceKind =
        if (
            block.size > INSTRUCTION_OFFSET &&
            block[INSTRUCTION_OFFSET].unsignedValue() == VERIFY_INSTRUCTION
        ) {
            CcidBlockTraceKind.SENSITIVE
        } else {
            CcidBlockTraceKind.PUBLIC
        }

    private fun Byte.unsignedValue(): Int = toInt() and UNSIGNED_BYTE_MASK

    private const val INSTRUCTION_OFFSET = 1
    private const val VERIFY_INSTRUCTION = 0x20
    private const val UNSIGNED_BYTE_MASK = 0xFF
}

/**
 * Carries descriptor-selected APDU or TPDU blocks over CCID.
 * ISO 7816 lowering and recovery remain in Rust.
 *
 * The credential entry point consumes and clears its mutable input regardless
 * of the transport outcome. It never resubmits a command.
 */
internal class CcidBlockTransport(
    private val exchange: CcidCommandExchange,
    private val maximumBlockLength: Int,
    private val sequenceCounter: CcidSequenceCounter = CcidSequenceCounter(),
) {
    init {
        require(maximumBlockLength in MINIMUM_BLOCK_LENGTH..MAXIMUM_BLOCK_LENGTH) {
            "maximum transfer-block length is outside the CCID bound"
        }
    }

    fun transmitPublic(block: ByteArray): CcidBlockResult {
        if (CcidBlockTracePolicy.classify(block) == CcidBlockTraceKind.SENSITIVE) {
            return transmitSensitivePublic(block)
        }
        val startedAt =
            if (block.size >= MINIMUM_BLOCK_LENGTH) {
                AppTrace.cardPublicCommandStarted(
                    classByte = block[CLASS_BYTE_OFFSET].unsignedValue(),
                    instruction = block[INSTRUCTION_OFFSET].unsignedValue(),
                    parameterOne = block[PARAMETER_ONE_OFFSET].unsignedValue(),
                    parameterTwo = block[PARAMETER_TWO_OFFSET].unsignedValue(),
                    commandLength = block.size,
                )
            } else {
                AppTrace.cardPublicMalformedCommandStarted(commandLength = block.size)
            }
        return transmitOnce(block).also { result ->
            tracePublicResult(
                startedAt = startedAt,
                result = result,
            )
        }
    }

    private fun transmitSensitivePublic(block: ByteArray): CcidBlockResult =
        AppTrace.cardSensitiveCommandStarted().let { startedAt ->
            transmitOnce(block).also { result ->
                when (result) {
                    is CcidBlockResult.Response -> {
                        AppTrace.cardSensitiveCommandResponded(
                            startedAt = startedAt,
                            statusWord = result.statusWord,
                        )
                    }

                    is CcidBlockResult.Failure -> {
                        AppTrace.cardSensitiveCommandFailed(
                            startedAt = startedAt,
                            kind = result.kind,
                        )
                    }
                }
            }
        }

    fun transmitCredential(block: ByteArray): CcidBlockResult =
        AppTrace.cardCredentialCommandStarted().let { startedAt ->
            try {
                transmitOnce(block).also { result ->
                    traceCredentialResult(
                        startedAt = startedAt,
                        result = result,
                    )
                }
            } finally {
                block.fill(0)
            }
        }

    private fun tracePublicResult(
        startedAt: Long,
        result: CcidBlockResult,
    ) {
        when (result) {
            is CcidBlockResult.Response -> {
                AppTrace.cardPublicCommandResponded(
                    startedAt = startedAt,
                    statusWord = result.statusWord,
                    responseBodyLength = result.responseBodyLength,
                )
            }

            is CcidBlockResult.Failure -> {
                AppTrace.cardPublicCommandFailed(
                    startedAt = startedAt,
                    kind = result.kind,
                )
            }
        }
    }

    private fun traceCredentialResult(
        startedAt: Long,
        result: CcidBlockResult,
    ) {
        when (result) {
            is CcidBlockResult.Response -> {
                AppTrace.cardCredentialCommandResponded(
                    startedAt = startedAt,
                    statusWord = result.statusWord,
                )
            }

            is CcidBlockResult.Failure -> {
                AppTrace.cardCredentialCommandFailed(
                    startedAt = startedAt,
                    kind = result.kind,
                )
            }
        }
    }

    private fun Byte.unsignedValue(): Int = toInt() and UNSIGNED_BYTE_MASK

    private fun transmitOnce(block: ByteArray): CcidBlockResult {
        if (block.size !in MINIMUM_BLOCK_LENGTH..maximumBlockLength) {
            return failure(CcidBlockFailureKind.COMMAND_REJECTED)
        }

        val command =
            CcidCommand.transferBlock(
                slot = FIRST_SLOT,
                sequence = sequenceCounter.take(),
                block = block,
            )
        return try {
            when (val exchangeResult = exchange.exchange(command)) {
                is CcidExchangeResult.Failure -> mapExchangeFailure(exchangeResult.kind)
                is CcidExchangeResult.Response -> mapResponse(exchangeResult.value)
            }
        } finally {
            command.close()
        }
    }

    private fun mapExchangeFailure(kind: CcidExchangeFailureKind): CcidBlockResult =
        failure(
            when (kind) {
                CcidExchangeFailureKind.COMMAND_TOO_LONG -> {
                    CcidBlockFailureKind.COMMAND_REJECTED
                }

                CcidExchangeFailureKind.TRANSPORT -> {
                    CcidBlockFailureKind.TRANSPORT
                }

                CcidExchangeFailureKind.MALFORMED_RESPONSE,
                CcidExchangeFailureKind.TIME_EXTENSION_LIMIT,
                -> {
                    CcidBlockFailureKind.PROTOCOL
                }
            },
        )

    private fun mapResponse(response: CcidResponse): CcidBlockResult =
        when (response) {
            is CcidDataBlock -> {
                mapDataBlock(response)
            }

            is CcidCommandFailure -> {
                AppTrace.ccidCommandFailed(
                    errorCode = response.errorCode,
                    cardStatus = response.cardStatus,
                )
                if (response.cardStatus == CcidCardStatus.ACTIVE) {
                    failure(CcidBlockFailureKind.READER)
                } else {
                    failure(CcidBlockFailureKind.CARD_UNAVAILABLE)
                }
            }

            is CcidSlotStatus,
            is CcidTimeExtension,
            is CcidParameters,
            -> {
                if (response is CcidParameters) {
                    response.close()
                }
                failure(CcidBlockFailureKind.PROTOCOL)
            }
        }

    private fun mapDataBlock(response: CcidDataBlock): CcidBlockResult =
        response.use {
            if (response.cardStatus != CcidCardStatus.ACTIVE) {
                return failure(CcidBlockFailureKind.CARD_UNAVAILABLE)
            }
            if (response.chainParameter != CcidChainParameter.COMPLETE) {
                return failure(CcidBlockFailureKind.PROTOCOL)
            }

            val payload = response.copyPayload()
            return try {
                if (payload.size < ISO_7816_STATUS_LENGTH) {
                    failure(CcidBlockFailureKind.PROTOCOL)
                } else {
                    CcidBlockResult.Response(payload)
                }
            } finally {
                payload.fill(0)
            }
        }

    private fun failure(kind: CcidBlockFailureKind): CcidBlockResult.Failure = CcidBlockResult.Failure(kind)

    private companion object {
        const val FIRST_SLOT = 0
        const val MINIMUM_BLOCK_LENGTH = 4
        const val MAXIMUM_BLOCK_LENGTH = 65_544
        const val ISO_7816_STATUS_LENGTH = 2
        const val CLASS_BYTE_OFFSET = 0
        const val INSTRUCTION_OFFSET = 1
        const val PARAMETER_ONE_OFFSET = 2
        const val PARAMETER_TWO_OFFSET = 3
        const val UNSIGNED_BYTE_MASK = 0xFF
    }
}
