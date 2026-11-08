// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.core

import fi.refineid.android.diagnostics.AppTrace

/** What opens a card on the contactless interface, as its EF.CardAccess tells before any password is sent. */
internal enum class NfcCardKind {
    /** Opens with the Card Access Number printed on the card. */
    PERSONAL,

    /** Has no Card Access Number: opens with Basic PIN 1, Signature PIN 2 or the PUK. */
    ORGANIZATION,
}

/** What opening an organization card with Basic PIN 1 came to. */
internal sealed interface NativeOrganizationOpenResult {
    /** PIN 1 opened the channel; the certificates came through it. */
    class Opened(
        val identity: NativeContactlessOpenResult.Success,
        val qualifiedCertificate: NativeQualifiedCertificate?,
    ) : NativeOrganizationOpenResult {
        override fun toString(): String = "Opened"
    }

    /** The channel did not open: the card's answer, with its count after a wrong PIN. */
    data class Refused(
        val answer: Pin1Verification,
    ) : NativeOrganizationOpenResult

    /** The channel opened and the authentication certificate did not read. */
    data class Unreadable(
        val kind: NativeCertificateReadFailure,
    ) : NativeOrganizationOpenResult
}

/**
 * Native boundary for an organization card on the contactless interface.
 * Every operation reads EF.CardAccess, refuses a card that is not an
 * organization card before any password is named, and runs its own PACE
 * with the credential it spends (FINEID S1 v4.0, organizational cards,
 * section 2.1). The counters come from `MSE:Set AT`, which spends no try.
 * Each secret is cleared by the native border.
 */
@Suppress("TooManyFunctions")
internal object NativeOrganizationCard {
    /** PIN 1's counter, read in plain with no secret. */
    fun probePin1(exchange: NativeBlockExchange): NativePin1PreflightResult =
        if (!NativeCore.isLoaded) {
            NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
        } else {
            try {
                NativePin1PreflightReply.decode(organizationPin1CounterNative(exchange))
            } catch (_: LinkageError) {
                NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
            } catch (_: RuntimeException) {
                NativePin1PreflightResult.Failure(NativePin1PreflightFailure.BRIDGE_ERROR)
            }
        }

    /** PIN 2's counter, read in plain with no secret. */
    fun probePin2(exchange: NativeBlockExchange): NativePin2PreflightResult {
        val startedAt = AppTrace.nativePin2StatusProbeStarted(NativeCardExchangeLevel.APDU)
        val result =
            if (!NativeCore.isLoaded) {
                NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
            } else {
                try {
                    NativePin2PreflightReply.decode(organizationPin2CounterNative(exchange))
                } catch (_: LinkageError) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativePin2PreflightResult.Failure(NativePin2PreflightFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativePin2StatusProbeCompleted(startedAt = startedAt, result = result)
        return result
    }

    /** PIN 1, PIN 2 and PUK counters, read in plain with no secret. */
    fun probeHealth(exchange: NativeBlockExchange): CardManagementResult<CredentialHealth> =
        managed { NativeCardManagement.decodeCredentialHealth(organizationHealthNative(exchange)) }

    /** PACE with PIN 1, then the certificates read through the channel. Consumes [pin1]. */
    fun open(
        pin1: Pin1Submission,
        exchange: NativeBlockExchange,
    ): NativeOrganizationOpenResult {
        val startedAt = AppTrace.nativeContactlessOpenStarted()
        val result =
            try {
                pin1.consume { bytes ->
                    if (!NativeCore.isLoaded) {
                        refusedByBridge()
                    } else {
                        NativeOrganizationOpenReply.decode(organizationOpenNative(bytes, exchange))
                    }
                }
            } catch (_: LinkageError) {
                refusedByBridge()
            } catch (_: RuntimeException) {
                refusedByBridge()
            } finally {
                pin1.close()
            }
        AppTrace.nativeContactlessOpenCompleted(
            startedAt = startedAt,
            result = (result as? NativeOrganizationOpenResult.Opened)?.identity ?: UNOPENED_TRACE,
        )
        return result
    }

    /** PACE with PIN 1 and nothing after it: the handshake proves the digits. Consumes [pin1]. */
    fun verifyPin1(
        pin1: Pin1Submission,
        exchange: NativeBlockExchange,
    ): Pin1Verification =
        try {
            pin1.consume { bytes ->
                if (!NativeCore.isLoaded) {
                    Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR)
                } else {
                    NativePin1Verification.decode(organizationVerifyPin1Native(bytes, exchange))
                }
            }
        } catch (_: LinkageError) {
            Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR)
        } catch (_: RuntimeException) {
            Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR)
        } finally {
            pin1.close()
        }

    /** One authentication signature on a PIN 1 handshake, with no VERIFY. Consumes [pin1]. */
    fun authenticateAndSign(
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
                NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR)
            } else {
                try {
                    pin1.consume { bytes ->
                        if (!NativeCore.isLoaded) {
                            NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR)
                        } else {
                            NativeAuthenticationSignReply.decode(
                                organizationAuthenticateAndSignNative(
                                    request = algorithm.requestWireValue(inputMode),
                                    pin = bytes,
                                    message = input,
                                    callback = exchange,
                                ),
                            )
                        }
                    }
                } catch (_: LinkageError) {
                    NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR)
                } catch (_: RuntimeException) {
                    NativeAuthenticationSignResult.Failure(NativeAuthenticationSignFailure.BRIDGE_ERROR)
                }
            }
        AppTrace.nativeContactlessSignCompleted(startedAt = startedAt, result = result)
        return result
    }

    /**
     * One qualified signature on a PIN 2 handshake, with no VERIFY. Consumes [pin2].
     * With [readCaCertificates], a made signature is followed on the same
     * channel by reads of the card's root and issuing CA, which
     * [NativeCardCa] then holds with the card's answers.
     */
    fun qualifiedSign(
        algorithm: QualifiedSigningAlgorithm,
        inputMode: QualifiedSigningInputMode,
        pin2: Pin2Submission,
        input: ByteArray,
        expectedCertificate: NativeQualifiedCertificate,
        exchange: NativeBlockExchange,
        readCaCertificates: Boolean = false,
    ): NativeQualifiedSignResult {
        val startedAt = AppTrace.nativeQualifiedSignStarted(algorithm = algorithm, contentLength = input.size)
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
                    pin2.consume { bytes ->
                        if (!NativeCore.isLoaded) {
                            NativeQualifiedSignResult.Failure(NativeQualifiedSignFailure.BRIDGE_ERROR)
                        } else {
                            NativeQualifiedSignReply.decode(
                                organizationQualifiedSignNative(
                                    algorithm = algorithm.requestWireValue(inputMode),
                                    pin = bytes,
                                    content = input,
                                    expectedCertificate = expectedDer,
                                    readCaCertificates = readCaCertificates,
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
        AppTrace.nativeQualifiedSignCompleted(startedAt = startedAt, result = result)
        return result
    }

    /** PIN 1 changed on the channel the current PIN opens. */
    fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        managed {
            NativeCardManagement.decodeManageOutcome(organizationChangePin1Native(currentPin, newPin, exchange))
        }

    /** PIN 2 changed on the channel the current PIN opens; core makes DF.ESIGN current. */
    fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        managed {
            NativeCardManagement.decodeManageOutcome(organizationChangePin2Native(currentPin, newPin, exchange))
        }

    /** PIN 1 set on the channel the PUK opens, spending no PUK try after the handshake. */
    fun resetPin1(
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        managed {
            NativeCardManagement.decodeManageOutcome(organizationResetPin1Native(puk, newPin, exchange))
        }

    /** PIN 2 set on the channel the PUK opens, spending no PUK try after the handshake. */
    fun resetPin2(
        puk: ByteArray,
        newPin: ByteArray,
        exchange: NativeBlockExchange,
    ): CardManagementResult<ManageOutcome> =
        managed {
            NativeCardManagement.decodeManageOutcome(organizationResetPin2Native(puk, newPin, exchange))
        }

    private fun <Value> managed(operation: () -> CardManagementResult<Value>): CardManagementResult<Value> {
        if (!NativeCore.isLoaded) {
            return CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
        return try {
            operation()
        } catch (_: LinkageError) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        } catch (_: RuntimeException) {
            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
        }
    }

    private fun refusedByBridge(): NativeOrganizationOpenResult =
        NativeOrganizationOpenResult.Refused(Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR))

    private val UNOPENED_TRACE = NativeContactlessOpenResult.Failure(NativeCertificateReadFailure.REJECTED)

    @JvmStatic
    private external fun organizationPin1CounterNative(callback: Any): ByteArray

    @JvmStatic
    private external fun organizationPin2CounterNative(callback: Any): ByteArray

    @JvmStatic
    private external fun organizationHealthNative(callback: Any): ByteArray

    @JvmStatic
    private external fun organizationOpenNative(
        pin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationVerifyPin1Native(
        pin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationAuthenticateAndSignNative(
        request: Int,
        pin: ByteArray,
        message: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationQualifiedSignNative(
        algorithm: Int,
        pin: ByteArray,
        content: ByteArray,
        expectedCertificate: ByteArray,
        readCaCertificates: Boolean,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationChangePin1Native(
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationChangePin2Native(
        currentPin: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationResetPin1Native(
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray

    @JvmStatic
    private external fun organizationResetPin2Native(
        puk: ByteArray,
        newPin: ByteArray,
        callback: Any,
    ): ByteArray
}

/**
 * Strict decoder for the organization card's open reply: `[answered, identity
 * length as four big-endian bytes, contactless open reply, qualified-certificate
 * reply]`, or `[refused, PIN 1 answer]`. The nested parts reuse the established
 * strict sub-decoders.
 */
internal object NativeOrganizationOpenReply {
    fun decode(reply: ByteArray): NativeOrganizationOpenResult =
        try {
            when (reply.firstOrNull()?.toInt()) {
                OPEN_ANSWERED -> decodeAnswered(reply)
                OPEN_REFUSED -> NativeOrganizationOpenResult.Refused(decodeRefused(reply))
                else -> bridgeRefusal()
            }
        } finally {
            reply.fill(0)
        }

    private fun decodeAnswered(reply: ByteArray): NativeOrganizationOpenResult {
        if (reply.size < HEADER_LENGTH) return bridgeRefusal()
        var length = 0
        for (index in TAG_LENGTH until HEADER_LENGTH) {
            if (length > MAXIMUM_LENGTH_BEFORE_SHIFT) return bridgeRefusal()
            length = (length shl Byte.SIZE_BITS) or (reply[index].toInt() and BYTE_MASK)
        }
        val qualifiedStart = HEADER_LENGTH + length
        if (length == 0 || qualifiedStart >= reply.size) return bridgeRefusal()
        val qualified =
            NativeCertificateReply.decode(
                reply = reply.copyOfRange(qualifiedStart, reply.size),
                certificate = { profile, der -> NativeQualifiedCertificate(keyProfile = profile, ownedDer = der) },
            )
        val qualifiedCertificate = (qualified as? NativeCertificateReadResult.Success)?.certificate
        return when (val open = NativeContactlessOpenReply.decode(reply.copyOfRange(HEADER_LENGTH, qualifiedStart))) {
            is NativeContactlessOpenResult.Success -> {
                NativeOrganizationOpenResult.Opened(open, qualifiedCertificate)
            }

            is NativeContactlessOpenResult.Failure -> {
                qualifiedCertificate?.close()
                NativeOrganizationOpenResult.Unreadable(open.kind)
            }

            is NativeContactlessOpenResult.ActivationRequired -> {
                qualifiedCertificate?.close()
                bridgeRefusal()
            }
        }
    }

    private fun decodeRefused(reply: ByteArray): Pin1Verification =
        NativePin1Verification.decode(reply.copyOfRange(TAG_LENGTH, reply.size))

    private fun bridgeRefusal(): NativeOrganizationOpenResult =
        NativeOrganizationOpenResult.Refused(Pin1Verification(Pin1VerificationResult.BRIDGE_ERROR))

    private const val OPEN_ANSWERED = 0
    private const val OPEN_REFUSED = 1
    private const val TAG_LENGTH = 1
    private const val LENGTH_OCTETS = 4
    private const val HEADER_LENGTH = TAG_LENGTH + LENGTH_OCTETS
    private const val BYTE_MASK = 0xFF
    private const val MAXIMUM_LENGTH_BEFORE_SHIFT = Int.MAX_VALUE shr Byte.SIZE_BITS
}

/**
 * Whether PIN 1 is not offered for an organization card with this many tries
 * left: core's floor refuses two or one, and a blocked PIN takes the PUK. An
 * unread counter still offers the entry; `MSE:Set AT` reads it again before any
 * try can be spent, and the floor decides there.
 */
internal fun organizationPin1Refused(attemptsLeft: Int?): Boolean =
    attemptsLeft != null && attemptsLeft < ORGANIZATION_PIN1_LOWEST_OFFERED

private const val ORGANIZATION_PIN1_LOWEST_OFFERED = 3
