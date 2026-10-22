// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappCardReader
import uniffi.refineid_rapp.RappCloseReason
import uniffi.refineid_rapp.RappOperationDescriptor
import uniffi.refineid_rapp.RappOperationKind
import uniffi.refineid_rapp.RappOperationResult
import uniffi.refineid_rapp.RappProgressEvent
import uniffi.refineid_rapp.RappResultKind
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.RappTerminalReason
import uniffi.refineid_rapp.rappRandomByteCounts
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The identifier of one operation: a fresh random value of the size the
 * engine draws (RAPP v26.10.22 section 8.1 item 1).
 */
internal class RappOperationId private constructor(
    private val bytes: ByteArray,
) {
    /** The identifier as the binding takes it back. */
    fun toWire(): ByteArray = bytes.copyOf()

    /** Lowercase hexadecimal: the key of the operation's views on this phone. */
    @OptIn(ExperimentalStdlibApi::class)
    val key: String
        get() = bytes.toHexString()

    override fun equals(other: Any?): Boolean = other is RappOperationId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = "RappOperationId($key)"

    companion object {
        private val SIZE = rappRandomByteCounts().operationId.toInt()

        /** The identifier the binding handed out, or null when it is not an identifier's size. */
        fun fromWire(wire: ByteArray): RappOperationId? =
            if (wire.size ==
                SIZE
            ) {
                RappOperationId(wire.copyOf())
            } else {
                null
            }

        /** A fresh identifier drawn from [random]. */
        fun random(random: SecureRandom): RappOperationId = RappOperationId(ByteArray(SIZE).also(random::nextBytes))
    }
}

/** The SHA-256 digest of a card's authentication certificate in DER (RAPP v26.10.22 section 8.4 item 2). */
internal class RappCertificateFingerprint private constructor(
    private val digest: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is RappCertificateFingerprint && MessageDigest.isEqual(digest, other.digest)

    override fun hashCode(): Int = digest.contentHashCode()

    override fun toString(): String = "RappCertificateFingerprint"

    companion object {
        private const val DIGEST_ALGORITHM = "SHA-256"
        private val SIZE = MessageDigest.getInstance(DIGEST_ALGORITHM).digestLength

        /** The fingerprint the binding reported, or null when it is not a SHA-256 digest's size. */
        fun fromWire(wire: ByteArray): RappCertificateFingerprint? =
            if (wire.size == SIZE) RappCertificateFingerprint(wire.copyOf()) else null

        /** The fingerprint of [certificate]. */
        fun of(certificate: RappCertificate): RappCertificateFingerprint =
            RappCertificateFingerprint(MessageDigest.getInstance(DIGEST_ALGORITHM).digest(certificate.toWire()))
    }
}

/** An X.509 certificate a card holds; its DER form is re-encoded from the parsed certificate. */
internal class RappCertificate private constructor(
    private val certificate: X509Certificate,
) {
    /** The DER encoding, for the binding or the platform. */
    fun toWire(): ByteArray = certificate.encoded

    override fun equals(other: Any?): Boolean = other is RappCertificate && certificate == other.certificate

    override fun hashCode(): Int = certificate.hashCode()

    override fun toString(): String = "RappCertificate"

    companion object {
        private const val CERTIFICATE_TYPE = "X.509"

        /** The certificate [der] encodes, or null when it is not one X.509 certificate. */
        fun fromDer(der: ByteArray): RappCertificate? =
            try {
                (
                    CertificateFactory
                        .getInstance(
                            CERTIFICATE_TYPE,
                        ).generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
                )?.let(::RappCertificate)
            } catch (_: CertificateException) {
                null
            }
    }
}

/** The card a custodian reports on a session (RAPP v26.10.22 section 8.4 item 1). */
internal sealed interface RappCardStatus {
    /** A card can answer now; [fingerprint] names it. */
    class Present(
        val fingerprint: RappCertificateFingerprint,
    ) : RappCardStatus

    /** No card can answer. */
    data object Absent : RappCardStatus
}

/** The card this custodian can serve now (RAPP v26.10.22 section 8.4 item 1). */
internal sealed interface RappOfferedCard {
    /** A card coupled in a reader, or a primed card the holder can present, with its authentication certificate. */
    class Present(
        val certificate: RappCertificate,
    ) : RappOfferedCard {
        override fun equals(other: Any?): Boolean = other is Present && certificate == other.certificate

        override fun hashCode(): Int = certificate.hashCode()
    }

    /** No card can answer. */
    data object Absent : RappOfferedCard
}

/** One document of a signing request: the name the holder sees and the digest the card signs. */
internal class RappDocument(
    val name: String,
    /** The pre-hashed document, in transit to the card's signing command. */
    val digest: ByteArray,
)

/** What a requester asked of the card (RAPP v26.10.22 section 9). */
internal sealed interface RappRequest {
    data object InspectCard : RappRequest

    data object ReadIdentity : RappRequest

    data object ReadAuthenticationCertificate : RappRequest

    data object ReadSignatureCertificate : RappRequest

    /** [digest] is the hashed challenge, in transit to the card's signing command. */
    class BrowserAuthenticate(
        val origin: String,
        val keyProfile: RappCardKeyProfile,
        val algorithm: RappSignatureAlgorithm,
        val digest: ByteArray,
    ) : RappRequest

    class SignDocument(
        val document: RappDocument,
        val keyProfile: RappCardKeyProfile,
        val algorithm: RappSignatureAlgorithm,
    ) : RappRequest

    /** Every document of the batch, in signing order; never empty. */
    class BatchSignDocuments(
        val documents: List<RappDocument>,
        val keyProfile: RappCardKeyProfile,
        val algorithm: RappSignatureAlgorithm,
    ) : RappRequest

    companion object {
        /** The request the engine's descriptor states; fails on a descriptor whose fields do not fit its kind. */
        fun from(descriptor: RappOperationDescriptor): RappRequest =
            when (descriptor.kind) {
                RappOperationKind.INSPECT_CARD -> {
                    InspectCard
                }

                RappOperationKind.READ_IDENTITY -> {
                    ReadIdentity
                }

                RappOperationKind.READ_AUTHENTICATION_CERTIFICATE -> {
                    ReadAuthenticationCertificate
                }

                RappOperationKind.READ_SIGNATURE_CERTIFICATE -> {
                    ReadSignatureCertificate
                }

                RappOperationKind.BROWSER_AUTHENTICATE -> {
                    BrowserAuthenticate(
                        origin = checkNotNull(descriptor.displayContext),
                        keyProfile = checkNotNull(descriptor.keyProfile),
                        algorithm = checkNotNull(descriptor.algorithm),
                        digest = descriptor.digest.also { check(it.isNotEmpty()) },
                    )
                }

                RappOperationKind.SIGN_DOCUMENT -> {
                    SignDocument(
                        document =
                            RappDocument(
                                checkNotNull(descriptor.displayContext),
                                descriptor.digest.also { check(it.isNotEmpty()) },
                            ),
                        keyProfile = checkNotNull(descriptor.keyProfile),
                        algorithm = checkNotNull(descriptor.algorithm),
                    )
                }

                RappOperationKind.BATCH_SIGN_DOCUMENTS -> {
                    check(descriptor.documentNames.isNotEmpty())
                    check(descriptor.documentNames.size == descriptor.digests.size)
                    BatchSignDocuments(
                        documents = descriptor.documentNames.zip(descriptor.digests, ::RappDocument),
                        keyProfile = checkNotNull(descriptor.keyProfile),
                        algorithm = checkNotNull(descriptor.algorithm),
                    )
                }
            }
    }
}

/**
 * The answer a requester asked for. This client asks for certificates and
 * signatures only; any other answer to its own request cannot arrive.
 */
internal sealed interface RappAnswer {
    class Certificate(
        val certificate: RappCertificate,
    ) : RappAnswer

    /** The signature in its section 9.2 wire form, in transit to its consumer. */
    class Signature(
        val signature: ByteArray,
    ) : RappAnswer

    companion object {
        fun from(result: RappOperationResult): RappAnswer =
            when (result.kind) {
                RappResultKind.CERTIFICATE -> {
                    Certificate(checkNotNull(RappCertificate.fromDer(result.bytes)))
                }

                RappResultKind.SIGNATURE -> {
                    Signature(result.bytes.also { check(it.isNotEmpty()) })
                }

                RappResultKind.INSPECTION, RappResultKind.IDENTITY, RappResultKind.SIGNATURES -> {
                    error(
                        "unrequested answer",
                    )
                }
            }
    }
}

/**
 * One action of the engine's operation or session bridge, deconstructed once
 * at the binding border; the rest of the app consumes only this.
 */
internal sealed interface RappBridgeOutcome {
    /**
     * Deliver [frame], ciphertext in transit to the transport. A non-null
     * [closesWith] ends the session once the frame is delivered.
     */
    class Send(
        val frame: ByteArray,
        val closesWith: RappCloseReason?,
    ) : RappBridgeOutcome

    /** Nothing to do. */
    data object Idle : RappBridgeOutcome

    /** A request was admitted; it takes the card in its turn (section 8.2 item 2). */
    class Admitted(
        val operationId: RappOperationId,
    ) : RappBridgeOutcome

    /**
     * Obtain the holder's approval of [request]: the PIN it needs, or the
     * PIN 1 the phone holds (section 8.2 item 3).
     */
    class AwaitApproval(
        val operationId: RappOperationId,
        val request: RappRequest,
    ) : RappBridgeOutcome

    /** Run the read [request]; no private key, no PIN (section 8.2 item 6). */
    class ExecuteRead(
        val operationId: RappOperationId,
        val request: RappRequest,
    ) : RappBridgeOutcome

    /** Run the one approved card command [request]. */
    class ExecuteCommand(
        val operationId: RappOperationId,
        val request: RappRequest,
    ) : RappBridgeOutcome

    /** The requester's operation completed with [answer]. */
    class Completed(
        val operationId: RappOperationId,
        val answer: RappAnswer,
    ) : RappBridgeOutcome

    /** The requester's operation ended without completing (section 10.3). */
    class Terminal(
        val operationId: RappOperationId,
        val reason: RappTerminalReason,
    ) : RappBridgeOutcome

    /** The custodian reported the operation's progress. */
    class Progress(
        val operationId: RappOperationId,
        val event: RappProgressEvent,
    ) : RappBridgeOutcome

    /** The custodian reported its card and whether a card reader is connected to it. */
    class CardStatus(
        val status: RappCardStatus,
        val reader: RappCardReader,
    ) : RappBridgeOutcome

    /** The session closed; [reason] is the authenticated close's, when one was sent or received. */
    class Closed(
        val reason: RappCloseReason?,
    ) : RappBridgeOutcome

    companion object {
        /**
         * The outcome [action] states. Fails on an action whose fields do
         * not fit its kind: a frame on any kind but a send, a closing send
         * without its reason, or a missing or malformed operation field.
         */
        fun from(action: RappBridgeAction): RappBridgeOutcome {
            check((action.frame != null) == (action.kind == RappBridgeActionKind.SEND_FRAME))
            return when (action.kind) {
                RappBridgeActionKind.SEND_FRAME -> {
                    check(action.closeSessionAfterSend == (action.closeReason != null))
                    Send(checkNotNull(action.frame).also { check(it.isNotEmpty()) }, action.closeReason)
                }

                RappBridgeActionKind.NO_ACTION -> {
                    Idle
                }

                RappBridgeActionKind.INSPECT_PREREQUISITES -> {
                    Admitted(operationId(action))
                }

                RappBridgeActionKind.AWAIT_USER_APPROVAL -> {
                    AwaitApproval(operationId(action), request(action))
                }

                RappBridgeActionKind.EXECUTE_SAFE_READ -> {
                    ExecuteRead(operationId(action), request(action))
                }

                RappBridgeActionKind.EXECUTE_CARD_COMMAND -> {
                    ExecuteCommand(operationId(action), request(action))
                }

                RappBridgeActionKind.COMPLETED -> {
                    Completed(operationId(action), RappAnswer.from(checkNotNull(action.result)))
                }

                RappBridgeActionKind.TERMINAL -> {
                    Terminal(operationId(action), checkNotNull(action.terminalReason))
                }

                RappBridgeActionKind.PROGRESS -> {
                    Progress(operationId(action), checkNotNull(action.progressEvent))
                }

                RappBridgeActionKind.CARD_STATUS -> {
                    CardStatus(cardStatus(action), checkNotNull(action.cardReader))
                }

                RappBridgeActionKind.SESSION_CLOSED -> {
                    Closed(action.closeReason)
                }
            }
        }

        private fun operationId(action: RappBridgeAction): RappOperationId =
            checkNotNull(action.operationId?.let(RappOperationId::fromWire))

        private fun request(action: RappBridgeAction): RappRequest = RappRequest.from(checkNotNull(action.operation))

        private fun cardStatus(action: RappBridgeAction): RappCardStatus {
            val fingerprint = action.certificateFingerprint
            return if (checkNotNull(action.cardPresent)) {
                RappCardStatus.Present(checkNotNull(fingerprint?.let(RappCertificateFingerprint::fromWire)))
            } else {
                check(fingerprint == null)
                RappCardStatus.Absent
            }
        }
    }
}
