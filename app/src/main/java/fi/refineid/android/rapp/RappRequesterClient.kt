@file:Suppress(
    "TooGenericExceptionCaught",
    "SwallowedException",
    "MagicNumber",
    "MaxLineLength",
    "DEPRECATION",
    "CyclomaticComplexMethod",
    "LongMethod",
)

package fi.refineid.android.rapp

import android.content.Context
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.refineid_rapp.RappBridgeAction
import uniffi.refineid_rapp.RappBridgeActionKind
import uniffi.refineid_rapp.RappCardKeyProfile
import uniffi.refineid_rapp.RappLivenessConfiguration
import uniffi.refineid_rapp.RappOperationBridge
import uniffi.refineid_rapp.RappPairRecord
import uniffi.refineid_rapp.RappSessionBridge
import uniffi.refineid_rapp.RappSignatureAlgorithm
import uniffi.refineid_rapp.rappStreamSessionPreamble
import java.security.SecureRandom

/**
 * Connects over stream transport to a paired proxy device and executes
 * operations on the remote card.
 */
internal class RappRequesterClient(
    private val context: Context,
    private val scope: CoroutineScope,
    private val pairRecord: RappPairRecord,
    private val vault: AndroidRappVault,
) {
    private enum class SessionState {
        IDLE,
        AWAITING_RESPONDER_HANDSHAKE,
        AWAITING_RESPONDER_READY,
        ESTABLISHED,
    }

    suspend fun readAuthenticationCertificate(timeoutMs: Long = 15_000L): ByteArray? =
        executeOperation(timeoutMs = timeoutMs) { bridge, opId ->
            bridge.beginReadCertificate(
                operationId = opId,
                signatureCertificate = false,
                localStartMs = RappClock.monotonicMs(),
                expiresAfterMs = 120_000UL,
            )
        }

    suspend fun browserAuthenticate(
        origin: String,
        keyProfile: RappCardKeyProfile,
        algorithm: RappSignatureAlgorithm,
        digest: ByteArray,
        timeoutMs: Long = 60_000L,
    ): ByteArray? =
        executeOperation(timeoutMs = timeoutMs) { bridge, opId ->
            bridge.beginBrowserAuthentication(
                operationId = opId,
                origin = origin,
                keyProfile = keyProfile,
                algorithm = algorithm,
                digest = digest,
                localStartMs = RappClock.monotonicMs(),
                expiresAfterMs = 120_000UL,
            )
        }

    private suspend fun executeOperation(
        timeoutMs: Long,
        startOperation: (RappOperationBridge, ByteArray) -> RappBridgeAction,
    ): ByteArray? =
        withTimeoutOrNull(timeoutMs) {
            val deferred = CompletableDeferred<ByteArray?>()
            val token = pairRecord.metadata().rendezvousToken
            val preamble =
                try {
                    rappStreamSessionPreamble(token)
                } catch (e: Exception) {
                    android.util.Log.e("REQUESTER_CLIENT", "rappStreamSessionPreamble failed", e)
                    return@withTimeoutOrNull null
                }
            val serviceName = StreamRendezvousName.name(sharingValue = token)

            var browser: StreamRelayBrowser? = null
            var sessionBridge: RappSessionBridge? = null
            var operationBridge: RappOperationBridge? = null
            var state = SessionState.IDLE
            val opId = ByteArray(16).also { SecureRandom().nextBytes(it) }

            fun cleanup() {
                try {
                    operationBridge?.close()
                } catch (_: Exception) {
                }
                operationBridge = null
                try {
                    sessionBridge?.close()
                } catch (_: Exception) {
                }
                sessionBridge = null
                try {
                    browser?.close()
                } catch (_: Exception) {
                }
                browser = null
            }

            browser =
                StreamRelayBrowser(context, scope, serviceName) { event ->
                    when (event) {
                        is StreamRelayEvent.Connected -> {
                            try {
                                if (BuildConfig.DEBUG) {
                                    android.util.Log.i("REQUESTER_CLIENT", "Connected to proxy, sending preamble")
                                }
                                browser?.send(preamble)
                                val sess = RappSessionBridge.beginRequester(pair = pairRecord, vault = vault)
                                sessionBridge = sess
                                val handshake1 = sess.writeHandshakeFrame()
                                browser?.send(handshake1)
                                state = SessionState.AWAITING_RESPONDER_HANDSHAKE
                            } catch (e: Exception) {
                                android.util.Log.e("REQUESTER_CLIENT", "Failed starting handshake", e)
                                deferred.complete(null)
                                cleanup()
                            }
                        }

                        is StreamRelayEvent.Frame -> {
                            val sess = sessionBridge
                            if (sess == null) {
                                deferred.complete(null)
                                cleanup()
                                return@StreamRelayBrowser
                            }

                            val op = operationBridge
                            if (op != null) {
                                try {
                                    val action = op.receiveFrame(event.data, RappClock.monotonicMs())
                                    if (action.kind == RappBridgeActionKind.RESULT_ACKNOWLEDGMENT) {
                                        action.frame?.let { ackFrame ->
                                            browser?.send(ackFrame)
                                        }
                                        val releasedOpId = action.operationId ?: opId
                                        val result = op.acknowledgmentReleased(releasedOpId)
                                        if (BuildConfig.DEBUG) {
                                            android.util.Log.i(
                                                "REQUESTER_CLIENT",
                                                "Operation success! bytes=${result.bytes.size}",
                                            )
                                        }
                                        try {
                                            op.closeSession()
                                        } catch (_: Exception) {
                                        }
                                        deferred.complete(result.bytes)
                                        cleanup()
                                    } else if (action.kind == RappBridgeActionKind.PROGRESS) {
                                        if (BuildConfig.DEBUG) {
                                            android.util.Log.i(
                                                "REQUESTER_CLIENT",
                                                "Operation progress: ${action.progressEvent}",
                                            )
                                        }
                                        return@StreamRelayBrowser
                                    } else if (action.kind == RappBridgeActionKind.SEND_FRAME) {
                                        action.frame?.let { f -> browser?.send(f) }
                                    } else if (action.kind == RappBridgeActionKind.TERMINAL ||
                                        action.kind == RappBridgeActionKind.SESSION_CLOSED ||
                                        action.kind == RappBridgeActionKind.CANCELLED
                                    ) {
                                        android.util.Log.w("REQUESTER_CLIENT", "Operation ended with ${action.kind}")
                                        deferred.complete(null)
                                        cleanup()
                                    }
                                } catch (e: Exception) {
                                    android.util.Log.e("REQUESTER_CLIENT", "receiveFrame failed in operation", e)
                                    deferred.complete(null)
                                    cleanup()
                                }
                                return@StreamRelayBrowser
                            }

                            when (state) {
                                SessionState.AWAITING_RESPONDER_HANDSHAKE -> {
                                    try {
                                        sess.readHandshakeFrame(event.data)
                                        if (!sess.handshakeComplete()) {
                                            android.util.Log.w("REQUESTER_CLIENT", "Handshake not complete after reply")
                                            deferred.complete(null)
                                            cleanup()
                                            return@StreamRelayBrowser
                                        }
                                        sess.enterAuthentication()
                                        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
                                        val ready = sess.sendReady(nonce)
                                        browser?.send(ready)
                                        state = SessionState.AWAITING_RESPONDER_READY
                                    } catch (e: Exception) {
                                        android.util.Log.e("REQUESTER_CLIENT", "Handshake reply failed", e)
                                        deferred.complete(null)
                                        cleanup()
                                    }
                                }

                                SessionState.AWAITING_RESPONDER_READY -> {
                                    try {
                                        sess.receiveReady(event.data, RappClock.wallMs())
                                        sess.enterEstablished()
                                        state = SessionState.ESTABLISHED
                                        if (BuildConfig.DEBUG) {
                                            android.util.Log.i(
                                                "REQUESTER_CLIENT",
                                                "Session established! Starting operation",
                                            )
                                        }

                                        val liveness =
                                            RappLivenessConfiguration(
                                                baseIntervalMs = 5_000UL,
                                                responseTimeoutMs = 10_000UL,
                                                maximumIntervalMs = 60_000UL,
                                                maximumJitterMs = 500UL,
                                                maximumMisses = 3.toUByte(),
                                            )
                                        val bridge =
                                            RappOperationBridge.beginRequester(
                                                session = sess,
                                                vault = vault,
                                                maximumLifetimeMs = 120_000UL,
                                                liveness = liveness,
                                                nowMs = RappClock.monotonicMs(),
                                            )
                                        operationBridge = bridge

                                        val action = startOperation(bridge, opId)
                                        if (action.kind == RappBridgeActionKind.SEND_FRAME && action.frame != null) {
                                            browser?.send(action.frame!!)
                                        }
                                    } catch (e: Exception) {
                                        android.util.Log.e(
                                            "REQUESTER_CLIENT",
                                            "Failed establishing or startOperation",
                                            e,
                                        )
                                        deferred.complete(null)
                                        cleanup()
                                    }
                                }

                                else -> {
                                }
                            }
                        }

                        is StreamRelayEvent.Disconnected -> {
                            if (!deferred.isCompleted) {
                                deferred.complete(null)
                            }
                            cleanup()
                        }

                        is StreamRelayEvent.Error -> {
                            if (!deferred.isCompleted) {
                                deferred.complete(null)
                            }
                            cleanup()
                        }
                    }
                }

            browser?.start()
            deferred.await()
        }
}
