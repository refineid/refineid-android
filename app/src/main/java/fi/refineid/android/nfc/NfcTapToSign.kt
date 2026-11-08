package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import android.os.Handler
import android.os.Looper
import fi.refineid.android.core.NativeCardAccessResult
import fi.refineid.android.core.NativeCardExchangeLevel
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.core.NativeContactlessCore
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException

/**
 * Tap-to-sign: a qualified signature waits for the holder to present the
 * card instead of requiring a pre-opened session. The caller shows a hold
 * prompt and calls [begin]. A session the reader already holds takes the
 * presented tag and serves at once; otherwise the card's EF.CardAccess names
 * its kind and a transient session opens for it, a citizen card's with the
 * supplied or primed access number, an organisation card's with the
 * certificates Basic PIN 1 read. Control returns through the ready callback
 * so the qualified read and sign can run, or through the failure callback
 * with the reason the card cannot sign. [end] closes only a session the tap
 * opened.
 *
 * The `inProgress` flag is set on the main thread and read on the reader
 * thread; every session mutation runs on the shared worker thread, so the
 * session is the same one the qualified card service serves.
 */
internal class NfcTapToSign<Tag>(
    private val worker: Executor,
    private val mainThread: SignTapMainThread,
    private val latestTag: () -> Tag?,
    private val card: SignTapCard<Tag>,
    private val accessNumber: () -> ByteArray?,
    private val closeSession: () -> Unit,
) {
    @Volatile
    var inProgress = false
        private set

    /** Whether a card left the field during this wait; written on the worker. */
    @Volatile
    private var cardLeft = false

    // Worker-thread confined.
    private var can: ByteArray? = null
    private var ready: (() -> Unit)? = null
    private var failed: ((SignTapFailure) -> Unit)? = null
    private var openedSession = false

    // Main-thread confined.
    private var timeout: Runnable? = null

    /**
     * Wait for the holder to present the card, then hand back through
     * [onReady] once a session serves the signature. A null access number
     * falls back to the remembered or primed one. [onFailure] fires with the
     * reason when the card cannot sign, or when no card served in time. The
     * bytes are owned here and zeroized on teardown.
     */
    fun begin(
        canBytes: ByteArray?,
        onReady: () -> Unit,
        onFailure: (SignTapFailure) -> Unit,
    ) {
        checkMainThread()
        inProgress = true
        cardLeft = false
        timeout?.let(mainThread::remove)
        val pending =
            Runnable {
                timeout = null
                val failure = if (cardLeft) SignTapFailure.CARD_LEFT else SignTapFailure.NO_CARD
                AppTrace.nfcSignTapFailed(failure)
                end()
                onFailure(failure)
            }
        timeout = pending
        mainThread.postDelayed(pending, SIGNATURE_TAP_TIMEOUT_MILLISECONDS)
        val resting = latestTag()
        try {
            worker.execute {
                can?.fill(0)
                can = canBytes
                ready = onReady
                failed = onFailure
                if (resting != null) {
                    onTag(resting)
                }
            }
        } catch (_: RejectedExecutionException) {
            canBytes?.fill(0)
            inProgress = false
            timeout?.let(mainThread::remove)
            timeout = null
            onFailure(SignTapFailure.NO_CARD)
        }
    }

    /** Close a session the tap opened and forget its inputs. */
    fun end() {
        checkMainThread()
        inProgress = false
        timeout?.let(mainThread::remove)
        timeout = null
        try {
            worker.execute {
                ready = null
                failed = null
                can?.fill(0)
                can = null
                if (openedSession) {
                    openedSession = false
                    closeSession()
                }
            }
        } catch (_: RejectedExecutionException) {
            // The executor only stops when the process is terminating.
        }
    }

    /** Best-effort teardown on reader stop; main-thread callbacks only. */
    fun cancel() {
        inProgress = false
        timeout?.let(mainThread::remove)
        timeout = null
    }

    /**
     * Worker-thread confined; claims a presented tag for the waiting
     * signature. Repeated taps after the session serves only hand it the
     * fresh handle.
     */
    fun onTag(tag: Tag) {
        if (!inProgress) {
            return
        }
        val claim =
            SignTapClaimer.claim(card, tag) {
                val number = can ?: accessNumber()
                can = null
                number
            }
        AppTrace.nfcSignTapClaimed(claim)
        when (claim) {
            is SignTapClaim.Ready -> {
                openedSession = openedSession || claim.opened
                val onReady = ready ?: return
                ready = null
                mainThread.post {
                    if (inProgress) {
                        timeout?.let(mainThread::remove)
                        timeout = null
                        onReady()
                    }
                }
            }

            SignTapClaim.CardLeft -> {
                cardLeft = true
            }

            is SignTapClaim.Refused -> {
                can?.fill(0)
                can = null
                val onFailure = failed ?: return
                ready = null
                failed = null
                mainThread.post {
                    if (inProgress) {
                        AppTrace.nfcSignTapFailed(claim.failure)
                        end()
                        onFailure(claim.failure)
                    }
                }
            }
        }
    }

    private fun checkMainThread() {
        check(mainThread.isCurrent()) {
            "tap-to-sign state must be changed on the main thread"
        }
    }

    internal companion object {
        /** How long a tap-to-sign waits for the holder to present the card. */
        const val SIGNATURE_TAP_TIMEOUT_MILLISECONDS = 25_000L
    }
}

/** The main thread as the tap sees it: posts, delays and the thread check. */
internal interface SignTapMainThread {
    fun post(action: Runnable)

    fun postDelayed(
        action: Runnable,
        delayMillis: Long,
    )

    fun remove(action: Runnable)

    fun isCurrent(): Boolean
}

/** [SignTapMainThread] over the main looper's handler. */
internal class HandlerSignTapMainThread(
    private val handler: Handler,
) : SignTapMainThread {
    override fun post(action: Runnable) {
        handler.post(action)
    }

    override fun postDelayed(
        action: Runnable,
        delayMillis: Long,
    ) {
        handler.postDelayed(action, delayMillis)
    }

    override fun remove(action: Runnable) {
        handler.removeCallbacks(action)
    }

    override fun isCurrent(): Boolean = Looper.myLooper() == Looper.getMainLooper()
}

/**
 * The ISO-DEP card behind a waiting signature, on the reader's worker thread:
 * the reader's session, the tag connection, the EF.CardAccess probe, and the
 * sessions a tap opens.
 */
internal class IsoDepSignTapCard(
    private val activeSession: () -> ContactlessCardSession?,
    private val adoptSession: (ContactlessCardSession) -> Unit,
    private val organizationSession: (IsoDep) -> ContactlessCardSession?,
) : SignTapCard<IsoDep> {
    override fun hasSession(): Boolean = activeSession() != null

    override fun adopt(tag: IsoDep) {
        activeSession()?.adopt(tag)
    }

    override fun connect(tag: IsoDep): Boolean =
        try {
            if (!tag.isConnected) {
                tag.connect()
            }
            tag.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            true
        } catch (_: IOException) {
            AppTrace.nfcSessionOpenFailed()
            false
        } catch (_: SecurityException) {
            AppTrace.nfcSessionOpenFailed()
            false
        } catch (_: IllegalStateException) {
            AppTrace.nfcSessionOpenFailed()
            false
        }

    override fun probe(tag: IsoDep): NativeCardAccessResult =
        NativeContactlessCore.probeCardAccess(
            exchangeLevel = NativeCardExchangeLevel.APDU,
            exchange = NfcNativeBlockExchange(IsoDepCardChannel(tag)),
        )

    override fun openCitizen(
        tag: IsoDep,
        accessNumber: ByteArray,
    ) {
        adoptSession(
            ContactlessSession(
                isoDep = tag,
                can = accessNumber,
                material = NativeCardSessionMaterial(),
            ),
        )
    }

    override fun openOrganization(tag: IsoDep): Boolean {
        val session = organizationSession(tag) ?: return false
        adoptSession(session)
        return true
    }

    private companion object {
        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 15_000
    }
}
