package fi.refineid.android.nfc

import android.nfc.tech.IsoDep
import android.os.Handler
import fi.refineid.android.core.NativeCardSessionMaterial
import fi.refineid.android.diagnostics.AppTrace
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/**
 * Tap-to-sign: a qualified signature waits for the holder to present the
 * card instead of requiring a pre-opened session. The caller shows a
 * hold prompt and calls [begin]; the next presented tag opens a
 * transient signing session against the supplied access number — or the
 * primed one — and control returns through the ready callback so the
 * qualified read and sign can run. [end] tears the session down.
 *
 * The `inProgress` flag is set on the main thread and read on the reader
 * thread; every session mutation runs on the shared worker thread, so
 * the transient session is the same one the qualified card service
 * serves.
 */
internal class NfcTapToSign(
    private val probeExecutor: ExecutorService,
    private val mainHandler: Handler,
    private val latestIsoDep: () -> IsoDep?,
    private val primedCan: () -> ByteArray?,
    private val activeSession: () -> ContactlessCardSession?,
    private val adoptSession: (ContactlessCardSession) -> Unit,
    private val organizationSession: (IsoDep) -> ContactlessCardSession? = { null },
    private val closeSession: () -> Unit,
) {
    @Volatile
    var inProgress = false
        private set

    // Worker-thread confined.
    private var can: ByteArray? = null
    private var ready: (() -> Unit)? = null

    // Main-thread confined.
    private var timeout: Runnable? = null

    /**
     * Wait for the holder to present the card, then open a transient
     * signing session and hand back through [onReady]. A null access
     * number falls back to the primed one; [onNoCard] fires if no card
     * arrives in time. The bytes are owned here and zeroized on teardown.
     */
    fun begin(
        canBytes: ByteArray?,
        onReady: () -> Unit,
        onNoCard: () -> Unit,
    ) {
        checkMainThread()
        inProgress = true
        timeout?.let(mainHandler::removeCallbacks)
        val pending =
            Runnable {
                timeout = null
                end()
                onNoCard()
            }
        timeout = pending
        mainHandler.postDelayed(pending, SIGNATURE_TAP_TIMEOUT_MILLISECONDS)
        val resting = latestIsoDep()
        try {
            probeExecutor.execute {
                can?.fill(0)
                can = canBytes
                ready = onReady
                if (resting != null) {
                    onTag(resting)
                }
            }
        } catch (_: RejectedExecutionException) {
            canBytes?.fill(0)
            inProgress = false
            timeout?.let(mainHandler::removeCallbacks)
            timeout = null
            onNoCard()
        }
    }

    /** Close the transient signing session and forget its inputs. */
    fun end() {
        checkMainThread()
        inProgress = false
        timeout?.let(mainHandler::removeCallbacks)
        timeout = null
        try {
            probeExecutor.execute {
                ready = null
                can?.fill(0)
                can = null
                closeSession()
            }
        } catch (_: RejectedExecutionException) {
            // The executor only stops when the process is terminating.
        }
    }

    /** Best-effort teardown on reader stop; main-thread callbacks only. */
    fun cancel() {
        inProgress = false
        timeout?.let(mainHandler::removeCallbacks)
        timeout = null
    }

    /**
     * Worker-thread confined; adopts a presented tag into the transient
     * signing session, opening it on the first tap. The qualified read
     * and sign each re-run PACE with the session access number, or on an
     * organization card, which has none, with the credential each spends; a
     * substituted card of the other kind is refused before any password is
     * named.
     */
    fun onTag(isoDep: IsoDep) {
        if (!inProgress) {
            return
        }
        val session = activeSession()
        if (session != null) {
            session.adopt(isoDep)
            return
        }
        val number =
            can ?: fi.refineid.android.core.CanSessionStore
                .canBytes() ?: primedCan()
        try {
            if (!isoDep.isConnected) {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MILLISECONDS
            }
        } catch (_: IOException) {
            AppTrace.nfcSessionOpenFailed()
            return
        } catch (_: SecurityException) {
            AppTrace.nfcSessionOpenFailed()
            return
        } catch (_: IllegalStateException) {
            AppTrace.nfcSessionOpenFailed()
            return
        }
        can = null
        val opened =
            if (number != null) {
                ContactlessSession(
                    isoDep = isoDep,
                    can = number,
                    material = NativeCardSessionMaterial(),
                )
            } else {
                organizationSession(isoDep) ?: return
            }
        adoptSession(opened)
        val onReady = ready
        mainHandler.post {
            if (inProgress) {
                timeout?.let(mainHandler::removeCallbacks)
                timeout = null
                onReady?.invoke()
            }
        }
    }

    private fun checkMainThread() {
        check(android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
            "tap-to-sign state must be changed on the main thread"
        }
    }

    private companion object {
        /** Bound on one contactless exchange, PACE cryptography included. */
        const val TRANSCEIVE_TIMEOUT_MILLISECONDS = 15_000

        /** How long a tap-to-sign waits for the holder to present the card. */
        const val SIGNATURE_TAP_TIMEOUT_MILLISECONDS = 25_000L
    }
}
