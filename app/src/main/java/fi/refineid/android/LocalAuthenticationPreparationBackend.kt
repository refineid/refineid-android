package fi.refineid.android

import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPreparationBackend
import fi.refineid.android.core.AuthenticationReadiness
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.CardConnection
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin1VerificationOutcome
import fi.refineid.android.core.Pin1VerificationResult
import fi.refineid.android.core.runPin1Verification
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.nfc.NfcReaderStatus
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderConnectionStatus
import fi.refineid.android.usb.UsbReaderSnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

/** Selects and awaits a local card on Main; blocking card/storage work runs off Main. */
internal class LocalAuthenticationPreparationBackend(
    private val app: RefineIdApplication,
) : AuthenticationPreparationBackend {
    private var selected: AuthenticationCardService? = null
    private var stamp: TransportStamp? = null

    override fun readiness(): AuthenticationReadiness {
        val usb = app.readerController.snapshot
        val wired = usb.cardPresence == CardPresence.PRESENT
        val nfc = app.nfcReaderController.snapshot
        val primed = nfc.isPrimed && app.authenticationInvalidation?.isActive != true
        return AuthenticationReadiness(
            hasCertificate =
                if (wired) {
                    app.readerController.isCardReady
                } else {
                    primed && app.primedCanStore.hasAuthCertificate()
                },
            needsCan =
                if (wired) {
                    usb.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                        usb.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER
                } else {
                    nfc.status == NfcReaderStatus.WRONG_CAN || (!CanSessionStore.hasCan && !primed)
                },
            available = wired || (app.nfcReaderController.hasNfc && nfc.status != NfcReaderStatus.TURNED_OFF),
        )
    }

    override suspend fun connect(can: CanSubmission?): CardConnection {
        app.authenticationInvalidation?.join()
        val generation = app.authenticationGeneration.get()
        val wired = app.readerController.snapshot.cardPresence == CardPresence.PRESENT
        selected = if (wired) app.readerController else app.nfcReaderController.authenticationCardService
        if (wired) {
            if (!app.readerController.isCardReady) {
                if (can != null) app.readerController.connect(can.copy(), null) else app.readerController.refresh()
            }
        } else {
            app.nfcReaderController.connect(can, null)
        }
        val connection = awaitPreferredCard()
        if (connection != CardConnection.READY) return connection
        if (generation != app.authenticationGeneration.get()) return CardConnection.REFUSED
        val current = currentStamp()
        stamp = current
        selected = if (current.wired) app.readerController else app.nfcReaderController.authenticationCardService
        return CardConnection.READY
    }

    override suspend fun pin1AttemptsLeft(): Int? {
        val expected = stamp ?: return null
        if (expected != currentStamp()) return null
        val service = if (expected.wired) app.readerController else app.nfcReaderController.authenticationCardService
        return suspendCancellableCoroutine { continuation ->
            service.requestPin1AttemptsLeft { attempts ->
                if (continuation.isActive) continuation.resume(attempts)
            }
        }
    }

    /**
     * Verifies on the exact session [connect] proved ready. Cancellation
     * bumps that session's generation, so queued work is refused rather
     * than waiting for, or prompting for, another card.
     */
    override suspend fun verify(
        pin1: Pin1Submission,
        outcome: Pin1VerificationOutcome,
    ): Pin1VerificationResult {
        val expected = stamp
        val result =
            runPin1Verification(Dispatchers.IO, pin1, outcome) { submission ->
                when {
                    expected == null || expected != currentStamp() -> {
                        submission.close()
                        Pin1VerificationResult.CARD_UNAVAILABLE
                    }

                    expected.wired -> {
                        app.readerController.verifyAuthenticationPin(submission, expected.session).result
                    }

                    else -> {
                        app.nfcReaderController.authenticationCardService
                            .verifyAuthenticationPin(submission, expected.session)
                            .result
                    }
                }
            }
        return if (result == Pin1VerificationResult.VERIFIED && expected != currentStamp()) {
            Pin1VerificationResult.CARD_UNAVAILABLE
        } else {
            result
        }
    }

    override suspend fun retainVerified(pin: ByteArray): Boolean =
        withContext(Dispatchers.IO) {
            try {
                synchronized(app.authenticationCustodyLock) {
                    if (stamp != currentStamp()) {
                        false
                    } else {
                        if (app.primedCanStore.isPrimed()) app.primedCanStore.writePin1(pin.copyOf())
                        app.authenticationPinCache.recordVerified(pin.copyOf())
                        true
                    }
                }
            } finally {
                pin.fill(0)
            }
        }

    override fun invalidate() = app.invalidateAuthentication()

    override fun cancel() {
        val wasWired = selected === app.readerController
        val wasNfc = selected != null && !wasWired
        selected = null
        stamp = null
        if (wasWired) {
            app.readerController.invalidateAuthenticationSession()
        } else if (wasNfc || app.readerController.snapshot.cardPresence != CardPresence.PRESENT) {
            app.nfcReaderController.cancelAuthenticationPreparation()
        }
    }

    /**
     * Waits for the reader to settle: a card ready, a card that answered
     * and cannot be used, or nothing within the wait, which counts as no
     * card. A contactless card that lost contact is no card either: the
     * caller arms the reader again and the holder taps again.
     */
    private suspend fun awaitPreferredCard(): CardConnection =
        withTimeoutOrNull(CARD_WAIT_TIMEOUT_MS) {
            // A transport error the reader published before this wait began
            // belongs to the previous tap; only a newer snapshot settles it.
            val stale = app.nfcReaderController.snapshot.takeIf { it.status == NfcReaderStatus.TRANSPORT_ERROR }
            suspendCancellableCoroutine { continuation ->
                lateinit var usbListener: (UsbReaderSnapshot) -> Unit
                lateinit var nfcListener: (NfcReaderSnapshot) -> Unit

                fun finish() {
                    val nfcUnsettled = stale != null && app.nfcReaderController.snapshot === stale
                    val connection = settledConnection(nfcUnsettled) ?: return
                    if (continuation.isActive) {
                        app.readerController.removeStateListener(usbListener)
                        app.nfcReaderController.removeStateListener(nfcListener)
                        continuation.resume(connection)
                    }
                }
                usbListener = { finish() }
                nfcListener = { finish() }
                // Registration publishes immediately. Register both before completing.
                app.readerController.addStateListener(usbListener)
                if (continuation.isActive) app.nfcReaderController.addStateListener(nfcListener)
                continuation.invokeOnCancellation {
                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        app.readerController.removeStateListener(usbListener)
                        app.nfcReaderController.removeStateListener(nfcListener)
                    }
                }
            }
        } ?: CardConnection.ABSENT

    /** What the reader holds right now, or null while it is still waiting. */
    private fun settledConnection(nfcUnsettled: Boolean): CardConnection? {
        val usb = app.readerController.snapshot
        if (usb.cardPresence == CardPresence.PRESENT) {
            return when {
                app.readerController.isCardReady -> CardConnection.READY

                usb.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                    usb.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER -> CardConnection.WRONG_CAN

                usb.status == ReaderConnectionStatus.ACTIVATION_REQUIRED ||
                    usb.status == ReaderConnectionStatus.CARD_ERROR ||
                    usb.status == ReaderConnectionStatus.TRANSPORT_ERROR -> CardConnection.REFUSED

                else -> null
            }
        }
        if (nfcUnsettled) return null
        val nfc = app.nfcReaderController.snapshot
        return when {
            app.nfcReaderController.isCardReady -> CardConnection.READY
            nfc.status == NfcReaderStatus.WRONG_CAN -> CardConnection.WRONG_CAN
            nfc.status == NfcReaderStatus.ACTIVATION_REQUIRED -> CardConnection.REFUSED
            nfc.status == NfcReaderStatus.TRANSPORT_ERROR -> CardConnection.ABSENT
            else -> null
        }
    }

    private fun currentStamp(): TransportStamp {
        val wired = app.readerController.snapshot.cardPresence == CardPresence.PRESENT
        return TransportStamp(
            wired,
            if (wired) {
                app.readerController.authenticationSessionGeneration
            } else {
                app.nfcReaderController.authenticationSessionGeneration
            },
            app.authenticationGeneration.get(),
        )
    }

    private data class TransportStamp(
        val wired: Boolean,
        val session: Int,
        val custody: Int,
    )

    private companion object {
        const val CARD_WAIT_TIMEOUT_MS = 30_000L
    }
}
