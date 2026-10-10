package fi.refineid.android

import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.AuthenticationPreparationBackend
import fi.refineid.android.core.AuthenticationReadiness
import fi.refineid.android.core.CanSessionStore
import fi.refineid.android.core.CanSubmission
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

    override suspend fun connect(can: CanSubmission?): Boolean {
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
        val ready = awaitPreferredCard()
        if (!ready || generation != app.authenticationGeneration.get()) return false
        val current = currentStamp()
        stamp = current
        selected = if (current.wired) app.readerController else app.nfcReaderController.authenticationCardService
        return true
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

    private suspend fun awaitPreferredCard(): Boolean =
        withTimeoutOrNull(CARD_WAIT_TIMEOUT_MS) {
            suspendCancellableCoroutine { continuation ->
                lateinit var usbListener: (UsbReaderSnapshot) -> Unit
                lateinit var nfcListener: (NfcReaderSnapshot) -> Unit

                fun finish() {
                    val usb = app.readerController.snapshot
                    val nfc = app.nfcReaderController.snapshot
                    val wired = usb.cardPresence == CardPresence.PRESENT
                    val ready = if (wired) app.readerController.isCardReady else app.nfcReaderController.isCardReady
                    val failed =
                        if (wired) {
                            usb.status == ReaderConnectionStatus.ACCESS_NUMBER_REQUIRED ||
                                usb.status == ReaderConnectionStatus.WRONG_ACCESS_NUMBER ||
                                usb.status == ReaderConnectionStatus.ACTIVATION_REQUIRED ||
                                usb.status == ReaderConnectionStatus.CARD_ERROR ||
                                usb.status == ReaderConnectionStatus.TRANSPORT_ERROR
                        } else {
                            nfc.status == NfcReaderStatus.WRONG_CAN ||
                                nfc.status == NfcReaderStatus.ACTIVATION_REQUIRED ||
                                nfc.status == NfcReaderStatus.TRANSPORT_ERROR
                        }
                    if ((ready || failed) && continuation.isActive) {
                        app.readerController.removeStateListener(usbListener)
                        app.nfcReaderController.removeStateListener(nfcListener)
                        continuation.resume(ready)
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
        } ?: false

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
