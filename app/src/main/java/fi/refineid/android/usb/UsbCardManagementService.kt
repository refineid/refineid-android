package fi.refineid.android.usb

import android.os.Handler
import fi.refineid.android.core.ActivationReport
import fi.refineid.android.core.CardActivationNeeds
import fi.refineid.android.core.CardManagementFailure
import fi.refineid.android.core.CardManagementResult
import fi.refineid.android.core.CardManagementScheme
import fi.refineid.android.core.CardManagementService
import fi.refineid.android.core.CredentialHealth
import fi.refineid.android.core.ManageOutcome
import fi.refineid.android.core.NativePin1State
import fi.refineid.android.core.NativePin2State
import fi.refineid.android.core.NativePinReferenceScheme
import fi.refineid.android.usb.ccid.CcidUsbSession
import java.util.concurrent.ExecutorService
import java.util.concurrent.RejectedExecutionException

/** Card management work serialized onto the USB session's owner thread. */
internal class UsbCardManagementService(
    private val ioExecutor: ExecutorService,
    private val mainHandler: Handler,
    private val isReady: () -> Boolean,
    private val currentGeneration: () -> Int,
    private val isCurrentGeneration: (Int) -> Boolean,
    private val activeSession: () -> CcidUsbSession?,
) : CardManagementService {
    override fun probeCredentialHealth(onResult: (CardManagementResult<CredentialHealth>) -> Unit) {
        if (!isReady()) {
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.probeCredentialHealth(readPinLengths = true)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }

    override fun changePin1(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) {
        if (!isReady()) {
            currentPin.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.changePin1(currentPin, newPin)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        currentPin.fill(0)
                        newPin.fill(0)
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            currentPin.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }

    override fun changePin2(
        currentPin: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) {
        if (!isReady()) {
            currentPin.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.changePin2(currentPin, newPin)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        currentPin.fill(0)
                        newPin.fill(0)
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            currentPin.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }

    override fun unblockPin1(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) {
        if (!isReady()) {
            puk.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.unblockPin1(puk, newPin)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        puk.fill(0)
                        newPin.fill(0)
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            puk.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }

    override fun unblockPin2(
        puk: ByteArray,
        newPin: ByteArray,
        onResult: (CardManagementResult<ManageOutcome>) -> Unit,
    ) {
        if (!isReady()) {
            puk.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.unblockPin2(puk, newPin)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        puk.fill(0)
                        newPin.fill(0)
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            puk.fill(0)
            newPin.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }

    override fun activateCard(
        scheme: CardManagementScheme,
        code: ByteArray,
        newPin1: ByteArray?,
        newPin2: ByteArray?,
        onResult: (CardManagementResult<ActivationReport>) -> Unit,
    ) {
        if (!isReady()) {
            code.fill(0)
            newPin1?.fill(0)
            newPin2?.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
            return
        }
        val generation = currentGeneration()
        try {
            ioExecutor.execute {
                val result =
                    if (isCurrentGeneration(generation)) {
                        try {
                            activeSession()?.activateCard(scheme, code, newPin1, newPin2)
                                ?: CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                        } catch (_: IllegalStateException) {
                            CardManagementResult.Failure(CardManagementFailure.BRIDGE_ERROR)
                        }
                    } else {
                        code.fill(0)
                        newPin1?.fill(0)
                        newPin2?.fill(0)
                        CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE)
                    }
                mainHandler.post {
                    onResult(result)
                }
            }
        } catch (_: RejectedExecutionException) {
            code.fill(0)
            newPin1?.fill(0)
            newPin2?.fill(0)
            onResult(CardManagementResult.Failure(CardManagementFailure.CARD_UNAVAILABLE))
        }
    }
}
