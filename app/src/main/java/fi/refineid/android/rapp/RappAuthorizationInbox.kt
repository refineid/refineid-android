package fi.refineid.android.rapp

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

internal enum class RappAuthAction {
    BROWSER_AUTH,
    DOCUMENT_SIGN,
}

internal data class RappAuthRequest(
    val requestId: String,
    val requester: String,
    val action: RappAuthAction,
    val onApproved: (pin: String) -> Unit,
    val onDenied: () -> Unit,
)

internal data class RappCardTapPrompt(
    val requestId: String,
    val requester: String,
    val action: RappAuthAction,
    val onCancel: () -> Unit,
)

/**
 * Rendezvous between incoming RAPP proxy events, notifications, and Compose UI.
 */
internal class RappAuthorizationInbox(
    private val context: Context,
) {
    private val notificationManager = RappNotificationManager(context)

    var isForeground: Boolean = false
        private set

    var currentRequest by mutableStateOf<RappAuthRequest?>(null)
        private set

    var currentTapPrompt by mutableStateOf<RappCardTapPrompt?>(null)
        private set

    fun updateForeground(foreground: Boolean) {
        isForeground = foreground
        if (foreground) {
            notificationManager.dismissNotification()
        } else {
            currentRequest?.let {
                notificationManager.postAuthorizationNotification(it.requestId)
            } ?: currentTapPrompt?.let {
                notificationManager.postAuthorizationNotification(it.requestId)
            }
        }
    }

    fun ask(
        requestId: String,
        requester: String,
        action: RappAuthAction,
        onApproved: (pin: String) -> Unit,
        onDenied: () -> Unit,
    ) {
        val req =
            RappAuthRequest(
                requestId = requestId,
                requester = requester,
                action = action,
                onApproved = { pin ->
                    notificationManager.dismissNotification()
                    currentRequest = null
                    onApproved(pin)
                },
                onDenied = {
                    notificationManager.dismissNotification()
                    currentRequest = null
                    onDenied()
                },
            )
        currentRequest = req
        if (!isForeground) {
            notificationManager.postAuthorizationNotification(requestId)
        }
    }

    fun showTapPrompt(
        requestId: String,
        requester: String,
        action: RappAuthAction,
        onCancel: () -> Unit,
    ) {
        currentTapPrompt =
            RappCardTapPrompt(
                requestId = requestId,
                requester = requester,
                action = action,
                onCancel = {
                    currentTapPrompt = null
                    onCancel()
                },
            )
        if (!isForeground) {
            notificationManager.postAuthorizationNotification(requestId)
        }
    }

    fun dismissTapPrompt(requestId: String? = null) {
        if (requestId == null || currentTapPrompt?.requestId == requestId) {
            currentTapPrompt = null
            notificationManager.dismissNotification()
        }
    }

    fun cancel(requestId: String) {
        if (currentRequest?.requestId == requestId) {
            currentRequest?.onDenied?.invoke()
            currentRequest = null
            notificationManager.dismissNotification()
        }
        if (currentTapPrompt?.requestId == requestId) {
            currentTapPrompt?.onCancel?.invoke()
            currentTapPrompt = null
            notificationManager.dismissNotification()
        }
    }

    fun dismissAll() {
        currentRequest?.onDenied?.invoke()
        currentRequest = null
        currentTapPrompt?.onCancel?.invoke()
        currentTapPrompt = null
        notificationManager.dismissNotification()
    }
}
