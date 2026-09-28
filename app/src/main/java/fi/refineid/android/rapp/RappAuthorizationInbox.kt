package fi.refineid.android.rapp

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.core.Pin2Submission

internal enum class RappAuthAction {
    BROWSER_AUTH,
    DOCUMENT_SIGN,
}

internal sealed interface RappAuthRequest {
    val requestId: String
    val requester: String
    val action: RappAuthAction
    val onDenied: () -> Unit

    data class BrowserAuth(
        override val requestId: String,
        override val requester: String,
        val onApproved: (Pin1Submission) -> Unit,
        override val onDenied: () -> Unit,
    ) : RappAuthRequest {
        override val action: RappAuthAction get() = RappAuthAction.BROWSER_AUTH
    }

    data class DocumentSign(
        override val requestId: String,
        override val requester: String,
        val onApproved: (Pin2Submission) -> Unit,
        override val onDenied: () -> Unit,
    ) : RappAuthRequest {
        override val action: RappAuthAction get() = RappAuthAction.DOCUMENT_SIGN
    }
}

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

    fun askBrowserAuth(
        requestId: String,
        requester: String,
        onApproved: (Pin1Submission) -> Unit,
        onDenied: () -> Unit,
    ) {
        val req =
            RappAuthRequest.BrowserAuth(
                requestId = requestId,
                requester = requester,
                onApproved = { pin1 ->
                    notificationManager.dismissNotification()
                    currentRequest = null
                    onApproved(pin1)
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

    fun askDocumentSign(
        requestId: String,
        requester: String,
        onApproved: (Pin2Submission) -> Unit,
        onDenied: () -> Unit,
    ) {
        val req =
            RappAuthRequest.DocumentSign(
                requestId = requestId,
                requester = requester,
                onApproved = { pin2 ->
                    notificationManager.dismissNotification()
                    currentRequest = null
                    onApproved(pin2)
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

    fun dismiss(requestId: String) {
        if (currentRequest?.requestId == requestId) {
            currentRequest = null
            notificationManager.dismissNotification()
        }
        if (currentTapPrompt?.requestId == requestId) {
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
