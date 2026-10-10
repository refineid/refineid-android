package fi.refineid.android.rapp

import android.content.Context
import android.content.res.Resources
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.R
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
        /** Every document the approval signs, in signing order. */
        val documentNames: List<String>,
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
                notificationManager.postAuthorizationNotification(it.requestId, requestText(it))
            } ?: currentTapPrompt?.let {
                notificationManager.postAuthorizationNotification(it.requestId, tapPromptText(it), waitsOnCard = true)
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
            notificationManager.postAuthorizationNotification(requestId, requestText(req))
        }
    }

    fun askDocumentSign(
        requestId: String,
        requester: String,
        documentNames: List<String>,
        onApproved: (Pin2Submission) -> Unit,
        onDenied: () -> Unit,
    ) {
        val req =
            RappAuthRequest.DocumentSign(
                requestId = requestId,
                requester = requester,
                documentNames = documentNames,
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
            notificationManager.postAuthorizationNotification(requestId, requestText(req))
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
            currentTapPrompt?.let {
                notificationManager.postAuthorizationNotification(requestId, tapPromptText(it), waitsOnCard = true)
            }
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

    private fun requestText(request: RappAuthRequest): String = rappRequestText(context.resources, request)

    private fun tapPromptText(prompt: RappCardTapPrompt): String =
        context.getString(R.string.remote_card_needed, prompt.requester)

    fun dismissAll() {
        currentRequest?.onDenied?.invoke()
        currentRequest = null
        currentTapPrompt?.onCancel?.invoke()
        currentTapPrompt = null
        notificationManager.dismissNotification()
    }
}

/** What a request asks of the holder, independent of the card reader in use. */
internal fun rappRequestText(
    resources: Resources,
    request: RappAuthRequest,
): String =
    when (request) {
        is RappAuthRequest.BrowserAuth -> {
            resources.getString(R.string.remote_authentication_request, request.requester)
        }

        is RappAuthRequest.DocumentSign -> {
            val count = request.documentNames.size
            if (count > 1) {
                resources.getQuantityString(R.plurals.remote_signature_request_many, count, request.requester, count)
            } else {
                resources.getString(R.string.remote_signature_request, request.requester)
            }
        }
    }
