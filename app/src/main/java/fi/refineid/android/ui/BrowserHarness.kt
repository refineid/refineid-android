package fi.refineid.android.ui

import android.annotation.SuppressLint
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.webkit.ClientCertRequest
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.material3.Button
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SecureTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.net.toUri
import fi.refineid.android.R
import fi.refineid.android.browser.BrowserClientCertificateMatcher
import fi.refineid.android.browser.BrowserClientCertificateOutcome
import fi.refineid.android.browser.BrowserClientIdentity
import fi.refineid.android.browser.BrowserPinCoordinator
import fi.refineid.android.browser.BrowserPinRequest
import fi.refineid.android.browser.BrowserSignatureStatus
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.browser.ReFineIdCardProviderRegistration
import fi.refineid.android.core.AuthenticationCardService
import fi.refineid.android.core.CanSubmission
import fi.refineid.android.core.Pin1Submission
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.diagnostics.BuildDiagnostics
import fi.refineid.android.nfc.NfcReaderStatus
import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicBoolean

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
internal fun BrowserHarness(
    cardService: AuthenticationCardService?,
    pinCache: fi.refineid.android.core.AuthenticationPinCache? = null,
    nfcStatus: NfcReaderStatus? = null,
    nfcPrimed: Boolean = false,
    enabled: Boolean = true,
    onNfcConnect: (CanSubmission?, Pin1Submission) -> Unit = { _, _ -> },
    onWrongPin: (() -> Unit)? = null,
    launcher: (@Composable (onOpen: () -> Unit) -> Unit)? = null,
) {
    if (cardService == null) {
        return
    }
    var isOpen by remember { mutableStateOf(false) }
    val open = {
        if (enabled) {
            AppTrace.browserOpened()
            isOpen = true
        }
    }
    if (launcher != null) {
        launcher(open)
    } else {
        Button(
            onClick = open,
            enabled = enabled,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .testTag(UiAutomationIds.BROWSER_ACTION),
        ) {
            Text(stringResource(R.string.browser))
        }
    }
    if (isOpen) {
        BrowserDialog(
            cardService = cardService,
            pinCache = pinCache,
            nfcStatus = nfcStatus,
            nfcPrimed = nfcPrimed,
            onNfcConnect = onNfcConnect,
            onWrongPin = onWrongPin,
            onClose = {
                AppTrace.browserClosed()
                isOpen = false
            },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
// General sites need JavaScript; this browser exists only in debug
// builds and every signature stays behind the holder's PIN.
@SuppressLint("SetJavaScriptEnabled")
private fun BrowserDialog(
    cardService: AuthenticationCardService,
    pinCache: fi.refineid.android.core.AuthenticationPinCache?,
    nfcStatus: NfcReaderStatus?,
    nfcPrimed: Boolean,
    onNfcConnect: (CanSubmission?, Pin1Submission) -> Unit,
    onWrongPin: (() -> Unit)? = null,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val isActive = remember { AtomicBoolean(true) }
    var pinRequest by remember { mutableStateOf<BrowserPinRequest?>(null) }
    var unlockRequest by remember { mutableStateOf<BrowserCardUnlockRequest?>(null) }
    var unlockWaiting by remember { mutableStateOf(false) }
    var signatureStatus by remember { mutableStateOf(BrowserSignatureStatus.IDLE) }
    LaunchedEffect(signatureStatus) {
        if (signatureStatus == BrowserSignatureStatus.WRONG_PIN ||
            signatureStatus == BrowserSignatureStatus.PIN_LOCKED
        ) {
            onWrongPin?.invoke()
            onClose()
        }
    }
    // Once the holder unlocked and the session opened, resolve the held
    // certificate request; the handshake then proceeds with the card.
    LaunchedEffect(nfcStatus, unlockRequest) {
        if (unlockRequest != null && nfcStatus == NfcReaderStatus.CARD_READY) {
            val held = unlockRequest
            unlockRequest = null
            unlockWaiting = false
            held?.retry?.invoke()
        }
    }
    val coordinator =
        remember(cardService) {
            BrowserPinCoordinator(
                cardService = cardService,
                pinCache = pinCache,
                dispatchToUi = { action ->
                    if (Looper.myLooper() == Looper.getMainLooper()) {
                        action()
                    } else {
                        mainHandler.post {
                            if (isActive.get()) {
                                action()
                            }
                        }
                    }
                },
                onPromptChanged = { request -> pinRequest = request },
                onStatusChanged = { status ->
                    signatureStatus = status
                    AppTrace.browserSignatureStatus(status)
                },
            )
        }
    val issuerCandidates =
        remember(context) {
            runCatching { BundledIssuerCertificates.load(context) }.getOrNull()
        }
    val providerReady = remember { ReFineIdCardProviderRegistration.install() }
    LaunchedEffect(providerReady, issuerCandidates) {
        AppTrace.browserInitialized(
            providerReady = providerReady,
            issuerCount = issuerCandidates?.size ?: NO_ISSUER_CERTIFICATES,
        )
    }
    val webViewClient =
        remember(cardService, coordinator, issuerCandidates, providerReady, nfcStatus != null) {
            if (issuerCandidates == null || !providerReady) {
                null
            } else {
                ReFineIdWebViewClient(
                    cardService = cardService,
                    issuerCandidates = issuerCandidates,
                    signatureOperation = coordinator,
                    onCardNeeded =
                        if (nfcStatus == null) {
                            null
                        } else {
                            { request ->
                                if (isActive.get()) {
                                    unlockRequest = request
                                    unlockWaiting = false
                                } else {
                                    request.giveUp()
                                }
                            }
                        },
                )
            }
        }

    DisposableEffect(coordinator, webViewClient) {
        onDispose {
            isActive.set(false)
            webViewClient?.close()
            coordinator.close()
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties =
            DialogProperties(
                dismissOnClickOutside = false,
                usePlatformDefaultWidth = false,
                decorFitsSystemWindows = false,
                securePolicy = SecureFlagPolicy.SecureOn,
            ),
    ) {
        BrowserDialogContent(
            webViewClient = webViewClient,
            signatureStatus = signatureStatus,
        )
    }
    pinRequest?.let { request ->
        BrowserPinDialog(request)
    }
    unlockRequest?.let { request ->
        BrowserCardUnlockDialog(
            status = nfcStatus,
            primed = nfcPrimed,
            isWaiting = unlockWaiting,
            onUnlock = { can, pin1 ->
                unlockWaiting = true
                onNfcConnect(can, pin1)
            },
            onCancel = {
                unlockRequest = null
                unlockWaiting = false
                request.giveUp()
            },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserDialogContent(
    webViewClient: WebViewClient?,
    signatureStatus: BrowserSignatureStatus,
) {
    Surface(
        modifier =
            Modifier
                .fillMaxSize()
                .semantics { testTagsAsResourceId = true },
        color = MaterialTheme.colorScheme.background,
    ) {
        // The page owns the whole screen; the browsing controls float
        // over its bottom edge, the way the reference platform's
        // browser keeps its bar over the content.
        Box(modifier = Modifier.fillMaxSize()) {
            var urlText by remember { mutableStateOf("https://card.refineid.fi") }
            var liveWebView by remember { mutableStateOf<WebView?>(null) }
            val navigate = {
                val destination = normalizeHttpsUrl(urlText)
                if (destination != null) {
                    urlText = destination
                    liveWebView?.loadUrl(destination)
                } else {
                    AppTrace.browserNavigationBlocked()
                }
                Unit
            }

            LaunchedEffect(liveWebView) {
                val current = liveWebView
                if (current != null && urlText.isNotBlank()) {
                    normalizeHttpsUrl(urlText)?.let { current.loadUrl(it) }
                }
            }

            BrowserWebView(
                client = webViewClient,
                onWebViewCreated = { liveWebView = it },
                onWebViewReleased = { liveWebView = null },
                modifier = Modifier.fillMaxSize(),
            )

            BrowserControlsBar(
                urlText = urlText,
                signatureStatus = signatureStatus,
                onUrlChange = { urlText = it },
                onNavigate = navigate,
                onBack = { liveWebView?.takeIf { it.canGoBack() }?.goBack() },
                onForward = { liveWebView?.takeIf { it.canGoForward() }?.goForward() },
                onReload = { liveWebView?.reload() },
                modifier = Modifier.align(Alignment.BottomCenter),
            )
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserWebView(
    client: WebViewClient?,
    onWebViewCreated: (WebView) -> Unit,
    onWebViewReleased: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (client == null) {
        Box(modifier = modifier) {
            Text(
                text = stringResource(R.string.error),
                modifier = Modifier.align(Alignment.Center),
            )
        }
    } else {
        AndroidView(
            factory = { viewContext ->
                if ((viewContext.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    WebView.setWebContentsDebuggingEnabled(BuildDiagnostics.WEBVIEW_DEBUGGING_ENABLED)
                }
                WebView(viewContext).apply {
                    configureFullFeaturedBrowser()
                    this.webViewClient = client
                    webChromeClient = WebChromeClient()
                    onWebViewCreated(this)
                    WebView.clearClientCertPreferences {}
                }
            },
            modifier =
                modifier
                    .safeDrawingPadding()
                    .testTag(UiAutomationIds.BROWSER_VIEW),
            onRelease = { webView ->
                onWebViewReleased()
                webView.stopLoading()
                webView.webViewClient = WebViewClient()
                webView.destroy()
            },
        )
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserControlsBar(
    urlText: String,
    signatureStatus: BrowserSignatureStatus,
    onUrlChange: (String) -> Unit,
    onNavigate: () -> Unit,
    onBack: () -> Unit,
    onForward: () -> Unit,
    onReload: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier =
            modifier
                .fillMaxWidth()
                .safeDrawingPadding()
                .padding(
                    horizontal = FLOATING_BAR_HORIZONTAL_PADDING,
                    vertical = FLOATING_BAR_BOTTOM_PADDING,
                ),
        verticalArrangement = Arrangement.spacedBy(BROWSER_ITEM_SPACING),
    ) {
        BrowserStatus(signatureStatus)
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(FLOATING_BAR_CORNER_RADIUS),
            color =
                MaterialTheme.colorScheme.surface.copy(
                    alpha = FLOATING_BAR_ALPHA,
                ),
            shadowElevation = FLOATING_BAR_ELEVATION,
        ) {
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(FLOATING_BAR_INNER_PADDING),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(
                    onClick = onBack,
                    modifier = Modifier.testTag(UiAutomationIds.BROWSER_BACK_ACTION),
                ) {
                    Text(stringResource(R.string.browser_back))
                }
                IconButton(
                    onClick = onForward,
                    modifier = Modifier.testTag(UiAutomationIds.BROWSER_FORWARD_ACTION),
                ) {
                    Text(stringResource(R.string.browser_forward))
                }
                IconButton(
                    onClick = onReload,
                    modifier = Modifier.testTag(UiAutomationIds.BROWSER_RELOAD_ACTION),
                ) {
                    Text(stringResource(R.string.browser_reload))
                }
                OutlinedTextField(
                    value = urlText,
                    onValueChange = onUrlChange,
                    modifier =
                        Modifier
                            .weight(BROWSER_VIEW_WEIGHT)
                            .testTag(UiAutomationIds.BROWSER_URL_FIELD),
                    singleLine = true,
                    trailingIcon = {
                        IconButton(
                            onClick = onNavigate,
                            modifier = Modifier.testTag("BrowserGoAction"),
                        ) {
                            Text("Go")
                        }
                    },
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.Uri,
                            imeAction = ImeAction.Go,
                        ),
                    keyboardActions = KeyboardActions(onGo = { onNavigate() }),
                )
            }
        }
    }
}

/**
 * The reference flow's hold-and-unlock sheet: a site asked for the
 * card, so the holder presents it, enters the basic code — and the
 * access number when no card is saved — and the held handshake resumes.
 */
@Suppress("FunctionName", "ktlint:standard:function-naming", "LongMethod")
@Composable
private fun BrowserCardUnlockDialog(
    status: NfcReaderStatus?,
    primed: Boolean,
    isWaiting: Boolean,
    onUnlock: (CanSubmission?, Pin1Submission) -> Unit,
    onCancel: () -> Unit,
) {
    val initialCan = remember { fi.refineid.android.core.CanSessionStore.currentCan ?: "" }
    val canState = remember { TextFieldState(initialCan) }
    val pinState = remember { TextFieldState() }
    DisposableEffect(pinState) {
        onDispose {
            pinState.clearText()
        }
    }
    val cardEntryReady =
        status != NfcReaderStatus.TURNED_OFF &&
            status != NfcReaderStatus.NOT_AVAILABLE &&
            status != NfcReaderStatus.CARD_NOT_SUPPORTED
    val hasRememberedCan = primed || fi.refineid.android.core.CanSessionStore.hasCan
    val canReady = hasRememberedCan || CanSubmission.isComplete(canState.text)
    val pinReady = Pin1Submission.isComplete(pinState.text)
    val submit = {
        if (cardEntryReady && canReady && pinReady && !isWaiting) {
            val can =
                when {
                    primed -> {
                        null
                    }

                    CanSubmission.isComplete(canState.text) -> {
                        fi.refineid.android.core.CanSessionStore
                            .remember(canState.text)
                        CanSubmission.from(canState.text)
                    }

                    fi.refineid.android.core.CanSessionStore.hasCan -> {
                        fi.refineid.android.core.CanSessionStore.currentCan
                            ?.let { CanSubmission.from(it) }
                    }

                    else -> {
                        null
                    }
                }
            val pin1 = Pin1Submission.from(pinState.text)
            pinState.clearText()
            onUnlock(can, pin1)
        }
        Unit
    }
    Dialog(onDismissRequest = onCancel) {
        Surface(
            modifier = Modifier.semantics { testTagsAsResourceId = true },
            shape = MaterialTheme.shapes.extraLarge,
            color = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                modifier = Modifier.padding(UNLOCK_DIALOG_PADDING),
                verticalArrangement = Arrangement.spacedBy(UNLOCK_DIALOG_SPACING),
            ) {
                Text(
                    text = stringResource(R.string.sign_in),
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = stringResource(R.string.hold_card),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (!primed) {
                    SecureTextField(
                        state = canState,
                        modifier =
                            Modifier
                                .fillMaxWidth()
                                .testTag(UiAutomationIds.BROWSER_UNLOCK_CAN_FIELD),
                        enabled = !isWaiting,
                        label = { Text(stringResource(R.string.can)) },
                        inputTransformation = CanInputTransformation,
                        textObfuscationMode = TextObfuscationMode.Visible,
                        keyboardOptions =
                            KeyboardOptions(
                                autoCorrectEnabled = false,
                                keyboardType = KeyboardType.NumberPassword,
                                imeAction = ImeAction.Next,
                            ),
                    )
                }
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.BROWSER_UNLOCK_PIN1_FIELD),
                    enabled = !isWaiting,
                    label = { Text(stringResource(R.string.pin1)) },
                    inputTransformation = Pin1InputTransformation,
                    textObfuscationMode = TextObfuscationMode.Hidden,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(UNLOCK_DIALOG_SPACING),
                ) {
                    Button(
                        onClick = onCancel,
                        modifier =
                            Modifier
                                .weight(UNLOCK_BUTTON_WEIGHT)
                                .testTag(UiAutomationIds.BROWSER_UNLOCK_CANCEL_ACTION),
                    ) {
                        Text(stringResource(R.string.cancel))
                    }
                    Button(
                        onClick = submit,
                        modifier =
                            Modifier
                                .weight(UNLOCK_BUTTON_WEIGHT)
                                .testTag(UiAutomationIds.BROWSER_UNLOCK_ACTION),
                        enabled = cardEntryReady && canReady && pinReady && !isWaiting,
                    ) {
                        Text(stringResource(R.string.unlock))
                    }
                }
                if (isWaiting || !cardEntryReady) {
                    Text(
                        text = stringResource(R.string.checking),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserPinDialog(request: BrowserPinRequest) {
    val pinState = remember(request) { TextFieldState() }
    var wasSubmitted by remember(request) { mutableStateOf(false) }
    DisposableEffect(pinState) {
        onDispose(pinState::clearText)
    }
    val submit = {
        if (!wasSubmitted && Pin1Submission.isComplete(pinState.text)) {
            val submission = Pin1Submission.from(pinState.text)
            pinState.clearText()
            wasSubmitted = true
            request.submit(submission)
        }
        Unit
    }

    Dialog(
        onDismissRequest = request::cancel,
        properties =
            DialogProperties(
                dismissOnClickOutside = false,
                securePolicy = SecureFlagPolicy.SecureOn,
            ),
    ) {
        Surface(
            modifier = Modifier.semantics { testTagsAsResourceId = true },
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surface,
        ) {
            Column(
                modifier = Modifier.padding(PIN_DIALOG_PADDING),
                verticalArrangement = Arrangement.spacedBy(PIN_DIALOG_ITEM_SPACING),
            ) {
                Text(
                    text = stringResource(R.string.pin1),
                    style = MaterialTheme.typography.titleLarge,
                )
                SecureTextField(
                    state = pinState,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.BROWSER_PIN1_FIELD),
                    enabled = !wasSubmitted,
                    inputTransformation = Pin1InputTransformation,
                    textObfuscationMode = TextObfuscationMode.Hidden,
                    keyboardOptions =
                        KeyboardOptions(
                            autoCorrectEnabled = false,
                            keyboardType = KeyboardType.NumberPassword,
                            imeAction = ImeAction.Done,
                        ),
                )
                Button(
                    onClick = submit,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .testTag(UiAutomationIds.BROWSER_SIGN_ACTION),
                    enabled = !wasSubmitted && Pin1Submission.isComplete(pinState.text),
                ) {
                    Text(stringResource(R.string.sign))
                }
            }
        }
    }
}

@Suppress("FunctionName", "ktlint:standard:function-naming")
@Composable
private fun BrowserStatus(status: BrowserSignatureStatus) {
    // The page is its own success feedback; only surface a failure that
    // explains why a login did not happen.
    val text =
        when (status) {
            BrowserSignatureStatus.IDLE,
            BrowserSignatureStatus.PIN_REQUIRED,
            BrowserSignatureStatus.CANCELLED,
            BrowserSignatureStatus.SIGNING,
            BrowserSignatureStatus.SUCCEEDED,
            -> null

            BrowserSignatureStatus.WRONG_PIN -> stringResource(R.string.wrong_pin)

            BrowserSignatureStatus.PIN_LOCKED -> stringResource(R.string.pin_locked)

            BrowserSignatureStatus.REFUSED -> stringResource(R.string.unavailable)

            BrowserSignatureStatus.TIMED_OUT,
            BrowserSignatureStatus.INTERRUPTED,
            BrowserSignatureStatus.ERROR,
            -> stringResource(R.string.error)
        }
    if (text != null) {
        Text(
            text = text,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

/** One held client-certificate request waiting for the card to unlock. */
internal class BrowserCardUnlockRequest(
    val retry: () -> Unit,
    val giveUp: () -> Unit,
)

private class ReFineIdWebViewClient(
    private val cardService: AuthenticationCardService,
    private val issuerCandidates: List<X509Certificate>,
    private val signatureOperation: BrowserPinCoordinator,
    private val onCardNeeded: ((BrowserCardUnlockRequest) -> Unit)? = null,
) : WebViewClient(),
    AutoCloseable {
    private val isClosed = AtomicBoolean(false)

    override fun shouldOverrideUrlLoading(
        view: WebView,
        request: WebResourceRequest,
    ): Boolean {
        val isBlocked = !request.url.isHttps()
        if (isBlocked) {
            AppTrace.browserNavigationBlocked()
        }
        return isBlocked
    }

    override fun onReceivedSslError(
        view: WebView,
        handler: SslErrorHandler,
        error: android.net.http.SslError,
    ) {
        // The WebView trust store plus the debug network security config (which adds the
        // public Telia Root CA v2 that DVV's Suomi.fi identification hosts chain to)
        // validate legitimate chains; anything the WebView still rejects is logged with
        // its host and issuer, then refused.
        val host = runCatching { Uri.parse(error.url).host }.getOrNull().orEmpty()
        AppTrace.browserTlsError(
            host = host,
            primaryError = error.primaryError,
            issuedBy =
                error.certificate.issuedBy.dName
                    .orEmpty(),
            issuedTo =
                error.certificate.issuedTo.dName
                    .orEmpty(),
        )
        handler.cancel()
    }

    override fun onReceivedError(
        view: WebView,
        request: WebResourceRequest,
        error: WebResourceError,
    ) = Unit

    // Any HTTPS origin may ask; the holder's PIN gates every signature.
    override fun onReceivedClientCertRequest(
        view: WebView,
        request: ClientCertRequest,
    ) {
        AppTrace.browserClientCertificateRequested(
            originAllowed = true,
            keyTypeCount = request.keyTypes?.size ?: NO_KEY_TYPES,
            issuerCount = request.principals?.size ?: NO_ISSUER_HINTS,
        )
        resolveClientCertificate(request, allowUnlock = true)
    }

    private fun resolveClientCertificate(
        request: ClientCertRequest,
        allowUnlock: Boolean,
    ) {
        if (isClosed.get()) {
            AppTrace.browserClientCertificateCompleted(BrowserClientCertificateOutcome.CLOSED)
            request.cancel()
            return
        }
        cardService.requestAuthenticationCertificate { ownedLeaf ->
            if (ownedLeaf == null) {
                // The card is not unlocked. Instead of failing the
                // handshake, hold the request and ask the holder to
                // present and unlock the card, then resolve once more.
                val unlockPath = onCardNeeded
                if (allowUnlock && unlockPath != null && !isClosed.get()) {
                    AppTrace.browserClientCertificateUnlockRequested()
                    unlockPath(
                        BrowserCardUnlockRequest(
                            retry = { resolveClientCertificate(request, allowUnlock = false) },
                            giveUp = {
                                AppTrace.browserClientCertificateCompleted(
                                    BrowserClientCertificateOutcome.CARD_UNAVAILABLE,
                                )
                                request.cancel()
                            },
                        ),
                    )
                    return@requestAuthenticationCertificate
                }
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.CARD_UNAVAILABLE,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            val identity =
                BrowserClientIdentity.create(
                    ownedLeaf = ownedLeaf,
                    issuerCandidates = issuerCandidates,
                    operation = signatureOperation,
                )
            if (isClosed.get()) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.CLOSED,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            if (identity == null) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.IDENTITY_INVALID,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            if (
                !BrowserClientCertificateMatcher.accepts(
                    identity = identity,
                    keyTypes = request.keyTypes,
                    principals = request.principals,
                )
            ) {
                AppTrace.browserClientCertificateCompleted(
                    BrowserClientCertificateOutcome.HINT_MISMATCH,
                )
                request.cancel()
                return@requestAuthenticationCertificate
            }
            AppTrace.browserClientCertificateCompleted(
                BrowserClientCertificateOutcome.PROCEEDED,
            )
            request.proceed(
                identity.privateKey,
                identity.copyCertificateChain(),
            )
        }
    }

    override fun close() {
        isClosed.set(true)
    }
}

// A login browser must behave like a real one: scripts, storage,
// cross-site cookies for identity brokers, a usable viewport, and media.
// Local file and content access stay off, and mixed content is refused.
@SuppressLint("SetJavaScriptEnabled")
private fun WebView.configureFullFeaturedBrowser() {
    settings.apply {
        javaScriptEnabled = true
        domStorageEnabled = true
        javaScriptCanOpenWindowsAutomatically = true
        loadWithOverviewMode = true
        useWideViewPort = true
        builtInZoomControls = true
        displayZoomControls = false
        mediaPlaybackRequiresUserGesture = false
        allowFileAccess = false
        allowContentAccess = false
        mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
    }
    CookieManager.getInstance().apply {
        setAcceptCookie(true)
        setAcceptThirdPartyCookies(this@configureFullFeaturedBrowser, true)
    }
}

private fun Uri.isHttps(): Boolean = scheme.equals(HTTPS_SCHEME, ignoreCase = true)

/** Accept holder input as an HTTPS destination, or refuse it. */
private fun normalizeHttpsUrl(input: String): String? {
    val candidate = input.trim()
    if (candidate.isEmpty()) {
        return null
    }
    val withScheme =
        if (candidate.contains(SCHEME_SEPARATOR)) {
            candidate
        } else {
            HTTPS_SCHEME + SCHEME_SEPARATOR + candidate
        }
    val uri = withScheme.toUri()
    return withScheme.takeIf { uri.isHttps() && !uri.host.isNullOrEmpty() }
}

private const val HTTPS_SCHEME = "https"
private const val SCHEME_SEPARATOR = "://"
private val BROWSER_ITEM_SPACING = 12.dp
private val FLOATING_BAR_HORIZONTAL_PADDING = 12.dp
private val FLOATING_BAR_BOTTOM_PADDING = 8.dp
private val FLOATING_BAR_CORNER_RADIUS = 28.dp
private val FLOATING_BAR_INNER_PADDING = 4.dp
private val FLOATING_BAR_ELEVATION = 6.dp
private const val FLOATING_BAR_ALPHA = 0.95f
private val UNLOCK_DIALOG_PADDING = 24.dp
private val UNLOCK_DIALOG_SPACING = 14.dp
private const val UNLOCK_BUTTON_WEIGHT = 1f
private val PIN_DIALOG_PADDING = 24.dp
private val PIN_DIALOG_ITEM_SPACING = 16.dp
private const val BROWSER_VIEW_WEIGHT = 1F
private const val NO_ISSUER_CERTIFICATES = 0
private const val NO_KEY_TYPES = 0
private const val NO_ISSUER_HINTS = 0
