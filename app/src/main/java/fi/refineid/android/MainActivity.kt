package fi.refineid.android

import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import fi.refineid.android.diagnostics.AppTrace
import fi.refineid.android.diagnostics.BuildDiagnostics
import fi.refineid.android.nfc.NfcReaderController
import fi.refineid.android.nfc.NfcReaderSnapshot
import fi.refineid.android.ui.MainScreen
import fi.refineid.android.ui.ReFineIdTheme
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.UsbReaderController
import fi.refineid.android.usb.UsbReaderSnapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel

class MainActivity : ComponentActivity() {
    private val activityScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var readerSnapshot by mutableStateOf(UsbReaderSnapshot())
    private var nfcSnapshot by mutableStateOf(NfcReaderSnapshot())
    private lateinit var readerController: UsbReaderController
    private lateinit var nfcReaderController: NfcReaderController
    private val readerStateListener: (UsbReaderSnapshot) -> Unit = { snapshot ->
        readerSnapshot = snapshot
    }
    private val nfcStateListener: (NfcReaderSnapshot) -> Unit = { snapshot ->
        nfcSnapshot = snapshot
    }
    private var rappPairingModel: fi.refineid.android.rapp.RappPairingModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        AppTrace.activityCreated()
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        if (!BuildDiagnostics.SCREEN_CAPTURE_ALLOWED) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        window.setHideOverlayWindows(true)
        window.decorView.importantForAutofill =
            View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        window.decorView.importantForContentCapture =
            View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS

        if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                REQUEST_CODE_POST_NOTIFICATIONS,
            )
        }

        readerController = (application as RefineIdApplication).readerController
        readerController.addStateListener(readerStateListener)
        nfcReaderController = (application as RefineIdApplication).nfcReaderController
        nfcReaderController.addStateListener(nfcStateListener)

        val rappInbox = (application as RefineIdApplication).rappAuthorizationInbox
        val model =
            fi.refineid.android.rapp.RappPairingModel(
                context = this,
                scope = activityScope,
            )
        rappPairingModel = model
        handlePairIntent(intent)

        setContent {
            ReFineIdTheme {
                MainScreen(
                    snapshot = readerSnapshot,
                    onRequestPermission = readerController::requestPermission,
                    onSelectUsbDevice = readerController::selectDevice,
                    onReaderConnect = readerController::connect,
                    browserCardService = readerController,
                    qualifiedCardService = readerController.qualifiedCardService,
                    nfcQualifiedCardService = nfcReaderController.qualifiedCardService,
                    cardManagementService = readerController.cardManagementService,
                    nfcCardManagementService = nfcReaderController.cardManagementService,
                    timestampAuthorityRepository =
                        (application as RefineIdApplication).timestampAuthorityStore,
                    hasNfc = nfcReaderController.hasNfc,
                    nfcSnapshot = nfcSnapshot,
                    onOpenNfcSettings = ::openNfcSettings,
                    onNfcConnect = nfcReaderController::connect,
                    onForgetPrimedCard = nfcReaderController::forgetPrimedCard,
                    nfcCardService = nfcReaderController.authenticationCardService,
                    onSignBeginTap = nfcReaderController.tapToSign::begin,
                    onSignEndTap = nfcReaderController.tapToSign::end,
                    pinCache = (application as RefineIdApplication).authenticationPinCache,
                    onPin1Changed = nfcReaderController::forgetPin1,
                    rappPairingModel = model,
                    rappInbox = rappInbox,
                    remoteCardModel = (application as RefineIdApplication).remoteCardModel,
                    onReadPhoto = { onResult ->
                        if (readerSnapshot.cardPresence == CardPresence.PRESENT) {
                            readerController.readPhoto(onResult)
                        } else {
                            nfcReaderController.readPhoto(onResult)
                        }
                    },
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        nfcReaderController.attach(this)
        readerController.refresh()
        (application as RefineIdApplication).remoteCardModel.refresh()
    }

    override fun onStop() {
        nfcReaderController.detach(this)
        super.onStop()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        AppTrace.activityReceivedIntent()
        readerController.refresh()
        handlePairIntent(intent)
        handleAuthPinIntent(intent)
    }

    private fun handlePairIntent(intent: Intent?) {
        val pairOffer =
            intent?.getStringExtra("REFINEID_PAIR_OFFER")
                ?: intent?.getStringExtra("pair_code")
        if (!pairOffer.isNullOrBlank()) {
            rappPairingModel?.connectWithCode(pairOffer)
        }
    }

    private fun handleAuthPinIntent(intent: Intent?) {
        val pin = intent?.getStringExtra("REFINEID_AUTH_PIN")
        if (!pin.isNullOrBlank()) {
            val app = application as? RefineIdApplication ?: return
            app.rappAuthorizationInbox.currentRequest
                ?.onApproved
                ?.invoke(pin)
        }
    }

    override fun onDestroy() {
        AppTrace.activityDestroyed()
        activityScope.cancel()
        nfcReaderController.removeStateListener(nfcStateListener)
        readerController.removeStateListener(readerStateListener)
        super.onDestroy()
    }

    private fun openNfcSettings() {
        try {
            startActivity(Intent(Settings.ACTION_NFC_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            AppTrace.nfcSettingsUnavailable()
        }
    }

    private companion object {
        private const val REQUEST_CODE_POST_NOTIFICATIONS = 101
    }
}
