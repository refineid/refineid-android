@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android

import android.app.Application
import fi.refineid.android.browser.BundledIssuerCertificates
import fi.refineid.android.core.AuthenticationIssuerCertificateStore
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.keychain.AndroidExternalKeyCallerLabelResolver
import fi.refineid.android.keychain.ExternalKeyPinPromptBroker
import fi.refineid.android.keychain.ExternalKeyProviderRuntime
import fi.refineid.android.keychain.TransportSelectingCardSession
import fi.refineid.android.nfc.NfcReaderController
import fi.refineid.android.prime.PrimedCanStore
import fi.refineid.android.settings.TimestampAuthorityStore
import fi.refineid.android.usb.UsbReaderController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select

class ReFineIdApplication : Application() {
    internal lateinit var readerController: UsbReaderController
        private set
    internal lateinit var primedCanStore: PrimedCanStore
        private set
    internal lateinit var nfcReaderController: NfcReaderController
        private set
    internal val authenticationPinCache = AuthenticationPinCache()
    internal lateinit var pinPromptBroker: ExternalKeyPinPromptBroker
        private set
    internal lateinit var externalKeyProviderRuntime: ExternalKeyProviderRuntime
        private set
    internal lateinit var timestampAuthorityStore: TimestampAuthorityStore
        private set
    internal lateinit var rappAuthorizationInbox: fi.refineid.android.rapp.RappAuthorizationInbox
        private set
    internal lateinit var rappPairCatalog: fi.refineid.android.rapp.RappPairCatalog
        private set
    internal val rappVault by lazy {
        fi.refineid.android.rapp
            .AndroidRappVault(this)
    }
    internal lateinit var rappProxyDispatcher: fi.refineid.android.rapp.RappPhoneProxyDispatcher
        private set
    internal lateinit var remoteCardModel: fi.refineid.android.rapp.RemoteCardModel
        private set

    override fun onCreate() {
        super.onCreate()
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            fi.refineid.android.diagnostics.AppTrace
                .uncaughtException(thread, throwable)
            defaultHandler?.uncaughtException(thread, throwable)
        }
        fi.refineid.android.core.CardPhotoStore
            .initialize(java.io.File(filesDir, CARD_PHOTO_CACHE_DIRECTORY))
        fi.refineid.android.core.NativeVerification
            .installCscaAnchors(loadCscaAnchorAssets())
        readerController = UsbReaderController(this)
        val primedStore = PrimedCanStore(this)
        primedCanStore = primedStore
        try {
            primedStore.readPin1()?.let { storedPin ->
                authenticationPinCache.recordVerified(storedPin)
            }
            primedStore.read()?.let { storedCan ->
                fi.refineid.android.core.CanSessionStore
                    .remember(String(storedCan, Charsets.US_ASCII))
                storedCan.fill(0)
            }
        } catch (_: Exception) {
        }
        nfcReaderController =
            NfcReaderController(
                context = this,
                primedCanStore = primedStore,
                pinCache = authenticationPinCache,
            )
        timestampAuthorityStore = TimestampAuthorityStore(this)
        rappAuthorizationInbox =
            fi.refineid.android.rapp
                .RappAuthorizationInbox(this)
        rappPairCatalog =
            fi.refineid.android.rapp
                .RappPairCatalog(this)
        remoteCardModel =
            fi.refineid.android.rapp.RemoteCardModel(
                context = this,
                scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                vault = rappVault,
                catalog = rappPairCatalog,
            )
        pinPromptBroker =
            ExternalKeyPinPromptBroker(
                context = this,
                callerLabelResolver = AndroidExternalKeyCallerLabelResolver(packageManager),
                pinCache = authenticationPinCache,
            )
        externalKeyProviderRuntime =
            ExternalKeyProviderRuntime(
                cardSession =
                    TransportSelectingCardSession(
                        listOf(
                            readerController.externalKeyCardSession,
                            nfcReaderController.externalKeyCardSession,
                        ),
                    ),
                pinAuthorizer = pinPromptBroker,
                issuerCertificateSource =
                    AuthenticationIssuerCertificateStore(
                        BundledIssuerCertificates.load(this),
                    ),
            )
        readerController.start()
        rappProxyDispatcher = createRappProxyDispatcher(primedStore)
        val existingPairs = rappPairCatalog.listPairs()
        if (BuildConfig.DEBUG) {
            android.util.Log.i("APPLICATION", "existingPairs count=${existingPairs.size}")
        }
        if (existingPairs.isNotEmpty()) {
            val newestPair = existingPairs.maxByOrNull { it.createdAtMs } ?: existingPairs.first()
            val pairIdBytes =
                newestPair.pairIdHex
                    .chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
            try {
                val record = uniffi.refineid_rapp.RappPairRecord.loadFromVault(pairIdBytes, rappVault)
                if (record.metadata().role == uniffi.refineid_rapp.RappEndpointRole.PROXY) {
                    val token = record.metadata().rendezvousToken
                    val rendezvousName =
                        fi.refineid.android.rapp.StreamRendezvousName
                            .name(sharingValue = token)
                    android.util.Log.i("APPLICATION", "startListening on rendezvous $rendezvousName")
                    rappProxyDispatcher.startListening(rendezvousName, record, rappVault)
                } else {
                    android.util.Log.i("APPLICATION", "refreshing remote card model as requester")
                    remoteCardModel.refresh()
                }
            } catch (e: Exception) {
                android.util.Log.e("APPLICATION", "loadFromVault failed", e)
            }
        }
    }

    override fun onTerminate() {
        rappProxyDispatcher.close()
        externalKeyProviderRuntime.close()
        nfcReaderController.stop()
        readerController.stop()
        super.onTerminate()
    }

    private fun createRappProxyDispatcher(
        primedStore: PrimedCanStore?,
    ): fi.refineid.android.rapp.RappPhoneProxyDispatcher =
        fi.refineid.android.rapp.RappPhoneProxyDispatcher(
            context = this,
            scope = CoroutineScope(Dispatchers.Default),
            inbox = rappAuthorizationInbox,
            pinCache = authenticationPinCache,
            primedCanStore = primedStore,
            authCardService = {
                if (readerController.isCardReady) {
                    readerController
                } else {
                    nfcReaderController.authenticationCardService
                }
            },
            qualifiedCardService = {
                if (readerController.isCardReady) {
                    readerController.qualifiedCardService
                } else {
                    nfcReaderController.qualifiedCardService
                }
            },
            isCardReady = {
                readerController.isCardReady || nfcReaderController.isCardReady
            },
            awaitCardReady = {
                if (readerController.isCardReady || nfcReaderController.isCardReady) {
                    true
                } else {
                    coroutineScope {
                        val usbWait = async { readerController.awaitCardReady() }
                        val nfcWait = async { nfcReaderController.awaitCardReady() }
                        select {
                            usbWait.onAwait { ready ->
                                nfcWait.cancel()
                                ready
                            }
                            nfcWait.onAwait { ready ->
                                usbWait.cancel()
                                ready
                            }
                        }
                    }
                }
            },
        )

    // The CSCA trust anchors that close passive authentication's
    // DSC-to-CSCA hop. One DER certificate per file, grouped by issuing
    // state (csca/fi, later csca/ee); anchors ship with the app because
    // a card can never vouch for itself.
    private fun loadCscaAnchorAssets(): List<ByteArray> {
        val anchors = mutableListOf<ByteArray>()

        fun walk(path: String) {
            val children =
                try {
                    assets.list(path).orEmpty()
                } catch (_: java.io.IOException) {
                    return
                }
            if (children.isEmpty()) {
                try {
                    anchors.add(assets.open(path).use { stream -> stream.readBytes() })
                } catch (_: java.io.IOException) {
                    // A missing or unreadable anchor file surfaces as an
                    // unverified read, never as a crash.
                }
            } else {
                for (child in children) {
                    walk("$path/$child")
                }
            }
        }
        walk(CSCA_ANCHOR_ASSET_DIRECTORY)
        return anchors
    }

    private companion object {
        const val CARD_PHOTO_CACHE_DIRECTORY = "card-photos"
        const val CSCA_ANCHOR_ASSET_DIRECTORY = "csca"
    }
}
