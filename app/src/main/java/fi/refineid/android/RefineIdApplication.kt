@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android

import android.app.Application
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.NativeCardCa
import fi.refineid.android.keychain.AndroidExternalKeyCallerLabelResolver
import fi.refineid.android.keychain.ExternalKeyPinPromptBroker
import fi.refineid.android.keychain.ExternalKeyProviderRuntime
import fi.refineid.android.keychain.TransportSelectingCardSession
import fi.refineid.android.nfc.NfcReaderController
import fi.refineid.android.prime.PrimedCanStore
import fi.refineid.android.settings.TimestampAuthorityStore
import fi.refineid.android.trust.CaCertificateStore
import fi.refineid.android.usb.CardPresence
import fi.refineid.android.usb.ReaderCardPresenceWatch
import fi.refineid.android.usb.UsbReaderController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select

class RefineIdApplication : Application() {
    internal lateinit var readerController: UsbReaderController
        private set
    internal lateinit var primedCanStore: PrimedCanStore
        private set
    internal lateinit var nfcReaderController: NfcReaderController
        private set
    internal lateinit var caCertificateStore: CaCertificateStore
        private set
    internal val authenticationPinCache = AuthenticationPinCache()
    internal val authenticationGeneration =
        java.util.concurrent.atomic
            .AtomicInteger()
    internal val authenticationCustodyLock = Any()

    /** Published by whichever thread observed the rejection; readers join it on Main. */
    @Volatile
    internal var authenticationInvalidation: kotlinx.coroutines.Job? = null
        private set
    private val authenticationScope = CoroutineScope(Dispatchers.IO + kotlinx.coroutines.SupervisorJob())

    internal fun retainAuthenticationPin(
        pin: ByteArray,
        expectedGeneration: Long,
    ): Boolean {
        try {
            synchronized(authenticationCustodyLock) {
                if (authenticationPinCache.generation != expectedGeneration) return false
                if (primedCanStore.isPrimed()) primedCanStore.writePin1(pin.copyOf())
                return authenticationPinCache.recordVerified(pin.copyOf(), expectedGeneration)
            }
        } finally {
            pin.fill(0)
        }
    }

    /**
     * Forgets the PIN1 accepted while a card sat in the USB reader, once
     * that card is removed or the reader disconnects. A primed contactless
     * identity keeps the PIN1 its holder chose to store with it.
     */
    private fun forgetReaderPin1() {
        synchronized(authenticationCustodyLock) {
            authenticationPinCache.clear()
        }
        authenticationScope.launch {
            if (!primedCanStore.isPrimed()) return@launch
            val stored = primedCanStore.readPin1() ?: return@launch
            synchronized(authenticationCustodyLock) {
                authenticationPinCache.recordVerified(stored)
            }
        }
    }

    internal fun invalidateAuthentication() {
        synchronized(authenticationCustodyLock) {
            authenticationGeneration.incrementAndGet()
            authenticationPinCache.clear()
        }
        fi.refineid.android.core.CanSessionStore
            .drop()
        authenticationInvalidation =
            authenticationScope.launch {
                val nfcCleared = kotlinx.coroutines.CompletableDeferred<Unit>()
                kotlinx.coroutines.withContext(Dispatchers.Main) {
                    nfcReaderController.forgetPrimedCard { nfcCleared.complete(Unit) }
                    readerController.invalidateAuthenticationSession()
                    rappProxyDispatcher.disconnectClient()
                }
                nfcCleared.await()
                synchronized(authenticationCustodyLock) {
                    fi.refineid.android.core.CardPhotoStore
                        .clear()
                }
            }
    }

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
        val caStore = CaCertificateStore(this)
        caStore.load()
        caCertificateStore = caStore
        val rootCa = caStore.rootCaDer
        val intermediateCa = caStore.intermediateCaDer
        if (rootCa != null || intermediateCa != null) {
            NativeCardCa.setCachedCaCertificates(rootCa, intermediateCa)
        }
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
        registerActivityLifecycleCallbacks(
            object : ActivityLifecycleCallbacks {
                private var resumedActivities = 0

                override fun onActivityResumed(activity: android.app.Activity) {
                    resumedActivities++
                    rappAuthorizationInbox.updateForeground(resumedActivities > 0)
                }

                override fun onActivityPaused(activity: android.app.Activity) {
                    resumedActivities = (resumedActivities - 1).coerceAtLeast(0)
                    rappAuthorizationInbox.updateForeground(resumedActivities > 0)
                }

                override fun onActivityCreated(
                    activity: android.app.Activity,
                    savedInstanceState: android.os.Bundle?,
                ) {
                    // Unused lifecycle event.
                }

                override fun onActivityStarted(activity: android.app.Activity) {
                    // Unused lifecycle event.
                }

                override fun onActivityStopped(activity: android.app.Activity) {
                    // Unused lifecycle event.
                }

                override fun onActivitySaveInstanceState(
                    activity: android.app.Activity,
                    outState: android.os.Bundle,
                ) {
                    // Unused lifecycle event.
                }

                override fun onActivityDestroyed(activity: android.app.Activity) {
                    // Unused lifecycle event.
                }
            },
        )
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
                issuerCertificateSource = caStore,
            )
        val readerCardPresence = ReaderCardPresenceWatch()
        readerController.addStateListener { snapshot ->
            if (readerCardPresence.presenceEnded(snapshot)) forgetReaderPin1()
        }
        readerController.start()
        rappProxyDispatcher = createRappProxyDispatcher(primedStore)
        startRappProxyListening()
    }

    internal fun startRappProxyListening() {
        val settings =
            fi.refineid.android.rapp
                .RappSettings(this)
        if (!settings.isCardRemoteAccessEnabled) {
            return
        }
        val existingPairs = rappPairCatalog.listPairs()
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
                    rappProxyDispatcher.startListening(rappVault)
                } else {
                    remoteCardModel.refresh()
                }
            } catch (_: Exception) {
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
            onAuthenticationRejected = ::invalidateAuthentication,
            onAuthenticationVerified = ::retainAuthenticationPin,
            activeAuthCertDer = {
                if (readerController.snapshot.cardPresence == CardPresence.PRESENT) {
                    null
                } else {
                    nfcReaderController.currentAuthenticationCertificateDer
                }
            },
            authCardService = {
                if (readerController.snapshot.cardPresence == CardPresence.PRESENT) {
                    readerController
                } else {
                    nfcReaderController.authenticationCardService
                }
            },
            qualifiedCardService = {
                if (readerController.snapshot.cardPresence == CardPresence.PRESENT) {
                    readerController.qualifiedCardService
                } else {
                    nfcReaderController.qualifiedCardService
                }
            },
            isCardReady = {
                if (readerController.snapshot.cardPresence == CardPresence.PRESENT) {
                    readerController.isCardReady
                } else {
                    nfcReaderController.isCardReady
                }
            },
            awaitCardReady = {
                if (readerController.snapshot.cardPresence == CardPresence.PRESENT) {
                    readerController.awaitCardReady()
                } else if (nfcReaderController.isCardReady) {
                    true
                } else {
                    coroutineScope {
                        val usbWait = async { readerController.awaitCardReady() }
                        val nfcWait = async { nfcReaderController.awaitCardReady() }
                        // Either reader may supply the card; one that gives up
                        // leaves the wait to the other.
                        val usbFirst =
                            select {
                                usbWait.onAwait { true }
                                nfcWait.onAwait { false }
                            }
                        val usbReady = if (usbFirst) usbWait.await() else false
                        if (usbReady) {
                            nfcWait.cancel()
                            true
                        } else {
                            val nfcReady = nfcWait.await()
                            if (nfcReady) {
                                usbWait.cancel()
                                true
                            } else if (usbFirst) {
                                readerController.snapshot.cardPresence == CardPresence.PRESENT &&
                                    readerController.awaitCardReady()
                            } else {
                                usbWait.await()
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
