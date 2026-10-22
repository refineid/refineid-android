@file:Suppress("TooGenericExceptionCaught")

package fi.refineid.android

import android.app.Application
import fi.refineid.android.core.AuthenticationCardIdentity
import fi.refineid.android.core.AuthenticationPinCache
import fi.refineid.android.core.NativeCardCa
import fi.refineid.android.core.Pin1Retention
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
        retention: Pin1Retention,
        expectedGeneration: Long,
    ): Boolean {
        try {
            synchronized(authenticationCustodyLock) {
                if (authenticationPinCache.generation != expectedGeneration) return false
                return authenticationPinCache.recordVerified(pin.copyOf(), retention, expectedGeneration)
            }
        } finally {
            pin.fill(0)
        }
    }

    /**
     * Forgets the held PIN1 once the card in the USB reader is removed or the
     * reader disconnects (RAPP v26.10.22 section 11 item 2).
     */
    private fun forgetReaderPin1() {
        synchronized(authenticationCustodyLock) {
            authenticationPinCache.clear()
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
        fi.refineid.android.rapp.RappStoredPairs
            .cleanAtStartup(rappPairCatalog, rappVault)
        remoteCardModel =
            fi.refineid.android.rapp.RemoteCardModel(
                context = this,
                scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                vault = rappVault,
                catalog = rappPairCatalog,
            )
        val externalKeyCardSession =
            TransportSelectingCardSession(
                listOf(
                    readerController.externalKeyCardSession,
                    nfcReaderController.externalKeyCardSession,
                ),
            )
        pinPromptBroker =
            ExternalKeyPinPromptBroker(
                context = this,
                callerLabelResolver = AndroidExternalKeyCallerLabelResolver(packageManager),
                pinCache = authenticationPinCache,
                cardFor = { generation ->
                    externalKeyCardSession.copyIdentity(generation)?.use { identity ->
                        AuthenticationCardIdentity.of(identity.certificate)
                    }
                },
            )
        externalKeyProviderRuntime =
            ExternalKeyProviderRuntime(
                cardSession = externalKeyCardSession,
                pinAuthorizer = pinPromptBroker,
                issuerCertificateSource = caStore,
            )
        val readerCardPresence = ReaderCardPresenceWatch()
        readerController.addStateListener { snapshot ->
            if (readerCardPresence.presenceEnded(snapshot)) forgetReaderPin1()
        }
        readerController.start()
        rappProxyDispatcher = createRappProxyDispatcher(primedStore)
        // Either reader's card arriving or leaving, and the USB reader's
        // attachment or detachment, are reported on the open RAPP session
        // (RAPP v26.10.22 section 8.4 item 1).
        readerController.addStateListener { rappProxyDispatcher.cardChanged() }
        nfcReaderController.addStateListener { rappProxyDispatcher.cardChanged() }
        startRappProxyListening()
    }

    /** Whether a card is ready on the USB reader or on NFC; primed material alone is not a card. */
    private fun isAnyCardReady(): Boolean = readerController.isCardReady || nfcReaderController.isCardReady

    internal fun startRappProxyListening() {
        val settings =
            fi.refineid.android.rapp
                .RappSettings(this)
        if (!settings.isCardRemoteAccessEnabled) {
            return
        }
        // Forgotten pairings are served too, until their close reaches the
        // peer (RAPP v26.10.22 section 4.6 item 2).
        val served =
            fi.refineid.android.rapp.RappStoredPairs
                .served(rappPairCatalog, rappVault)
        val roles = served.map { it.pairing.role }.toSet()
        served.forEach { it.record.close() }
        if (uniffi.refineid_rapp.RappEndpointRole.PROXY in roles) {
            rappProxyDispatcher.startListening(rappVault)
        }
        if (uniffi.refineid_rapp.RappEndpointRole.REQUESTER in roles) {
            remoteCardModel.refresh()
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
            onAuthenticationVerified = ::retainAuthenticationPin,
            offeredCard = { offeredRappCard(primedStore) },
            cardReader = {
                fi.refineid.android.rapp.RappCardReport
                    .readerOf(readerController.snapshot)
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
            isCardReady = ::isAnyCardReady,
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

    /**
     * The card this phone holds for a paired computer (RAPP v26.10.22
     * section 8.4 item 1): a card ready in the USB reader, a card open on NFC,
     * or an NFC card the holder added to the phone and has not removed,
     * named by its authentication certificate. A reader that does not hand
     * the certificate over in time reports no card.
     */
    private suspend fun offeredRappCard(primedStore: PrimedCanStore?): fi.refineid.android.rapp.RappOfferedCard {
        val certificate =
            when {
                readerController.isCardReady -> {
                    fi.refineid.android.rapp.RappCardRead
                        .authenticationCertificate(readerController)
                }

                nfcReaderController.isCardReady -> {
                    nfcReaderController.currentAuthenticationCertificateDer
                        ?.let(fi.refineid.android.rapp.RappCertificate::fromDer)
                }

                primedStore?.isPrimed() == true -> {
                    primedStore.readAuthCertificateDer()?.let(fi.refineid.android.rapp.RappCertificate::fromDer)
                }

                else -> {
                    null
                }
            }
        return if (certificate != null) {
            fi.refineid.android.rapp.RappOfferedCard
                .Present(certificate)
        } else {
            fi.refineid.android.rapp.RappOfferedCard.Absent
        }
    }

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
