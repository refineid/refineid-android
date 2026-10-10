@file:Suppress("TooGenericExceptionCaught", "SwallowedException", "MagicNumber", "MaxLineLength", "DEPRECATION")

package fi.refineid.android.rapp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import fi.refineid.android.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Browses for a published RAPP stream advertising [targetMode] in its TXT
 * record and connects to the first one that resolves. Instance names are
 * random and carry nothing to match.
 */
internal class StreamRelayBrowser(
    private val context: Context,
    private val scope: CoroutineScope,
    private val targetMode: String,
    private val onEvent: (StreamRelayEvent) -> Unit,
) : AutoCloseable {
    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val multicastLock =
        wifiManager?.createMulticastLock("refineid-browser")?.apply {
            setReferenceCounted(false)
        }

    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var socket: Socket? = null
    private var outputStream: DataOutputStream? = null
    private var readJob: Job? = null
    private var refreshJob: Job? = null
    private val isClosed = AtomicBoolean(false)
    private val isConnected = AtomicBoolean(false)
    private val isResolving = AtomicBoolean(false)
    private var activeServiceCallback: Any? = null

    fun start() {
        if (isClosed.get()) return
        try {
            multicastLock?.acquire()
        } catch (_: Exception) {
        }
        startDiscoveryInternal()

        // Periodically refresh discovery while waiting to find the peer.
        // This ensures prompt discovery when the peer begins advertising after this browser has started,
        // overcoming mDNS backoff delays.
        refreshJob =
            scope.launch(Dispatchers.IO) {
                while (isActive && !isClosed.get() && !isConnected.get()) {
                    delay(3000L)
                    if (!isClosed.get() && !isConnected.get() && !isResolving.get()) {
                        if (BuildConfig.DEBUG) {
                            android.util.Log.d("STREAM_BROWSER", "Discovery refresh pulse for mode $targetMode")
                        }
                        restartDiscovery()
                    }
                }
            }
    }

    private fun startDiscoveryInternal() {
        if (isClosed.get() || isConnected.get()) return
        val listener =
            object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(regType: String) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.d("STREAM_BROWSER", "onDiscoveryStarted: $regType (mode=$targetMode)")
                    }
                }

                override fun onDiscoveryStopped(serviceType: String) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.d("STREAM_BROWSER", "onDiscoveryStopped: $serviceType")
                    }
                }

                override fun onStartDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.e("STREAM_BROWSER", "onStartDiscoveryFailed, code=$errorCode")
                    }
                    onEvent(StreamRelayEvent.Error(IOException("NSD discovery failed: $errorCode")))
                }

                override fun onStopDiscoveryFailed(
                    serviceType: String,
                    errorCode: Int,
                ) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.w("STREAM_BROWSER", "onStopDiscoveryFailed, code=$errorCode")
                    }
                }

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.i("STREAM_BROWSER", "onServiceFound type=${serviceInfo.serviceType}")
                    }
                    resolveAndConnect(serviceInfo)
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.d("STREAM_BROWSER", "onServiceLost")
                    }
                }
            }
        discoveryListener = listener
        try {
            nsdManager?.discoverServices(
                StreamRelayListener.SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD,
                listener,
            )
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) {
                android.util.Log.e("STREAM_BROWSER", "discoverServices error", e)
            }
            onEvent(StreamRelayEvent.Error(e))
        }
    }

    private fun restartDiscovery() {
        stopDiscovery()
        try {
            Thread.sleep(150)
        } catch (_: InterruptedException) {
        }
        if (!isClosed.get() && !isConnected.get()) {
            startDiscoveryInternal()
        }
    }

    private fun resolveAndConnect(serviceInfo: NsdServiceInfo) {
        if (isConnected.get() || isClosed.get()) return
        if (!isResolving.compareAndSet(false, true)) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                val cb =
                    object : NsdManager.ServiceInfoCallback {
                        override fun onServiceInfoCallbackRegistrationFailed(errorCode: Int) {
                            activeServiceCallback = null
                            if (BuildConfig.DEBUG) {
                                android.util.Log.w(
                                    "STREAM_BROWSER",
                                    "registerServiceInfoCallback failed: $errorCode, trying fallback",
                                )
                            }
                            isResolving.set(false)
                            resolveLegacy(serviceInfo)
                        }

                        override fun onServiceUpdated(resolved: NsdServiceInfo) {
                            if (BuildConfig.DEBUG) {
                                android.util.Log.i(
                                    "STREAM_BROWSER",
                                    "onServiceUpdated",
                                )
                            }
                            val host = resolved.hostAddresses.firstOrNull()?.hostAddress ?: resolved.host?.hostAddress
                            val port = resolved.port
                            if (!StreamRendezvousName.matches(resolved.attributes, targetMode)) {
                                isResolving.set(false)
                                activeServiceCallback = null
                                try {
                                    nsdManager?.unregisterServiceInfoCallback(this)
                                } catch (_: Exception) {
                                }
                                return
                            }
                            if (host != null && port > 0 && isConnected.compareAndSet(false, true)) {
                                isResolving.set(false)
                                activeServiceCallback = null
                                try {
                                    nsdManager?.unregisterServiceInfoCallback(this)
                                } catch (_: Exception) {
                                }
                                stopDiscovery()
                                connectToEndpoint(host, port)
                            }
                        }

                        override fun onServiceLost() {
                            activeServiceCallback = null
                            isResolving.set(false)
                        }

                        override fun onServiceInfoCallbackUnregistered() {
                            activeServiceCallback = null
                            isResolving.set(false)
                        }
                    }
                activeServiceCallback = cb
                nsdManager?.registerServiceInfoCallback(
                    serviceInfo,
                    context.mainExecutor,
                    cb,
                )
                return
            } catch (e: Exception) {
                if (BuildConfig.DEBUG) {
                    android.util.Log.w("STREAM_BROWSER", "registerServiceInfoCallback exception, fallback", e)
                }
            }
        }
        resolveLegacy(serviceInfo)
    }

    @Suppress("DEPRECATION")
    private fun resolveLegacy(serviceInfo: NsdServiceInfo) {
        if (isConnected.get() || isClosed.get()) {
            isResolving.set(false)
            return
        }
        try {
            nsdManager?.resolveService(
                serviceInfo,
                object : NsdManager.ResolveListener {
                    override fun onResolveFailed(
                        serviceInfo: NsdServiceInfo,
                        errorCode: Int,
                    ) {
                        if (BuildConfig.DEBUG) {
                            android.util.Log.w(
                                "STREAM_BROWSER",
                                "resolveService failed, code=$errorCode",
                            )
                        }
                        isResolving.set(false)
                    }

                    override fun onServiceResolved(resolved: NsdServiceInfo) {
                        isResolving.set(false)
                        val host = resolved.host?.hostAddress
                        val port = resolved.port
                        if (BuildConfig.DEBUG) {
                            android.util.Log.i(
                                "STREAM_BROWSER",
                                "onServiceResolved",
                            )
                        }
                        if (host != null &&
                            port > 0 &&
                            StreamRendezvousName.matches(resolved.attributes, targetMode) &&
                            isConnected.compareAndSet(false, true)
                        ) {
                            stopDiscovery()
                            connectToEndpoint(host, port)
                        }
                    }
                },
            )
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) {
                android.util.Log.e("STREAM_BROWSER", "resolveService exception", e)
            }
            isResolving.set(false)
        }
    }

    private fun connectToEndpoint(
        host: String?,
        port: Int,
    ) {
        if (host == null || port <= 0) return
        if (BuildConfig.DEBUG) {
            android.util.Log.i("STREAM_BROWSER", "Connecting to endpoint")
        }
        scope.launch(Dispatchers.IO) {
            try {
                // nosemgrep: kotlin.lang.security.unencrypted-socket.unencrypted-socket
                val s = Socket()
                s.connect(InetSocketAddress(host, port), 5000)
                socket = s
                outputStream = DataOutputStream(s.getOutputStream())
                if (BuildConfig.DEBUG) {
                    android.util.Log.i("STREAM_BROWSER", "Connected")
                }
                onEvent(StreamRelayEvent.Connected)

                val input = DataInputStream(s.getInputStream())
                while (scope.isActive && !isClosed.get() && !s.isClosed) {
                    val length = input.readUnsignedShort()
                    val buffer = ByteArray(length)
                    input.readFully(buffer)
                    if (BuildConfig.DEBUG) {
                        android.util.Log.d("STREAM_BROWSER", "Received frame length=$length")
                    }
                    onEvent(StreamRelayEvent.Frame(buffer))
                }
            } catch (e: IOException) {
                isConnected.set(false)
                isResolving.set(false)
                if (BuildConfig.DEBUG) {
                    android.util.Log.w("STREAM_BROWSER", "Socket loop disconnected: ${e.javaClass.simpleName}")
                }
                if (!isClosed.get()) {
                    onEvent(StreamRelayEvent.Disconnected)
                }
            }
        }
    }

    fun send(frame: ByteArray) {
        if (isClosed.get()) throw IOException("Browser is closed")
        val out = outputStream ?: throw IOException("Not connected")
        synchronized(this) {
            if (BuildConfig.DEBUG) {
                android.util.Log.d("STREAM_BROWSER", "Sending frame size=${frame.size}")
            }
            out.writeShort(frame.size)
            out.write(frame)
            out.flush()
        }
    }

    private fun stopDiscovery() {
        discoveryListener?.let {
            try {
                nsdManager?.stopServiceDiscovery(it)
            } catch (_: Exception) {
            }
        }
        discoveryListener = null
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            refreshJob?.cancel()
            refreshJob = null
            stopDiscovery()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                (activeServiceCallback as? NsdManager.ServiceInfoCallback)?.let {
                    try {
                        nsdManager?.unregisterServiceInfoCallback(it)
                    } catch (_: Exception) {
                    }
                }
                activeServiceCallback = null
            }
            readJob?.cancel()
            try {
                socket?.close()
            } catch (_: Exception) {
            }
            outputStream = null
            try {
                multicastLock?.release()
            } catch (_: Exception) {
            }
        }
    }
}
