@file:Suppress("SwallowedException", "MaxLineLength", "TooGenericExceptionCaught")

package fi.refineid.android.rapp

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import fi.refineid.android.BuildConfig
import fi.refineid.android.diagnostics.AppTrace
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

internal sealed interface StreamRelayEvent {
    data object Connected : StreamRelayEvent

    data class Frame(
        val data: ByteArray,
    ) : StreamRelayEvent

    data object Disconnected : StreamRelayEvent

    data class Error(
        val cause: Throwable,
    ) : StreamRelayEvent
}

/**
 * Listens for incoming RAPP stream connections and advertises via mDNS/NSD.
 */
internal class StreamRelayListener(
    private val context: Context,
    private val scope: CoroutineScope,
    private val handshakeTimeoutMs: Long = DEFAULT_HANDSHAKE_TIMEOUT_MS,
    private val onEvent: (StreamRelayEvent) -> Unit,
) : AutoCloseable {
    companion object {
        const val SERVICE_TYPE = "_refineid-stream._tcp"
        const val DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000L
        const val ESTABLISHED_READ_TIMEOUT_MS = 60_000
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val multicastLock =
        wifiManager?.createMulticastLock("refineid-listener")?.apply {
            setReferenceCounted(false)
        }

    private var serverSocket: ServerSocket? = null
    private var clientSocket: Socket? = null
    private var outputStream: DataOutputStream? = null
    private var listenerJob: Job? = null
    private var readJob: Job? = null
    private var authDeadlineJob: Job? = null
    private val isClosed = AtomicBoolean(false)
    private var registrationListener: NsdManager.RegistrationListener? = null

    /** A registration that waits for the previous one to finish unregistering. */
    private var nextRegistration: (() -> Unit)? = null
    private var isWithdrawn = false
    private var advertisedName: String? = null

    /**
     * The instance portion of the name the service is registered under,
     * which the system may have changed to resolve a conflict.
     */
    @Volatile
    var registeredName: String? = null
        private set

    val port: Int?
        get() = serverSocket?.localPort

    /**
     * Starts listening and advertises under [instanceName] with the given TXT
     * attributes.
     */
    fun start(
        instanceName: String,
        attributes: Map<String, String>,
    ) {
        if (isClosed.get()) return
        try {
            multicastLock?.acquire()
        } catch (_: Exception) {
        }
        try {
            // nosemgrep: kotlin.lang.security.unencrypted-socket.unencrypted-socket
            val server = ServerSocket(0)
            serverSocket = server
            AppTrace.rappListenerStarted(server.localPort)
            if (BuildConfig.DEBUG) {
                android.util.Log.i("STREAM_LISTENER", "ServerSocket listening")
            }

            advertisedName = instanceName
            register(instanceName, server.localPort, attributes)

            listenerJob =
                scope.launch(Dispatchers.IO) {
                    while (isActive && !isClosed.get()) {
                        try {
                            val socket = server.accept()
                            val shouldReject =
                                synchronized(this@StreamRelayListener) {
                                    val current = clientSocket
                                    if (current != null && !current.isClosed && current.isConnected) {
                                        true
                                    } else {
                                        readJob?.cancel()
                                        clientSocket = socket
                                        outputStream = DataOutputStream(socket.getOutputStream())
                                        false
                                    }
                                }

                            if (shouldReject) {
                                AppTrace.rappConnectionRejected(
                                    socket.remoteSocketAddress?.toString() ?: "unknown",
                                    "already_connected",
                                )
                                try {
                                    socket.close()
                                } catch (_: Exception) {
                                }
                            } else {
                                if (handshakeTimeoutMs > 0) {
                                    try {
                                        socket.soTimeout =
                                            handshakeTimeoutMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                                    } catch (_: Exception) {
                                    }
                                    authDeadlineJob?.cancel()
                                    authDeadlineJob =
                                        scope.launch(Dispatchers.IO) {
                                            delay(handshakeTimeoutMs)
                                            val shouldDisconnect =
                                                synchronized(this@StreamRelayListener) {
                                                    if (clientSocket === socket) {
                                                        AppTrace.rappListenerFailed("handshake_auth_deadline_expired")
                                                        true
                                                    } else {
                                                        false
                                                    }
                                                }
                                            if (shouldDisconnect) {
                                                disconnectClient()
                                            }
                                        }
                                }
                                AppTrace.rappConnectionAccepted(socket.remoteSocketAddress.toString())
                                if (BuildConfig.DEBUG) {
                                    android.util.Log.i(
                                        "STREAM_LISTENER",
                                        "Accepted connection from ${socket.remoteSocketAddress}",
                                    )
                                }
                                onEvent(StreamRelayEvent.Connected)

                                readJob =
                                    scope.launch(Dispatchers.IO) {
                                        readLoop(socket)
                                    }
                            }
                        } catch (e: IOException) {
                            if (!isClosed.get()) {
                                AppTrace.rappListenerFailed("accept_loop_exited_${e.javaClass.simpleName}")
                                if (BuildConfig.DEBUG) {
                                    android.util.Log.w(
                                        "STREAM_LISTENER",
                                        "ServerSocket accept loop exited: ${e.javaClass.simpleName}",
                                    )
                                }
                                onEvent(StreamRelayEvent.Error(e))
                            }
                            break
                        }
                    }
                }
        } catch (e: IOException) {
            AppTrace.rappListenerFailed("start_failed_${e.javaClass.simpleName}")
            if (BuildConfig.DEBUG) {
                android.util.Log.e("STREAM_LISTENER", "start failed", e)
            }
            onEvent(StreamRelayEvent.Error(e))
        }
    }

    private suspend fun readLoop(socket: Socket) {
        val input = DataInputStream(socket.getInputStream())
        try {
            while (scope.isActive && !isClosed.get() && !socket.isClosed) {
                val length = input.readUnsignedShort()
                if (length == 0) {
                    throw IOException("empty stream frame")
                }
                val buffer = ByteArray(length)
                input.readFully(buffer)
                if (BuildConfig.DEBUG) {
                    android.util.Log.d(
                        "STREAM_LISTENER",
                        "Received frame length=$length from ${socket.remoteSocketAddress}",
                    )
                }
                onEvent(StreamRelayEvent.Frame(buffer))
            }
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) {
                android.util.Log.w("STREAM_LISTENER", "Socket read loop ended: ${e.javaClass.simpleName}")
            }
            val notifyDisconnect =
                synchronized(this) {
                    if (!isClosed.get() && clientSocket === socket) {
                        authDeadlineJob?.cancel()
                        authDeadlineJob = null
                        clientSocket = null
                        outputStream = null
                        true
                    } else {
                        false
                    }
                }
            if (notifyDisconnect) {
                onEvent(StreamRelayEvent.Disconnected)
            }
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
            synchronized(this) {
                if (clientSocket === socket) {
                    authDeadlineJob?.cancel()
                    authDeadlineJob = null
                    clientSocket = null
                    outputStream = null
                }
            }
        }
    }

    /**
     * Replaces the published TXT attributes, keeping the instance name and
     * the listening socket, so a connected peer is not disturbed.
     */
    fun updateAttributes(attributes: Map<String, String>) {
        if (isClosed.get()) return
        val name = advertisedName ?: return
        val listeningPort = serverSocket?.localPort ?: return
        reregister(name, listeningPort, attributes)
    }

    /**
     * Stops accepting connections and drops the connected peer, then keeps
     * the instance advertised with [attributes] until [close] (RAPP
     * section 4.5 steps 2 and 3).
     */
    fun withdraw(attributes: Map<String, String>) {
        if (isClosed.get() || isWithdrawn) return
        val name = advertisedName ?: return
        val listeningPort = serverSocket?.localPort ?: return
        isWithdrawn = true
        listenerJob?.cancel()
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        disconnectClient()
        reregister(name, listeningPort, attributes)
    }

    /**
     * Registers the same instance anew once the current registration has
     * finished unregistering, so the responder does not see the name as
     * taken and rename the instance.
     */
    private fun reregister(
        instanceName: String,
        listeningPort: Int,
        attributes: Map<String, String>,
    ) {
        val current = registrationListener
        if (current == null) {
            register(instanceName, listeningPort, attributes)
            return
        }
        registrationListener = null
        synchronized(this) { nextRegistration = { register(instanceName, listeningPort, attributes) } }
        try {
            nsdManager?.unregisterService(current)
        } catch (_: Exception) {
            takeNextRegistration()?.invoke()
        }
    }

    @Synchronized
    private fun takeNextRegistration(): (() -> Unit)? = nextRegistration.also { nextRegistration = null }

    private fun register(
        instanceName: String,
        listeningPort: Int,
        attributes: Map<String, String>,
    ) {
        val serviceInfo =
            NsdServiceInfo().apply {
                serviceName = instanceName
                serviceType = SERVICE_TYPE
                this.port = listeningPort
                attributes.forEach { (key, value) -> setAttribute(key, value) }
            }

        val regListener =
            object : NsdManager.RegistrationListener {
                override fun onServiceRegistered(serviceInfo: NsdServiceInfo) {
                    registeredName = serviceInfo.serviceName
                    advertisedName = serviceInfo.serviceName
                    AppTrace.rappListenerServiceRegistered(serviceInfo.serviceName)
                    if (BuildConfig.DEBUG) {
                        android.util.Log.i("STREAM_LISTENER", "onServiceRegistered")
                    }
                }

                override fun onRegistrationFailed(
                    serviceInfo: NsdServiceInfo,
                    errorCode: Int,
                ) {
                    AppTrace.rappListenerFailed("registration_failed_code_$errorCode")
                    if (BuildConfig.DEBUG) {
                        android.util.Log.e(
                            "STREAM_LISTENER",
                            "onRegistrationFailed, errorCode: $errorCode",
                        )
                    }
                }

                override fun onServiceUnregistered(serviceInfo: NsdServiceInfo) {
                    if (BuildConfig.DEBUG) {
                        android.util.Log.i("STREAM_LISTENER", "onServiceUnregistered")
                    }
                    if (!isClosed.get()) takeNextRegistration()?.invoke()
                }

                override fun onUnregistrationFailed(
                    serviceInfo: NsdServiceInfo,
                    errorCode: Int,
                ) {
                    if (!isClosed.get()) takeNextRegistration()?.invoke()
                    if (BuildConfig.DEBUG) {
                        android.util.Log.e(
                            "STREAM_LISTENER",
                            "onUnregistrationFailed, errorCode: $errorCode",
                        )
                    }
                }
            }
        registrationListener = regListener
        nsdManager?.registerService(serviceInfo, NsdManager.PROTOCOL_DNS_SD, regListener)
    }

    fun send(frame: ByteArray) {
        if (isClosed.get()) throw IOException("Listener is closed")
        val out = outputStream ?: throw IOException("No peer connected")
        synchronized(this) {
            if (BuildConfig.DEBUG) {
                android.util.Log.d("STREAM_LISTENER", "Sending frame size=${frame.size}")
            }
            out.writeShort(frame.size)
            out.write(frame)
            out.flush()
        }
    }

    fun disconnectClient() {
        val notifyDisconnect =
            synchronized(this) {
                val activeSocket = clientSocket
                authDeadlineJob?.cancel()
                authDeadlineJob = null
                readJob?.cancel()
                readJob = null
                try {
                    activeSocket?.close()
                } catch (_: Exception) {
                }
                clientSocket = null
                outputStream = null
                !isClosed.get() && activeSocket != null
            }
        if (notifyDisconnect) {
            onEvent(StreamRelayEvent.Disconnected)
        }
    }

    fun clearSocketTimeout() {
        synchronized(this) {
            authDeadlineJob?.cancel()
            authDeadlineJob = null
            try {
                clientSocket?.soTimeout = ESTABLISHED_READ_TIMEOUT_MS
            } catch (_: Exception) {
            }
        }
    }

    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            if (BuildConfig.DEBUG) android.util.Log.i("STREAM_LISTENER", "close() called")
            authDeadlineJob?.cancel()
            authDeadlineJob = null
            takeNextRegistration()
            registrationListener?.let {
                try {
                    nsdManager?.unregisterService(it)
                } catch (_: Exception) {
                }
            }
            registrationListener = null
            listenerJob?.cancel()
            readJob?.cancel()
            try {
                clientSocket?.close()
            } catch (_: Exception) {
            }
            try {
                serverSocket?.close()
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
