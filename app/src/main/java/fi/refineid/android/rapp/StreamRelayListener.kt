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
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executor
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
 *
 * It holds one connection at a time. [send] and [disconnectClient] return
 * at once on any thread: each connection writes its frames, and is finally
 * closed, in the order they were queued, on its own lane off the calling
 * thread. A connection that fails or is closed under its read loop ends
 * quietly; only the current connection's end is reported.
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

    /**
     * One accepted connection: its socket, and the lane that writes its
     * frames and then closes it, one task at a time in the order queued.
     * A failed write closes the socket, which ends its read loop.
     */
    private class StreamConnection(
        val socket: Socket,
    ) {
        private val output: OutputStream = socket.getOutputStream()
        private val lane: Executor = Dispatchers.IO.limitedParallelism(1).asExecutor()

        val isOpen: Boolean
            get() = !socket.isClosed && socket.isConnected

        /** Queues one encoded stream record behind the frames queued before it. */
        fun write(record: ByteArray) {
            lane.execute {
                try {
                    output.write(record)
                    output.flush()
                } catch (e: IOException) {
                    if (!socket.isClosed) AppTrace.rappListenerFailed("write_failed_${e.javaClass.simpleName}")
                    closeNow()
                }
            }
        }

        /** Closes the socket once every frame queued before is written. */
        fun close() {
            lane.execute(::closeNow)
        }

        fun closeNow() {
            try {
                socket.close()
            } catch (_: IOException) {
            }
        }
    }

    private val nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val multicastLock =
        wifiManager?.createMulticastLock("refineid-listener")?.apply {
            setReferenceCounted(false)
        }

    private var serverSocket: ServerSocket? = null

    /** The connected peer; guarded by this listener's lock. */
    private var connection: StreamConnection? = null
    private var listenerJob: Job? = null
    private var readJob: Job? = null
    private var authDeadlineJob: Job? = null
    private val isClosed = AtomicBoolean(false)
    private var registrationListener: NsdManager.RegistrationListener? = null

    /** A registration that waits for the previous one to finish unregistering. */
    private var nextRegistration: (() -> Unit)? = null

    @Volatile
    private var isWithdrawn = false
    private var advertisedName: String? = null

    /**
     * The instance portion of the name the service is registered under,
     * which the system may have changed to resolve a conflict.
     */
    @Volatile
    var registeredName: String? = null
        private set

    /** Called with the instance name each time the responder confirms a registration. */
    @Volatile
    var onRegistered: ((String) -> Unit)? = null

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
                        val socket =
                            try {
                                server.accept()
                            } catch (e: IOException) {
                                acceptEnded(e)
                                break
                            }
                        admit(socket)
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

    /** Accepting ended; a failure after [close] or [withdraw] closed the server socket is that close, not an error. */
    private fun acceptEnded(e: IOException) {
        if (isClosed.get() || isWithdrawn) return
        AppTrace.rappListenerFailed("accept_loop_exited_${e.javaClass.simpleName}")
        if (BuildConfig.DEBUG) {
            android.util.Log.w(
                "STREAM_LISTENER",
                "ServerSocket accept loop exited: ${e.javaClass.simpleName}",
            )
        }
        onEvent(StreamRelayEvent.Error(e))
    }

    /**
     * Takes [socket] as the connection unless a peer is already connected,
     * then reads it until it ends.
     */
    private fun admit(socket: Socket) {
        val accepted =
            try {
                StreamConnection(socket)
            } catch (_: IOException) {
                try {
                    socket.close()
                } catch (_: IOException) {
                }
                return
            }
        val shouldReject =
            synchronized(this) {
                if (connection?.isOpen == true) {
                    true
                } else {
                    readJob?.cancel()
                    connection = accepted
                    false
                }
            }

        if (shouldReject) {
            AppTrace.rappConnectionRejected(
                socket.remoteSocketAddress?.toString() ?: "unknown",
                "already_connected",
            )
            accepted.closeNow()
            return
        }
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
                            if (connection === accepted) {
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

        // The handler may already have dropped the connection.
        synchronized(this) {
            if (connection === accepted) {
                readJob = scope.launch(Dispatchers.IO) { readLoop(accepted) }
            }
        }
    }

    /**
     * Reads [accepted]'s frames until it ends. Any read failure, the socket
     * closed by another thread included, ends the connection at once; only
     * the current connection's end is reported as
     * [StreamRelayEvent.Disconnected]. A loop that stops because the
     * listener closed leaves the socket to close after its queued frames.
     */
    private fun readLoop(accepted: StreamConnection) {
        val socket = accepted.socket
        try {
            val input = DataInputStream(socket.getInputStream())
            while (scope.isActive && !isClosed.get()) {
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
            accepted.closeNow()
            val notifyDisconnect =
                synchronized(this) {
                    if (!isClosed.get() && connection === accepted) {
                        authDeadlineJob?.cancel()
                        authDeadlineJob = null
                        connection = null
                        true
                    } else {
                        false
                    }
                }
            if (notifyDisconnect) {
                onEvent(StreamRelayEvent.Disconnected)
            }
        } finally {
            accepted.close()
            synchronized(this) {
                if (connection === accepted) {
                    authDeadlineJob?.cancel()
                    authDeadlineJob = null
                    connection = null
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
     * Stops accepting connections and drops the connected peer once the
     * frames queued for it are written, then keeps the instance advertised
     * with [attributes] until [close] (RAPP section 4.5 steps 2 and 3).
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
                    onRegistered?.invoke(serviceInfo.serviceName)
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

    /**
     * Queues [frame] for the connected peer and returns at once; the
     * connection writes it after the frames queued before it, off the
     * calling thread.
     */
    fun send(frame: ByteArray) {
        if (isClosed.get()) throw IOException("Listener is closed")
        val record = StreamRelayFraming.encode(frame) ?: throw IOException("Frame outside the stream framing")
        synchronized(this) {
            val current = connection ?: throw IOException("No peer connected")
            if (BuildConfig.DEBUG) {
                android.util.Log.d("STREAM_LISTENER", "Sending frame size=${frame.size}")
            }
            current.write(record)
        }
    }

    /** Drops the connected peer at once; its socket closes once the frames queued for it are written. */
    fun disconnectClient() {
        val notifyDisconnect =
            synchronized(this) {
                val active = connection
                authDeadlineJob?.cancel()
                authDeadlineJob = null
                readJob?.cancel()
                readJob = null
                active?.close()
                connection = null
                !isClosed.get() && active != null
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
                connection?.socket?.soTimeout = ESTABLISHED_READ_TIMEOUT_MS
            } catch (_: Exception) {
            }
        }
    }

    /** Stops listening and advertising; the connected peer's socket closes once the frames queued for it are written. */
    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            if (BuildConfig.DEBUG) android.util.Log.i("STREAM_LISTENER", "close() called")
            val active =
                synchronized(this) {
                    authDeadlineJob?.cancel()
                    authDeadlineJob = null
                    readJob?.cancel()
                    readJob = null
                    connection.also { connection = null }
                }
            takeNextRegistration()
            registrationListener?.let {
                try {
                    nsdManager?.unregisterService(it)
                } catch (_: Exception) {
                }
            }
            registrationListener = null
            listenerJob?.cancel()
            active?.close()
            try {
                serverSocket?.close()
            } catch (_: Exception) {
            }
            try {
                multicastLock?.release()
            } catch (_: Exception) {
            }
        }
    }
}
