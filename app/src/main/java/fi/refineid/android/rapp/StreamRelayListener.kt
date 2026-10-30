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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
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

/** One accepted connection of a [StreamRelayListener]; it names no peer. */
internal class StreamRelayConnection(
    private val drop: () -> Unit,
) {
    /**
     * Drops this connection as [StreamRelayListener.disconnectClient] does
     * if it is still the listener's current connection; a later connection
     * is left alone.
     */
    fun disconnect() = drop()
}

/**
 * Listens for incoming RAPP stream connections and advertises via mDNS/NSD.
 *
 * It holds one connection at a time. [send] and [disconnectClient] return
 * at once on any thread: each connection writes its frames, and is finally
 * closed, in the order they were queued, on its own lane off the calling
 * thread; a close waits at most [CLOSE_DRAIN_BOUND_MS] for the frames
 * queued before it. A connection that fails or is closed under its read
 * loop ends quietly.
 *
 * Every change of the connection and the event that reports it happen in
 * one step under this listener's lock, which queues the event; one lane
 * delivers the queued events to [onEvent], in order and off the lock, and
 * none once the listener is closed. So a connection's
 * [StreamRelayEvent.Connected] comes before its frames and its
 * [StreamRelayEvent.Disconnected], its frames only while it is current,
 * and the next connection is taken only after every event of the
 * previous one was delivered.
 *
 * A connection that arrives while another is current is refused: with
 * [answerWhileHeld] set, its first frame is read and answered as that
 * callback says before it closes, at most [CONCURRENT_HELD_ANSWERS] at a
 * time; otherwise it closes unanswered. It reports no event.
 *
 * A connection whose read loop stops because [scope] was cancelled is
 * cleared without a [StreamRelayEvent.Disconnected]: the scope belongs to
 * the listener's owner, which ended it and handles no further event.
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

        /**
         * How long a closing connection's queued frames have to leave before
         * its socket closes regardless: the bound RAPP v26.10.29 section 4.5
         * item 8 sets on a quitting Requester's closes.
         */
        const val CLOSE_DRAIN_BOUND_MS = 1_000L

        /**
         * How long a new connection waits for the previous connection to
         * finish before it is refused: that socket closes within
         * [CLOSE_DRAIN_BOUND_MS] of its close, which ends its read loop, and
         * its last events have as long again to be delivered.
         */
        private const val READ_HANDOFF_BOUND_MS = 2 * CLOSE_DRAIN_BOUND_MS

        /**
         * How many connections refused while another is current may wait for
         * their first frame at once; more are closed unanswered.
         */
        const val CONCURRENT_HELD_ANSWERS = 4

        /** Why a connection was refused while another is current. */
        private const val ALREADY_CONNECTED = "already_connected"

        /** Runs the bounded closes of every listener's connections; never cancelled. */
        private val closeDeadlines = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    /**
     * One accepted connection: its socket, and the lane that writes its
     * frames and then closes it, one task at a time in the order queued.
     * A failed write closes the socket, which ends its read loop.
     */
    private class StreamConnection(
        val socket: Socket,
        val handle: StreamRelayConnection,
    ) {
        private val output: OutputStream = socket.getOutputStream()
        private val lane: Executor = Dispatchers.IO.limitedParallelism(1).asExecutor()
        private val closing = AtomicBoolean(false)

        /** Opens once the connection's read loop has ended and every event it reported was delivered. */
        val finished = CountDownLatch(1)

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

        /**
         * Closes the socket once every frame queued before is written, or
         * after [CLOSE_DRAIN_BOUND_MS] with frames still queued; closing the
         * socket ends a write the peer does not read, and the read loop.
         * Later calls do nothing.
         */
        fun close() {
            if (!closing.compareAndSet(false, true)) return
            val deadline =
                closeDeadlines.launch {
                    delay(CLOSE_DRAIN_BOUND_MS)
                    if (!socket.isClosed) {
                        AppTrace.rappListenerFailed("close_drain_bound_expired")
                        closeNow()
                    }
                }
            lane.execute {
                closeNow()
                deadline.cancel()
            }
        }

        /**
         * Reads this connection's first frame, sends what [answer] returns
         * for it unless [stopped], and closes the connection; a failed read
         * closes it unanswered.
         */
        fun answerFirstFrame(
            scope: CoroutineScope,
            stopped: () -> Boolean,
            answer: (ByteArray) -> ByteArray?,
        ): Job =
            scope
                .launch(Dispatchers.IO) {
                    try {
                        val frame = StreamRelayFraming.read(DataInputStream(socket.getInputStream()))
                        val reply = if (stopped()) null else answer(frame)
                        reply?.let(StreamRelayFraming::encode)?.let(::write)
                    } catch (_: IOException) {
                    } finally {
                        close()
                    }
                }.also { job -> job.invokeOnCompletion { cause -> if (cause != null) closeNow() } }

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

    /** The connection that has not finished; guarded by this listener's lock. */
    private var reader: StreamConnection? = null
    private var listenerJob: Job? = null

    /** Ends the current connection when its handshake runs past its deadline; guarded by this listener's lock. */
    private var authDeadlineJob: Job? = null

    /** Delivers the queued events one at a time, in the order they were queued. */
    private val events: Executor = Dispatchers.IO.limitedParallelism(1).asExecutor()
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

    /**
     * The answer to the first frame of a connection that arrives while
     * another is current, sent before that connection closes; null closes
     * it unanswered. Runs off the event lane.
     */
    @Volatile
    var answerWhileHeld: ((ByteArray) -> ByteArray?)? = null

    /** The refused connections that may wait for their first frame at once. */
    private val heldAnswers = Semaphore(CONCURRENT_HELD_ANSWERS)

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
            post(StreamRelayEvent.Error(e))
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
        post(StreamRelayEvent.Error(e))
    }

    /** Queues [event] for delivery after every event queued before it; it is dropped once the listener is closed. */
    private fun post(event: StreamRelayEvent) {
        events.execute {
            if (!isClosed.get()) onEvent(event)
        }
    }

    /** Takes [socket] as the connection unless it is refused, then reads it until it ends. */
    private fun admit(socket: Socket) {
        lateinit var accepted: StreamConnection
        accepted =
            try {
                StreamConnection(socket, StreamRelayConnection { disconnect(accepted) })
            } catch (_: IOException) {
                try {
                    socket.close()
                } catch (_: IOException) {
                }
                return
            }
        if (handshakeTimeoutMs > 0) {
            try {
                socket.soTimeout = handshakeTimeoutMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            } catch (_: Exception) {
            }
        }
        val refusal = handOff(accepted)
        if (refusal != null) {
            AppTrace.rappConnectionRejected(refusal)
            val answer = answerWhileHeld
            if (refusal == ALREADY_CONNECTED && answer != null && heldAnswers.tryAcquire()) {
                accepted.answerFirstFrame(scope, { isClosed.get() || isWithdrawn }, answer).invokeOnCompletion {
                    heldAnswers.release()
                }
            } else {
                accepted.closeNow()
            }
            return
        }
        AppTrace.rappConnectionAccepted()
        if (BuildConfig.DEBUG) {
            android.util.Log.i("STREAM_LISTENER", "Accepted connection")
        }
    }

    /**
     * Makes [accepted] the connection once the previous connection has
     * finished, waiting at most [READ_HANDOFF_BOUND_MS]: in one step it
     * becomes current, its [StreamRelayEvent.Connected] is queued, and its
     * handshake deadline and read loop start. Returns why it was refused: a
     * peer is connected, the previous connection has not finished, or the
     * listener stopped meanwhile; null when it was taken.
     */
    private fun handOff(accepted: StreamConnection): String? {
        val previous =
            synchronized(this) {
                if (connection?.isOpen == true) return ALREADY_CONNECTED
                reader
            }
        if (previous?.finished?.await(READ_HANDOFF_BOUND_MS, TimeUnit.MILLISECONDS) == false) {
            return "previous_reads_running"
        }
        synchronized(this) {
            if (isClosed.get() || isWithdrawn) return "listener_stopped"
            if (connection?.isOpen == true) return ALREADY_CONNECTED
            connection = accepted
            reader = accepted
            post(StreamRelayEvent.Connected)
            authDeadlineJob?.cancel()
            authDeadlineJob =
                if (handshakeTimeoutMs > 0) {
                    scope.launch(Dispatchers.IO) {
                        delay(handshakeTimeoutMs)
                        if (disconnect(accepted)) AppTrace.rappListenerFailed("handshake_auth_deadline_expired")
                    }
                } else {
                    null
                }
            scope.launch(Dispatchers.IO) { readLoop(accepted) }.invokeOnCompletion {
                // Queued behind every event the connection reported.
                events.execute {
                    accepted.finished.countDown()
                    synchronized(this) { if (reader === accepted) reader = null }
                }
            }
        }
        return null
    }

    /**
     * Reads [accepted]'s frames while it is the current connection; a frame
     * read after it stopped being current is dropped and the loop ends. Any
     * read failure, the socket closed by another thread included, ends the
     * connection as [disconnectClient] does: its socket closes once the
     * frames queued for it are written, within [CLOSE_DRAIN_BOUND_MS]. A
     * loop that stops because its scope ended clears the connection without
     * an event.
     */
    private fun readLoop(accepted: StreamConnection) {
        val socket = accepted.socket
        try {
            val input = DataInputStream(socket.getInputStream())
            while (scope.isActive) {
                val buffer = StreamRelayFraming.read(input)
                if (BuildConfig.DEBUG) {
                    android.util.Log.d("STREAM_LISTENER", "Received frame length=${buffer.size}")
                }
                val delivered =
                    synchronized(this) {
                        val isCurrent = !isClosed.get() && connection === accepted
                        if (isCurrent) post(StreamRelayEvent.Frame(buffer))
                        isCurrent
                    }
                if (!delivered) break
            }
        } catch (e: IOException) {
            if (BuildConfig.DEBUG) {
                android.util.Log.w("STREAM_LISTENER", "Socket read loop ended: ${e.javaClass.simpleName}")
            }
            disconnect(accepted)
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
     * frames queued for it are written, within [CLOSE_DRAIN_BOUND_MS], then
     * keeps the instance advertised with [attributes] until [close] (RAPP
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
                    AppTrace.rappListenerServiceRegistered()
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

    /**
     * Drops the connected peer at once; its socket closes once the frames
     * queued for it are written, within [CLOSE_DRAIN_BOUND_MS].
     */
    fun disconnectClient() {
        disconnect(null)
    }

    /** The current connection, or null without one. */
    val currentConnection: StreamRelayConnection?
        get() = synchronized(this) { connection?.handle }

    /**
     * Drops [expected], or whichever connection is current when null, if it
     * is the current connection: in one step it stops being current, its
     * close is requested and its [StreamRelayEvent.Disconnected] queued.
     * True when it dropped a connection.
     */
    private fun disconnect(expected: StreamConnection?): Boolean {
        synchronized(this) {
            val active = connection
            if (active == null || (expected != null && active !== expected)) return false
            authDeadlineJob?.cancel()
            authDeadlineJob = null
            connection = null
            active.close()
            post(StreamRelayEvent.Disconnected)
        }
        return true
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

    /**
     * Stops listening and advertising, and delivers no further event; the
     * connected peer's socket closes once the frames queued for it are
     * written, within [CLOSE_DRAIN_BOUND_MS].
     */
    override fun close() {
        if (isClosed.compareAndSet(false, true)) {
            if (BuildConfig.DEBUG) android.util.Log.i("STREAM_LISTENER", "close() called")
            val active =
                synchronized(this) {
                    authDeadlineJob?.cancel()
                    authDeadlineJob = null
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
