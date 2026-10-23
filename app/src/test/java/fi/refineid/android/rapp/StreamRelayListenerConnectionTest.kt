// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import android.content.Context
import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Random
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import kotlin.concurrent.thread

/**
 * The stream listener's connections end quietly whoever closes them, and
 * its sends never write on the calling thread: the frames queued for a
 * connection leave in order before it closes, whatever the listener does
 * next (RAPP v26.10.22 section 4.5 item 3).
 */
class StreamRelayListenerConnectionTest {
    private companion object {
        const val INSTANCE_NAME = "test-listener"
        const val NO_HANDSHAKE_DEADLINE_MS = 0L
        const val EVENT_WAIT_SECONDS = 5L
        const val SETTLE_LIMIT_MS = 5_000L
        const val POLL_INTERVAL_MS = 1L

        /** The one coroutine a listener without a connection runs: its accept loop. */
        const val ACCEPT_LOOP_ONLY = 1
        const val SOCKET_TIMEOUT_MS = 10_000

        /** How long queuing every frame may take; a send that waits for the peer never finishes. */
        const val SEND_LIMIT_MS = 5_000L

        /** The largest payload one stream frame carries. */
        const val FRAME_BYTES = StreamRelayFraming.MAXIMUM_PAYLOAD_BYTE_COUNT

        /** The peer's receive buffer, fixed so the kernel does not grow it. */
        const val PEER_RECEIVE_BUFFER_BYTES = 65_536

        /** More bytes than the socket buffers between this phone and a peer that does not read can hold. */
        const val QUEUED_FRAMES = 192

        const val END_OF_STREAM = -1

        /** A length prefix announcing no payload, which the stream framing refuses. */
        const val EMPTY_FRAME_LENGTH = 0

        const val CONNECTED = "connected"
        const val DISCONNECTED = "disconnected"
        const val ERROR = "error"
        const val FROM_A = "peer A frame"
        const val FROM_A_LATE = "peer A frame after peer B connected"
        const val FROM_B = "peer B frame"

        /** How many peers connect, one after another, while their connections are dropped at random. */
        const val STRESS_PEERS = 100

        /** How many frames each of those peers sends. */
        const val FRAMES_PER_PEER = 3

        /** The longest pause between two random drops, so that some frames arrive while connected. */
        const val MAX_DROP_PAUSE_NANOS = 200_000L

        /** How many listeners start and close while a peer connects. */
        const val STRESS_LISTENERS = 50

        /** A handshake deadline no test outlives. */
        const val LONG_HANDSHAKE_DEADLINE_MS = 60_000L

        /** The frames a stream connection's lane runs in: its writes and its close. */
        val CONNECTION_LANE_CLASS = StreamRelayListener::class.java.name + "\$StreamConnection"
    }

    /** A context that offers no system service, so nothing is advertised. */
    private class DummyContext : ContextWrapper(null) {
        override fun getSystemService(name: String): Any? = null

        override fun getApplicationContext(): Context = this
    }

    /** Every exception a coroutine of the listener let escape. */
    private val uncaught = CopyOnWriteArrayList<Throwable>()
    private val scope =
        CoroutineScope(SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, e -> uncaught += e })

    @After
    fun tearDown() {
        scope.cancel()
    }

    /** The thread the last started listener accepts on. */
    private lateinit var acceptor: Thread

    private fun acceptingThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .filterValues { stack ->
                stack.any { it.className == ServerSocket::class.java.name && it.methodName == "accept" }
            }.keys

    /** Starts a listener and waits until it accepts, on [acceptor]. */
    private fun listener(
        handshakeDeadlineMs: Long = NO_HANDSHAKE_DEADLINE_MS,
        onEvent: (StreamRelayEvent) -> Unit,
    ): StreamRelayListener {
        val othersAccepting = acceptingThreads()
        val listener = StreamRelayListener(DummyContext(), scope, handshakeDeadlineMs, onEvent)
        listener.start(INSTANCE_NAME, emptyMap())
        awaitCondition("the listener never accepted") { (acceptingThreads() - othersAccepting).isNotEmpty() }
        acceptor = (acceptingThreads() - othersAccepting).single()
        return listener
    }

    private fun peer(
        listener: StreamRelayListener,
        configure: Socket.() -> Unit = {},
    ): Socket =
        Socket().apply {
            configure()
            soTimeout = SOCKET_TIMEOUT_MS
            connect(InetSocketAddress(InetAddress.getLoopbackAddress(), checkNotNull(listener.port)))
        }

    private fun runningCoroutines(): List<Job> =
        scope.coroutineContext.job.children
            .filter { !it.isCompleted }
            .toList()

    /** Waits until every coroutine the listener started has ended. */
    private fun settle() =
        runBlocking {
            withTimeout(SETTLE_LIMIT_MS) {
                while (true) {
                    val running = runningCoroutines()
                    if (running.isEmpty()) break
                    running.joinAll()
                }
            }
        }

    private fun awaitCondition(
        what: String,
        condition: () -> Boolean,
    ) {
        val deadline = System.currentTimeMillis() + SETTLE_LIMIT_MS
        while (!condition()) {
            check(System.currentTimeMillis() < deadline) { what }
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    /**
     * Waits until the listener waits for the next connection, which it does
     * only after it finished with the previous one.
     */
    private fun awaitAccepting() =
        awaitCondition("the listener never went back to accepting") {
            acceptor.stackTrace.any { it.className == ServerSocket::class.java.name && it.methodName == "accept" }
        }

    /** Whether some thread is inside a stream connection's write or close. */
    private fun connectionLaneBusy(): Boolean =
        Thread.getAllStackTraces().values.any { stack ->
            stack.any { it.className.startsWith(CONNECTION_LANE_CLASS) }
        }

    /**
     * The first event of [events] that does not follow from the ones before
     * it: a connection opens, carries frames and ends, one at a time, with
     * no error; null when every event does.
     */
    private fun firstOutOfOrder(events: List<String>): Int? {
        var connected = false
        events.forEachIndexed { index, event ->
            val follows =
                when (event) {
                    CONNECTED -> !connected
                    DISCONNECTED -> connected
                    ERROR -> false
                    else -> connected
                }
            if (!follows) return index
            if (event == CONNECTED || event == DISCONNECTED) connected = event == CONNECTED
        }
        return null
    }

    private fun label(event: StreamRelayEvent): String =
        when (event) {
            StreamRelayEvent.Connected -> CONNECTED
            StreamRelayEvent.Disconnected -> DISCONNECTED
            is StreamRelayEvent.Frame -> event.data.decodeToString()
            is StreamRelayEvent.Error -> ERROR
        }

    private fun Socket.sendFrame(text: String) {
        getOutputStream().write(checkNotNull(StreamRelayFraming.encode(text.encodeToByteArray())))
    }

    /** Queues more frames than a peer that does not read can take, and waits until a write is held up. */
    private fun fillTheConnection(listener: StreamRelayListener) {
        repeat(QUEUED_FRAMES) { listener.send(frame(it)) }
        awaitCondition("no write was held up") { connectionLaneBusy() }
    }

    /** One full-size synthetic frame, its text naming its place in the sequence. */
    private fun frame(index: Int): ByteArray {
        val text = "frame $index "
        return String(CharArray(FRAME_BYTES) { text[it % text.length] }).encodeToByteArray()
    }

    @Test
    fun aConnectionItsConnectedHandlerDropsEndsQuietly() {
        lateinit var listener: StreamRelayListener
        listener = listener { if (it == StreamRelayEvent.Connected) listener.disconnectClient() }
        try {
            peer(listener).use { socket ->
                assertEquals(END_OF_STREAM, socket.getInputStream().read())
            }
            awaitAccepting()
            awaitCondition("the dropped connection's coroutines never ended") {
                runningCoroutines().size == ACCEPT_LOOP_ONLY
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun aConnectionClosedUnderItsReadLoopEndsQuietly() {
        val received = CountDownLatch(1)
        val ends = CopyOnWriteArrayList<StreamRelayEvent>()
        val listener =
            listener { event ->
                when (event) {
                    is StreamRelayEvent.Frame -> {
                        received.countDown()
                    }

                    StreamRelayEvent.Disconnected, is StreamRelayEvent.Error -> {
                        ends += event
                    }

                    StreamRelayEvent.Connected -> {}
                }
            }
        try {
            peer(listener).use { socket ->
                socket.getOutputStream().write(checkNotNull(StreamRelayFraming.encode(frame(0))))
                assertTrue(received.await(EVENT_WAIT_SECONDS, TimeUnit.SECONDS))

                listener.close()

                assertEquals(END_OF_STREAM, socket.getInputStream().read())
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(emptyList<StreamRelayEvent>(), ends.toList())
        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun withdrawingEndsAcceptingWithoutAnError() {
        val events = CopyOnWriteArrayList<String>()
        val listener = listener { events += label(it) }
        try {
            listener.withdraw(emptyMap())
            settle()
        } finally {
            listener.close()
        }

        assertEquals(emptyList<String>(), events.toList())
        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun sendsReturnAtOnceAndLeaveInOrderBeforeTheConnectionCloses() {
        val connected = CountDownLatch(1)
        val listener = listener { if (it == StreamRelayEvent.Connected) connected.countDown() }
        val frames = List(QUEUED_FRAMES, ::frame)
        try {
            peer(listener) { receiveBufferSize = PEER_RECEIVE_BUFFER_BYTES }.use { socket ->
                assertTrue(connected.await(EVENT_WAIT_SECONDS, TimeUnit.SECONDS))

                // The peer reads nothing yet: a send that wrote on its caller's thread would wait here.
                val sender = thread { frames.forEach(listener::send) }
                sender.join(SEND_LIMIT_MS)
                assertFalse("send waited for the network", sender.isAlive)
                // The withdrawal's order: the connection drops, accepting stops, the listener closes.
                listener.disconnectClient()
                listener.withdraw(emptyMap())
                listener.close()

                val input = DataInputStream(socket.getInputStream())
                for (expected in frames) {
                    assertArrayEquals(expected, ByteArray(input.readUnsignedShort()).also(input::readFully))
                }
                assertEquals(END_OF_STREAM, input.read())
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun aCloseThePeerDoesNotDrainEndsWithinTheBound() {
        val connected = CountDownLatch(1)
        val listener = listener { if (it == StreamRelayEvent.Connected) connected.countDown() }
        try {
            peer(listener) { receiveBufferSize = PEER_RECEIVE_BUFFER_BYTES }.use {
                assertTrue(connected.await(EVENT_WAIT_SECONDS, TimeUnit.SECONDS))
                fillTheConnection(listener)

                val droppedAtMs = System.currentTimeMillis()
                listener.disconnectClient()

                awaitCondition("the dropped connection's write or read never ended") {
                    runningCoroutines().size == ACCEPT_LOOP_ONLY && !connectionLaneBusy()
                }
                assertTrue(System.currentTimeMillis() - droppedAtMs >= StreamRelayListener.CLOSE_DRAIN_BOUND_MS)
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun aDroppedConnectionsFramesAreNeverDelivered() {
        val events = CopyOnWriteArrayList<String>()
        val listener = listener { events += label(it) }
        try {
            peer(listener) { receiveBufferSize = PEER_RECEIVE_BUFFER_BYTES }.use { peerA ->
                awaitCondition("peer A never connected") { events == listOf(CONNECTED) }
                // Frames queued for peer A keep its socket open after the drop.
                fillTheConnection(listener)
                listener.disconnectClient()

                peerA.sendFrame(FROM_A)
                awaitCondition("peer A's reads never ended") {
                    (runningCoroutines().size == ACCEPT_LOOP_ONLY && DISCONNECTED in events) || FROM_A in events
                }
                assertEquals(listOf(CONNECTED, DISCONNECTED), events.toList())

                peer(listener).use { peerB ->
                    awaitCondition("peer B never connected") { events == listOf(CONNECTED, DISCONNECTED, CONNECTED) }
                    runCatching { peerA.sendFrame(FROM_A_LATE) }
                    peerB.sendFrame(FROM_B)
                    awaitCondition("peer B's frame never arrived") { FROM_B in events }
                }
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(listOf(CONNECTED, DISCONNECTED, CONNECTED, FROM_B), events.toList())
        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun aReadFailureStillWritesTheFramesQueuedBeforeIt() {
        val disconnected = CountDownLatch(1)
        val connected = CountDownLatch(1)
        val listener =
            listener { event ->
                if (event == StreamRelayEvent.Connected) connected.countDown()
                if (event == StreamRelayEvent.Disconnected) disconnected.countDown()
            }
        val frames = List(QUEUED_FRAMES, ::frame)
        try {
            peer(listener) { receiveBufferSize = PEER_RECEIVE_BUFFER_BYTES }.use { socket ->
                assertTrue(connected.await(EVENT_WAIT_SECONDS, TimeUnit.SECONDS))
                frames.forEach(listener::send)
                awaitCondition("no write was held up") { connectionLaneBusy() }

                DataOutputStream(socket.getOutputStream()).writeShort(EMPTY_FRAME_LENGTH)
                assertTrue(disconnected.await(EVENT_WAIT_SECONDS, TimeUnit.SECONDS))

                val input = DataInputStream(socket.getInputStream())
                for (expected in frames) {
                    assertArrayEquals(expected, ByteArray(input.readUnsignedShort()).also(input::readFully))
                }
                assertEquals(END_OF_STREAM, input.read())
            }
        } finally {
            listener.close()
        }
        settle()

        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun eventsFollowTheConnectionsInOrderWhileTheyAreDroppedAtRandom() {
        val events = CopyOnWriteArrayList<String>()
        val listener = listener { events += label(it) }
        val dropping = AtomicBoolean(true)
        val dropper =
            thread {
                val random = Random()
                while (dropping.get()) {
                    listener.disconnectClient()
                    LockSupport.parkNanos(random.nextLong(MAX_DROP_PAUSE_NANOS))
                }
            }
        try {
            repeat(STRESS_PEERS) { index ->
                peer(listener).use { socket ->
                    repeat(FRAMES_PER_PEER) { runCatching { socket.sendFrame("$FROM_A $index") } }
                }
            }
        } finally {
            dropping.set(false)
            dropper.join()
        }
        awaitCondition("the last connection's coroutines never ended") { runningCoroutines().size == ACCEPT_LOOP_ONLY }
        listener.close()
        settle()

        assertTrue("no connection was taken", CONNECTED in events)
        val delivered = events.toList()
        assertEquals("events out of order: $delivered", null, firstOutOfOrder(delivered))
        assertEquals(emptyList<Throwable>(), uncaught)
    }

    @Test
    fun aClosedListenerLeavesNoHandshakeDeadlineRunning() {
        repeat(STRESS_LISTENERS) {
            val listener = StreamRelayListener(DummyContext(), scope, LONG_HANDSHAKE_DEADLINE_MS) {}
            listener.start(INSTANCE_NAME, emptyMap())
            peer(listener).use { listener.close() }
        }
        settle()

        assertEquals(emptyList<Throwable>(), uncaught)
    }
}
