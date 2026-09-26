// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.Context
import android.content.ContextWrapper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class StreamRelayListenerTimeoutTest {
    private class DummyContext : ContextWrapper(null) {
        override fun getSystemService(name: String): Any? = null

        override fun getApplicationContext(): Context = this
    }

    @Test
    fun handshakeTimeoutClosesSocketAndRestoresListening() {
        val scope = CoroutineScope(Dispatchers.IO)
        val disconnectedLatch = CountDownLatch(1)
        val connectedLatch1 = CountDownLatch(1)
        val connectedLatch2 = CountDownLatch(1)

        val timeoutMs = 200L
        val listener =
            StreamRelayListener(
                context = DummyContext(),
                scope = scope,
                handshakeTimeoutMs = timeoutMs,
            ) { event ->
                if (event is StreamRelayEvent.Connected) {
                    if (connectedLatch1.count > 0L) {
                        connectedLatch1.countDown()
                    } else {
                        connectedLatch2.countDown()
                    }
                } else if (event is StreamRelayEvent.Disconnected) {
                    disconnectedLatch.countDown()
                }
            }

        try {
            listener.start("test-listener")
            val port = listener.port
            assertTrue("Listener must have bound to a port", port != null && port > 0)

            // 1. Client connects but sends nothing (stalling unauthenticated peer)
            val socket1 = Socket(InetAddress.getLoopbackAddress(), port!!)
            assertTrue("First peer connected", connectedLatch1.await(5, TimeUnit.SECONDS))

            // 2. Wait for the handshake timeout to fire, close the socket, and report Disconnected
            assertTrue(
                "Disconnected event must fire on handshake timeout",
                disconnectedLatch.await(5, TimeUnit.SECONDS),
            )

            // Verify socket1 reached EOF after listener closed it
            val readResult = socket1.getInputStream().read()
            assertEquals("Socket stream should reach EOF after server closed it", -1, readResult)
            socket1.close()

            // 3. Verify listening is restored: a second peer connects to the SAME listener and is accepted
            val socket2 = Socket(InetAddress.getLoopbackAddress(), port)
            assertTrue("Second peer connected and accepted", connectedLatch2.await(5, TimeUnit.SECONDS))
            socket2.close()
        } finally {
            listener.close()
            scope.cancel()
        }
    }
}
