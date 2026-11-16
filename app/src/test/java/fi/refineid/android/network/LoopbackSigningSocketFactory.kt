// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import javax.net.SocketFactory

/** Records the numeric destination before routing a hermetic test socket to its local server. */
internal class LoopbackSigningSocketFactory(
    private val destinations: MutableList<InetAddress> = mutableListOf(),
) : SocketFactory() {
    override fun createSocket(): Socket =
        object : Socket() {
            override fun connect(
                endpoint: SocketAddress,
                timeout: Int,
            ) {
                val destination = endpoint as InetSocketAddress
                destinations += checkNotNull(destination.address)
                super.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), destination.port), timeout)
            }
        }

    override fun createSocket(
        host: String,
        port: Int,
    ): Socket = throw AssertionError("unexpected hostname resolution")

    override fun createSocket(
        host: String,
        port: Int,
        local: InetAddress,
        localPort: Int,
    ): Socket = throw AssertionError("unexpected hostname resolution")

    override fun createSocket(
        host: InetAddress,
        port: Int,
    ): Socket = throw AssertionError("unexpected connected socket")

    override fun createSocket(
        host: InetAddress,
        port: Int,
        local: InetAddress,
        localPort: Int,
    ): Socket = throw AssertionError("unexpected connected socket")

    companion object {
        val PUBLIC_ADDRESS: InetAddress = checkNotNull(SigningNetworkAddressPolicy.numericAddress("8.8.8.8"))
    }
}
