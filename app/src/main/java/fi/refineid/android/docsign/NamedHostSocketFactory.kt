// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * TLS over a connection made to an address literal, naming [host] in the
 * handshake. The platform connects the plain socket to the vetted address
 * and layers TLS over it here; the layer is created for [host], whatever
 * name the platform passes, so the server-name indication carries it.
 * Opening a socket by name is refused, since that resolves the name.
 * Certificate trust stays with [delegate]; the host name check is the
 * connection's verifier.
 */
internal class NamedHostSocketFactory(
    private val delegate: SSLSocketFactory,
    private val host: String,
) : SSLSocketFactory() {
    /** [host] as a server name; null for an address literal, which TLS does not name. */
    private val serverName: SNIHostName? =
        try {
            SNIHostName(host)
        } catch (_: IllegalArgumentException) {
            null
        }

    override fun createSocket(
        socket: Socket,
        ignoredHost: String?,
        port: Int,
        autoClose: Boolean,
    ): Socket = named(delegate.createSocket(socket, host, port, autoClose))

    /** Refused: connecting by name would resolve it again. */
    override fun createSocket(
        ignoredHost: String?,
        port: Int,
    ): Socket = throw SocketException(BY_NAME_REFUSED)

    /** Refused: connecting by name would resolve it again. */
    override fun createSocket(
        ignoredHost: String?,
        port: Int,
        localAddress: InetAddress?,
        localPort: Int,
    ): Socket = throw SocketException(BY_NAME_REFUSED)

    override fun createSocket(
        address: InetAddress,
        port: Int,
    ): Socket = named(delegate.createSocket(address, port))

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress?,
        localPort: Int,
    ): Socket = named(delegate.createSocket(address, port, localAddress, localPort))

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    private fun named(socket: Socket): Socket {
        val name = serverName
        if (socket is SSLSocket && name != null) {
            val parameters = socket.sslParameters
            parameters.serverNames = listOf(name)
            socket.sslParameters = parameters
        }
        return socket
    }

    private companion object {
        const val BY_NAME_REFUSED = "a vetted connection never connects by name"
    }
}
