// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.network

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsExchange
import com.sun.net.httpserver.HttpsServer
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName

class SigningNetworkTlsTest {
    @Test
    fun pinsBothEndpointKindsWithoutReresolvingWhilePreservingTlsIdentityAndSni() {
        for (endpoint in SigningNetworkEndpoint.entries) {
            withServer { server, client, receivedName ->
                val destinations = mutableListOf<InetAddress>()
                var resolutions = NO_RESOLUTIONS
                val network =
                    HttpSigningNetwork(
                        resolver =
                            SigningNetworkResolver {
                                resolutions += ONE_RESOLUTION
                                if (resolutions == ONE_RESOLUTION) {
                                    listOf(LoopbackSigningSocketFactory.PUBLIC_ADDRESS)
                                } else {
                                    listOf(InetAddress.getLoopbackAddress())
                                }
                            },
                        client =
                            client
                                .newBuilder()
                                .socketFactory(
                                    LoopbackSigningSocketFactory(destinations),
                                ).build(),
                    )
                assertArrayEquals(
                    RESPONSE,
                    network.get(address(server), RESPONSE.size, endpoint),
                )
                assertEquals(ONE_RESOLUTION, resolutions)
                assertEquals(listOf(LoopbackSigningSocketFactory.PUBLIC_ADDRESS), destinations)
                assertEquals(HOST, receivedName.get())
            }
        }
    }

    @Test
    fun rejectsTlsCertificateForAnotherLogicalHost() {
        withServer { server, client, _ ->
            val network =
                HttpSigningNetwork(
                    resolver = SigningNetworkResolver { listOf(LoopbackSigningSocketFactory.PUBLIC_ADDRESS) },
                    client = client.newBuilder().socketFactory(LoopbackSigningSocketFactory()).build(),
                )
            val failure =
                assertThrows(SigningNetworkException::class.java) {
                    network.get(address(server, OTHER_HOST), RESPONSE.size, SigningNetworkEndpoint.AUTHORITY)
                }
            assertEquals(SigningNetworkFailure.TRANSPORT, failure.kind)
        }
    }

    @Test
    fun refusesAuthorityPrivateDnsAndDirectPrivateUrlsBeforeConnecting() {
        val destinations = mutableListOf<InetAddress>()
        val network =
            HttpSigningNetwork(
                resolver = SigningNetworkResolver { listOf(InetAddress.getLoopbackAddress()) },
                client = OkHttpClient.Builder().socketFactory(LoopbackSigningSocketFactory(destinations)).build(),
            )
        for (address in listOf("https://$HOST/request", "http://127.0.0.1/request", "https://localhost/request")) {
            val failure =
                assertThrows(SigningNetworkException::class.java) {
                    network.get(address, RESPONSE.size, SigningNetworkEndpoint.AUTHORITY)
                }
            assertEquals(SigningNetworkFailure.UNSAFE_ADDRESS, failure.kind)
        }
        assertTrue(destinations.isEmpty())
    }

    private fun address(
        server: HttpsServer,
        host: String = HOST,
    ): String = "https://$host:${server.address.port}/request"

    private fun withServer(operation: (HttpsServer, OkHttpClient, AtomicReference<String?>) -> Unit) {
        val certificate =
            HeldCertificate
                .Builder()
                .commonName(HOST)
                .addSubjectAlternativeName(HOST)
                .build()
        val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientCertificates = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val client =
            OkHttpClient
                .Builder()
                .sslSocketFactory(clientCertificates.sslSocketFactory(), clientCertificates.trustManager)
                .build()
        val name = AtomicReference<String?>()
        val server =
            HttpsServer.create(
                InetSocketAddress(InetAddress.getLoopbackAddress(), EPHEMERAL_PORT),
                DEFAULT_BACKLOG,
            )
        server.httpsConfigurator = HttpsConfigurator(serverCertificates.sslContext())
        server.createContext("/request") { exchange ->
            val session = (exchange as HttpsExchange).sslSession as ExtendedSSLSession
            name.set((session.requestedServerNames.single() as SNIHostName).asciiName)
            exchange.sendResponseHeaders(SUCCESS_STATUS, RESPONSE.size.toLong())
            exchange.responseBody.use { it.write(RESPONSE) }
            exchange.close()
        }
        server.start()
        try {
            operation(server, client, name)
        } finally {
            server.stop(IMMEDIATE_STOP)
            client.connectionPool.evictAll()
        }
    }

    private companion object {
        const val HOST = "timestamp.example"
        const val OTHER_HOST = "other.example"
        const val NO_RESOLUTIONS = 0
        const val ONE_RESOLUTION = 1
        const val EPHEMERAL_PORT = 0
        const val DEFAULT_BACKLOG = 0
        const val SUCCESS_STATUS = 200
        const val IMMEDIATE_STOP = 0
        val RESPONSE = "synthetic-response".encodeToByteArray()
    }
}
