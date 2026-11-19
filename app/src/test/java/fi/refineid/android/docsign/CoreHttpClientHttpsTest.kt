// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.docsign

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.refineid_doc_sign_android.HttpFailure
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.net.URL
import java.security.cert.Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocketFactory

/**
 * HTTPS to a certificate-published host connects to the address the core
 * vetted, never to a fresh answer for the name, and still speaks to the
 * name: the TLS layer is made for it and the certificate is checked
 * against it.
 */
class CoreHttpClientHttpsTest {
    private val opened = mutableListOf<RecordingConnection>()
    private val vetted = mutableListOf<String>()
    private val verifiedNames = mutableListOf<String>()

    private fun client(
        refuseFirstConnect: Boolean = false,
        redirectTo: String? = null,
        vetAnswer: List<String> = listOf(REDIRECT_VETTED_ADDRESS),
    ) = CoreHttpClient(
        connectionFactory = { uri ->
            val refuse = refuseFirstConnect && opened.isEmpty()
            val location = redirectTo.takeIf { opened.isEmpty() }
            RecordingConnection(uri, refuse, location).also(opened::add)
        },
        vet = { target ->
            vetted += target
            vetAnswer
        },
        authorityRedirect = { _, _ -> false },
        hostnameVerifier =
            HostnameVerifier { name, _ ->
                verifiedNames += name
                true
            },
    )

    @Test
    fun theConnectionGoesToTheVettedAddressAndNamesTheHost() {
        val body = client().get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)

        assertArrayEquals(RESPONSE, body)
        val connection = opened.single()
        assertEquals(VETTED_ADDRESS, connection.target.host)
        assertEquals(PUBLISHED_PATH, connection.target.rawPath)
        assertEquals(PUBLISHED_HOST, connection.headers[HOST_HEADER])
        assertTrue(vetted.isEmpty())
    }

    @Test
    fun theTlsLayerIsMadeForTheNameAndTheCertificateCheckedAgainstIt() {
        client().get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)
        val connection = opened.single()

        val factory = connection.sslSocketFactory
        assertTrue(factory is NamedHostSocketFactory)
        val layering = RecordingSocketFactory()
        val named = NamedHostSocketFactory(layering, PUBLISHED_HOST)
        named.createSocket(Socket(), VETTED_ADDRESS, HTTPS_PORT, true)
        assertEquals(listOf(PUBLISHED_HOST), layering.layeredHosts)

        assertTrue(connection.hostnameVerifier.verify(VETTED_ADDRESS, null))
        assertEquals(listOf(PUBLISHED_HOST), verifiedNames)
    }

    @Test
    fun theNamedFactoryNeverConnectsByName() {
        val named = NamedHostSocketFactory(RecordingSocketFactory(), PUBLISHED_HOST)
        assertThrows(SocketException::class.java) { named.createSocket(PUBLISHED_HOST, HTTPS_PORT) }
        assertThrows(SocketException::class.java) {
            named.createSocket(PUBLISHED_HOST, HTTPS_PORT, InetAddress.getLoopbackAddress(), ANY_LOCAL_PORT)
        }
    }

    @Test
    fun aRefusedAddressFallsToTheNextVettedOne() {
        client(refuseFirstConnect = true).get(PUBLISHED_URL, listOf(VETTED_ADDRESS, SECOND_VETTED_ADDRESS), BOUND)

        assertEquals(listOf(VETTED_ADDRESS, SECOND_VETTED_ADDRESS), opened.map { it.target.host })
    }

    @Test
    fun aRedirectIsVettedAgainAndConnectsToWhatTheVetReturns() {
        client(redirectTo = REDIRECT_URL).get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)

        assertEquals(listOf(REDIRECT_URL), vetted)
        val redirected = opened.last()
        assertEquals(REDIRECT_VETTED_ADDRESS, redirected.target.host)
        assertEquals(REDIRECT_HOST, redirected.headers[HOST_HEADER])
        assertTrue(redirected.sslSocketFactory is NamedHostSocketFactory)
    }

    @Test
    fun aNameInPlaceOfAnAddressIsRefusedBeforeAnyConnection() {
        assertThrows(HttpFailure.BadUrl::class.java) {
            client().get(PUBLISHED_URL, listOf(PUBLISHED_HOST), BOUND)
        }
        assertTrue(opened.isEmpty())
    }

    @Test
    fun aConnectionWithoutTlsControlCannotCarryAVettedHttpsRequest() {
        val plain =
            CoreHttpClient(
                connectionFactory = { URL(PLAIN_URL).openConnection() as HttpURLConnection },
                vet = { emptyList() },
            )
        val failure =
            assertThrows(HttpFailure.Transport::class.java) {
                plain.get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)
            }
        assertEquals(false, failure.retryable)
    }

    @Test
    fun aPostConfiguresItsBodyBeforeConnectingAndSendsIt() {
        client().post(PUBLISHED_URL, listOf(VETTED_ADDRESS), CONTENT_TYPE, REQUEST, BOUND)

        val connection = opened.single()
        assertArrayEquals(REQUEST, connection.sent.toByteArray())
        assertEquals(CONTENT_TYPE, connection.headers[CONTENT_TYPE_HEADER])
    }

    @Test
    fun noVettedAddressIsAnUnsafeDestinationAndNothingConnects() {
        assertThrows(HttpFailure.UnsafeDestination::class.java) {
            client().get(PUBLISHED_URL, emptyList(), BOUND)
        }
        assertThrows(HttpFailure.UnsafeDestination::class.java) {
            client().post(PLAIN_URL, emptyList(), CONTENT_TYPE, REQUEST, BOUND)
        }
        assertTrue(opened.isEmpty())
    }

    @Test
    fun aRedirectTheCoreDoesNotVetIsAnUnsafeDestination() {
        assertThrows(HttpFailure.UnsafeDestination::class.java) {
            client(redirectTo = REDIRECT_URL, vetAnswer = emptyList()).get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)
        }
        assertEquals(1, opened.size)
    }

    @Test
    fun anUncheckedFailureLeavesAsATransportFailure() {
        val failing =
            CoreHttpClient(
                connectionFactory = { throw IllegalStateException("platform fault") },
                vet = { emptyList() },
            )
        val failure =
            assertThrows(HttpFailure.Transport::class.java) {
                failing.get(PUBLISHED_URL, listOf(VETTED_ADDRESS), BOUND)
            }
        assertEquals(false, failure.retryable)
    }

    /** An HTTPS connection that records what the client set and answers from memory. */
    private class RecordingConnection(
        val target: URI,
        private val refuseConnect: Boolean,
        private val location: String?,
    ) : HttpsURLConnection(URL(target.toString())) {
        val headers = mutableMapOf<String, String>()
        val sent = ByteArrayOutputStream()
        private var factory: SSLSocketFactory = RecordingSocketFactory()
        private var verifier: HostnameVerifier = HostnameVerifier { _, _ -> false }

        override fun setRequestProperty(
            key: String,
            value: String,
        ) {
            headers[key] = value
        }

        override fun setSSLSocketFactory(sf: SSLSocketFactory) {
            factory = sf
        }

        override fun getSSLSocketFactory(): SSLSocketFactory = factory

        override fun setHostnameVerifier(v: HostnameVerifier) {
            verifier = v
        }

        override fun getHostnameVerifier(): HostnameVerifier = verifier

        override fun setDoOutput(dooutput: Boolean) {
            check(!connected) { ALREADY_CONNECTED }
            super.setDoOutput(dooutput)
        }

        override fun setFixedLengthStreamingMode(contentLength: Int) {
            check(!connected) { ALREADY_CONNECTED }
            super.setFixedLengthStreamingMode(contentLength)
        }

        override fun getOutputStream(): OutputStream {
            check(doOutput) { "output was not configured" }
            return sent
        }

        override fun connect() {
            if (refuseConnect) {
                throw ConnectException("refused")
            }
            connected = true
        }

        override fun getResponseCode(): Int = if (location != null) TEMPORARY_REDIRECT_STATUS else OK_STATUS

        override fun getHeaderField(name: String?): String? = location.takeIf { name == LOCATION_HEADER }

        override fun getContentLengthLong(): Long = RESPONSE.size.toLong()

        override fun getInputStream(): InputStream = ByteArrayInputStream(RESPONSE)

        override fun disconnect() {
            connected = false
        }

        override fun usingProxy(): Boolean = false

        override fun getCipherSuite(): String = throw IOException("no session")

        override fun getLocalCertificates(): Array<Certificate> = emptyArray()

        override fun getServerCertificates(): Array<Certificate> = emptyArray()
    }

    /** A TLS factory that records the host each layered socket is made for. */
    private class RecordingSocketFactory : SSLSocketFactory() {
        val layeredHosts = mutableListOf<String?>()

        override fun createSocket(
            socket: Socket,
            host: String?,
            port: Int,
            autoClose: Boolean,
        ): Socket {
            layeredHosts += host
            return socket
        }

        override fun createSocket(
            host: String?,
            port: Int,
        ): Socket = throw SocketException("unused")

        override fun createSocket(
            host: String?,
            port: Int,
            localAddress: InetAddress?,
            localPort: Int,
        ): Socket = throw SocketException("unused")

        override fun createSocket(
            address: InetAddress?,
            port: Int,
        ): Socket = throw SocketException("unused")

        override fun createSocket(
            address: InetAddress?,
            port: Int,
            localAddress: InetAddress?,
            localPort: Int,
        ): Socket = throw SocketException("unused")

        override fun getDefaultCipherSuites(): Array<String> = emptyArray()

        override fun getSupportedCipherSuites(): Array<String> = emptyArray()
    }

    private companion object {
        const val HTTPS_SCHEME = "https"
        const val PUBLISHED_HOST = "ocsp.example"
        const val PUBLISHED_PATH = "/responder"
        const val PUBLISHED_URL = "$HTTPS_SCHEME://$PUBLISHED_HOST$PUBLISHED_PATH"
        const val REDIRECT_HOST = "crl.example"
        const val REDIRECT_URL = "$HTTPS_SCHEME://$REDIRECT_HOST/list"

        // Documentation addresses (RFC 5737), never routed.
        const val VETTED_ADDRESS = "192.0.2.10"
        const val SECOND_VETTED_ADDRESS = "192.0.2.11"
        const val REDIRECT_VETTED_ADDRESS = "198.51.100.20"
        const val PLAIN_URL = "http://$VETTED_ADDRESS$PUBLISHED_PATH"
        const val HOST_HEADER = "Host"
        const val LOCATION_HEADER = "Location"
        const val CONTENT_TYPE_HEADER = "Content-Type"
        const val CONTENT_TYPE = "application/synthetic-request"
        const val ALREADY_CONNECTED = "Already connected"
        const val OK_STATUS = 200
        const val TEMPORARY_REDIRECT_STATUS = 307
        const val HTTPS_PORT = 443
        const val ANY_LOCAL_PORT = 0
        const val BOUND = 64UL
        val RESPONSE = "answer".encodeToByteArray()
        val REQUEST = "request".encodeToByteArray()
    }
}
