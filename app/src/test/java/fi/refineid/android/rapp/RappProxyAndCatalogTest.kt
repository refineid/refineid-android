// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber", "EmptyFunctionBlock", "MaxLineLength")

package fi.refineid.android.rapp

import android.content.SharedPreferences
import fi.refineid.android.trust.CaCertificateStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.concurrent.TimeUnit

class RappProxyAndCatalogTest {
    @Test
    fun decodeHexOrNullReturnsNullOnEmptyString() {
        assertNull(RappPairingModel.decodeHexOrNull(""))
    }

    @Test
    fun decodeHexOrNullReturnsNullOnOddLength() {
        assertNull(RappPairingModel.decodeHexOrNull("abc"))
        assertNull(RappPairingModel.decodeHexOrNull("1"))
    }

    @Test
    fun decodeHexOrNullReturnsNullOnInvalidCharacters() {
        assertNull(RappPairingModel.decodeHexOrNull("zz"))
        assertNull(RappPairingModel.decodeHexOrNull("1g"))
        assertNull(RappPairingModel.decodeHexOrNull("deadbeefzz"))
    }

    @Test
    fun decodeHexOrNullParsesValidHexBytes() {
        assertArrayEquals(byteArrayOf(0x00), RappPairingModel.decodeHexOrNull("00"))
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0x0a, 0x0f), RappPairingModel.decodeHexOrNull("01020a0f"))
        assertArrayEquals(
            byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte()),
            RappPairingModel.decodeHexOrNull("deadbeef"),
        )
        assertArrayEquals(
            byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte()),
            RappPairingModel.decodeHexOrNull("CAFEBABE"),
        )
    }

    @Test
    fun pairCatalogSavesAndRetrievesPeersWithAllFields() {
        val prefs = FakeSharedPreferences()
        val catalog = RappPairCatalog(prefs)

        assertTrue(catalog.listPairs().isEmpty())

        val pairId = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val certDer = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00)
        catalog.savePair(
            pairId = pairId,
            displayName = "MacBook Pro",
            platform = "macOS",
            createdAtMs = 123456789L,
            holderName = "Alice",
            certificateDerBase64 = "MIIBAA==",
        )

        val pairs = catalog.listPairs()
        assertEquals(1, pairs.size)
        val peer = pairs.first()
        assertEquals("01020304", peer.pairIdHex)
        assertEquals("MacBook Pro", peer.displayName)
        assertEquals("macOS", peer.platform)
        assertEquals(123456789L, peer.createdAtMs)
        assertEquals("Alice", peer.holderName)
        assertEquals("MIIBAA==", peer.certificateDerBase64)

        // Update holder name
        catalog.updateHolderName("01020304", "Alice Smith")
        val updatedName = catalog.listPairs().first()
        assertEquals("Alice Smith", updatedName.holderName)

        // Update certificate DER
        catalog.updateCertificateDer("01020304", certDer)
        val updatedCert = catalog.listPairs().first()
        val expectedBase64 =
            java.util.Base64
                .getEncoder()
                .encodeToString(certDer)
        assertEquals(expectedBase64, updatedCert.certificateDerBase64)

        // Remove pair
        catalog.removePair("01020304")
        assertTrue(catalog.listPairs().isEmpty())

        // Save again and clearAll
        catalog.savePair(
            pairId = pairId,
            displayName = "MacBook Pro",
            platform = "macOS",
            createdAtMs = 123456789L,
        )
        assertEquals(1, catalog.listPairs().size)
        catalog.clearAll()
        assertTrue(catalog.listPairs().isEmpty())
    }

    @Test
    fun caCertificateStoreRejectsLeafAndAcceptsCaCertificates() {
        val openssl = findExecutable(OPENSSL_EXECUTABLE_NAME)
        assumeTrue("OpenSSL required for CA store test", openssl != null)
        val tempDir = Files.createTempDirectory("test-ca-store")
        try {
            val env = CaStoreTestEnvironment(checkNotNull(openssl), tempDir)
            env.generate()

            val rootDer = Files.readAllBytes(tempDir.resolve("root.der"))
            val intermediateDer = Files.readAllBytes(tempDir.resolve("intermediate.der"))
            val leafDer = Files.readAllBytes(tempDir.resolve("leaf.der"))

            val storeDir = tempDir.resolve("store-dir").toFile()
            storeDir.mkdirs()
            val store = CaCertificateStore(baseDirectory = storeDir)
            store.load()

            // Leaf certificate must be rejected because basicConstraints < 0
            val leafSaved = store.saveCertificate(leafDer)
            assertFalse("Leaf certificate must not be saved to CA store", leafSaved)
            assertNull(store.rootCaDer)
            assertNull(store.intermediateCaDer)

            // Intermediate CA must be accepted
            val intermediateSaved = store.saveCertificate(intermediateDer)
            assertTrue("Intermediate CA should be saved", intermediateSaved)
            assertNotNull("Intermediate CA should be recorded", store.intermediateCaDer)
            assertNull("Root CA not yet recorded", store.rootCaDer)

            // Root CA must be accepted and recognized as root (self-signed)
            val rootSaved = store.saveCertificate(rootDer)
            assertTrue("Root CA should be saved", rootSaved)
            assertNotNull("Root CA recorded", store.rootCaDer)

            // Verify issuer lookup for leaf
            assertTrue("Store should find issuer for leaf", store.hasIssuerFor(leafDer))
            val copiedIssuer = store.copyIssuerCertificate(leafDer)
            assertNotNull(copiedIssuer)
            assertArrayEquals(intermediateDer, copiedIssuer)

            // Verify persistence and reloading from disk
            val reloadedStore = CaCertificateStore(baseDirectory = storeDir)
            reloadedStore.load()
            assertTrue("Reloaded store should recognize issuer for leaf", reloadedStore.hasIssuerFor(leafDer))
            assertNotNull("Reloaded store has root CA", reloadedStore.rootCaDer)
            assertNotNull("Reloaded store has intermediate CA", reloadedStore.intermediateCaDer)
        } finally {
            Files.walk(tempDir).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun findExecutable(name: String): Path? =
        listOf("/usr/bin", "/usr/local/bin", "/opt/homebrew/bin")
            .asSequence()
            .map { dir -> Path.of(dir, name) }
            .firstOrNull(Files::isExecutable)

    private class CaStoreTestEnvironment(
        private val openssl: Path,
        private val directory: Path,
    ) {
        fun generate() {
            // 1. Root CA: self-signed, CA:TRUE, keyCertSign
            run(
                listOf(
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-pkeyopt",
                    "ec_param_enc:named_curve",
                    "-sha384",
                    "-days",
                    "30",
                    "-nodes",
                    "-subj",
                    "/CN=Test Root CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign",
                    "-keyout",
                    "root.key",
                    "-out",
                    "root.pem",
                ),
            )
            convert("root.pem", "root.der")

            // 2. Intermediate CA: CSR signed by Root CA, CA:TRUE, keyCertSign
            Files.writeString(
                directory.resolve("intermediate.ext"),
                "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n",
            )
            run(
                listOf(
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-pkeyopt",
                    "ec_param_enc:named_curve",
                    "-nodes",
                    "-subj",
                    "/CN=Test Intermediate CA",
                    "-keyout",
                    "intermediate.key",
                    "-out",
                    "intermediate.csr",
                ),
            )
            run(
                listOf(
                    "x509",
                    "-req",
                    "-in",
                    "intermediate.csr",
                    "-CA",
                    "root.pem",
                    "-CAkey",
                    "root.key",
                    "-CAcreateserial",
                    "-sha384",
                    "-days",
                    "30",
                    "-extfile",
                    "intermediate.ext",
                    "-out",
                    "intermediate.pem",
                ),
            )
            convert("intermediate.pem", "intermediate.der")

            // 3. Leaf certificate: CSR signed by Intermediate CA, basicConstraints CA:FALSE, digitalSignature
            Files.writeString(
                directory.resolve("leaf.ext"),
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n",
            )
            run(
                listOf(
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-pkeyopt",
                    "ec_param_enc:named_curve",
                    "-nodes",
                    "-subj",
                    "/CN=Test Leaf",
                    "-keyout",
                    "leaf.key",
                    "-out",
                    "leaf.csr",
                ),
            )
            run(
                listOf(
                    "x509",
                    "-req",
                    "-in",
                    "leaf.csr",
                    "-CA",
                    "intermediate.pem",
                    "-CAkey",
                    "intermediate.key",
                    "-CAcreateserial",
                    "-sha384",
                    "-days",
                    "30",
                    "-extfile",
                    "leaf.ext",
                    "-out",
                    "leaf.pem",
                ),
            )
            convert("leaf.pem", "leaf.der")
        }

        private fun convert(
            input: String,
            output: String,
        ) {
            run(listOf("x509", "-in", input, "-outform", "DER", "-out", output))
        }

        private fun run(args: List<String>) {
            val process =
                ProcessBuilder(listOf(openssl.toString()) + args)
                    .directory(directory.toFile())
                    .redirectErrorStream(true)
                    .start()
            val output = process.inputStream.bufferedReader().readText()
            val completed = process.waitFor(15, TimeUnit.SECONDS)
            check(completed && process.exitValue() == 0) {
                "OpenSSL command failed: $args\nOutput: $output"
            }
        }
    }

    private class FakeSharedPreferences : SharedPreferences {
        val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = HashMap(data)

        override fun getString(
            key: String?,
            defValue: String?,
        ): String? = data[key] as? String ?: defValue

        override fun getStringSet(
            key: String?,
            defValues: MutableSet<String>?,
        ): MutableSet<String>? = (data[key] as? Set<*>)?.filterIsInstance<String>()?.toMutableSet() ?: defValues

        override fun getInt(
            key: String?,
            defValue: Int,
        ): Int = data[key] as? Int ?: defValue

        override fun getLong(
            key: String?,
            defValue: Long,
        ): Long = data[key] as? Long ?: defValue

        override fun getFloat(
            key: String?,
            defValue: Float,
        ): Float = data[key] as? Float ?: defValue

        override fun getBoolean(
            key: String?,
            defValue: Boolean,
        ): Boolean = data[key] as? Boolean ?: defValue

        override fun contains(key: String?): Boolean = data.containsKey(key)

        override fun edit(): SharedPreferences.Editor = Editor(this)

        override fun registerOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?,
        ) = Unit

        override fun unregisterOnSharedPreferenceChangeListener(
            listener: SharedPreferences.OnSharedPreferenceChangeListener?,
        ) = Unit

        class Editor(
            private val prefs: FakeSharedPreferences,
        ) : SharedPreferences.Editor {
            private val temp = mutableMapOf<String, Any?>()
            private val removed = mutableSetOf<String>()
            private var clear = false

            override fun putString(
                key: String?,
                value: String?,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            value
                    }
                }

            override fun putStringSet(
                key: String?,
                values: MutableSet<String>?,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            values
                    }
                }

            override fun putInt(
                key: String?,
                value: Int,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            value
                    }
                }

            override fun putLong(
                key: String?,
                value: Long,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            value
                    }
                }

            override fun putFloat(
                key: String?,
                value: Float,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            value
                    }
                }

            override fun putBoolean(
                key: String?,
                value: Boolean,
            ): SharedPreferences.Editor =
                apply {
                    key?.let {
                        temp[it] =
                            value
                    }
                }

            override fun remove(key: String?): SharedPreferences.Editor = apply { key?.let { removed.add(it) } }

            override fun clear(): SharedPreferences.Editor = apply { clear = true }

            override fun commit(): Boolean {
                apply()
                return true
            }

            override fun apply() {
                if (clear) prefs.data.clear()
                removed.forEach { prefs.data.remove(it) }
                prefs.data.putAll(temp)
            }
        }
    }

    private companion object {
        const val OPENSSL_EXECUTABLE_NAME = "openssl"
    }
}
