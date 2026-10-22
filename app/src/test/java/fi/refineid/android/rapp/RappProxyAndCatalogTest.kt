// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

@file:Suppress("MagicNumber", "EmptyFunctionBlock", "MaxLineLength")
@file:OptIn(ExperimentalStdlibApi::class)

package fi.refineid.android.rapp

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
    fun pairCatalogSavesAndRetrievesPeersWithAllFields() {
        val catalog = RappPairCatalog(FakeSharedPreferences())
        assertTrue(catalog.listPairs().isEmpty())

        val pairId = PAIR_ID_TEXT.encodeToByteArray()
        val pairIdHex = pairId.toHexString()
        val certDer = CERTIFICATE_TEXT.encodeToByteArray()
        catalog.savePair(
            pairId = pairId,
            displayName = DISPLAY_NAME,
            platform = PLATFORM,
            createdAtMs = CREATED_AT_MS,
            holderName = HOLDER_NAME,
        )

        val peer = catalog.listPairs().single()
        assertEquals(pairIdHex, peer.pairIdHex)
        assertEquals(DISPLAY_NAME, peer.displayName)
        assertEquals(PLATFORM, peer.platform)
        assertEquals(CREATED_AT_MS, peer.createdAtMs)
        assertEquals(HOLDER_NAME, peer.holderName)
        assertNull(peer.forgottenAtMs)

        catalog.updateHolderName(pairIdHex, OTHER_HOLDER_NAME)
        assertEquals(OTHER_HOLDER_NAME, catalog.listPairs().single().holderName)

        catalog.updateCertificateDer(pairIdHex, certDer)
        assertEquals(
            java.util.Base64
                .getEncoder()
                .encodeToString(certDer),
            catalog.listPairs().single().certificateDerBase64,
        )

        catalog.removePair(pairIdHex)
        assertTrue(catalog.allPairs().isEmpty())
    }

    @Test
    fun aForgottenPairingLeavesTheListButStaysCatalogued() {
        val catalog = RappPairCatalog(FakeSharedPreferences())
        val pairId = PAIR_ID_TEXT.encodeToByteArray()
        catalog.savePair(pairId, DISPLAY_NAME, PLATFORM, createdAtMs = CREATED_AT_MS)
        catalog.markForgotten(pairId.toHexString(), FORGOTTEN_AT_MS)

        assertTrue(catalog.listPairs().isEmpty())
        val forgotten = catalog.forgottenPairs().single()
        assertEquals(FORGOTTEN_AT_MS, forgotten.forgottenAtMs)
        assertEquals(CREATED_AT_MS, forgotten.lastUsedMs)

        catalog.removePair(pairId.toHexString())
        assertTrue(catalog.allPairs().isEmpty())
    }

    @Test
    fun aPairingsLastUseStartsAtCreationAndFollowsItsSessions() {
        val catalog = RappPairCatalog(FakeSharedPreferences())
        val laptop = PAIR_ID_TEXT.encodeToByteArray()
        val desktop = OTHER_PAIR_ID_TEXT.encodeToByteArray()
        catalog.savePair(laptop, DISPLAY_NAME, PLATFORM, createdAtMs = CREATED_AT_MS)
        catalog.savePair(desktop, DISPLAY_NAME, PLATFORM, createdAtMs = OTHER_CREATED_AT_MS)
        assertEquals(CREATED_AT_MS, catalog.listPairs().first { it.pairIdHex == laptop.toHexString() }.lastUsedMs)
        catalog.markUsed(laptop.toHexString(), USED_AT_MS)
        val pairs = catalog.listPairs()
        assertEquals(USED_AT_MS, pairs.first { it.pairIdHex == laptop.toHexString() }.lastUsedMs)
        assertEquals(OTHER_CREATED_AT_MS, pairs.first { it.pairIdHex == desktop.toHexString() }.lastUsedMs)
    }

    @Test
    fun rappSettingsDefaultsToFalseWhenNoPairsExist() {
        val prefs = FakeSharedPreferences()
        val settings = RappSettings(prefs, pairCatalogSupplier = { emptyList() })
        assertFalse(settings.isCardRemoteAccessEnabled)
    }

    @Test
    fun rappSettingsDefaultsToTrueWhenPairsAlreadyExist() {
        val prefs = FakeSharedPreferences()
        val peer =
            PairedPeer(
                pairIdHex = "01020304",
                displayName = "Laptop",
                platform = "Linux",
                createdAtMs = 123456789L,
            )
        val settings = RappSettings(prefs, pairCatalogSupplier = { listOf(peer) })
        assertTrue(settings.isCardRemoteAccessEnabled)
    }

    @Test
    fun rappSettingsRespectsExplicitlyConfiguredValue() {
        val prefs = FakeSharedPreferences()
        val peer =
            PairedPeer(
                pairIdHex = "01020304",
                displayName = "Laptop",
                platform = "Linux",
                createdAtMs = 123456789L,
            )
        val settings = RappSettings(prefs, pairCatalogSupplier = { listOf(peer) })

        // Explicitly turn off
        settings.isCardRemoteAccessEnabled = false
        assertFalse(settings.isCardRemoteAccessEnabled)

        // Explicitly turn on
        settings.isCardRemoteAccessEnabled = true
        assertTrue(settings.isCardRemoteAccessEnabled)
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

    private companion object {
        const val OPENSSL_EXECUTABLE_NAME = "openssl"
        const val PAIR_ID_TEXT = "pair-identifier!"
        const val OTHER_PAIR_ID_TEXT = "other-identifier"
        const val CERTIFICATE_TEXT = "synthetic certificate"
        const val DISPLAY_NAME = "Laptop"
        const val PLATFORM = "macOS"
        const val HOLDER_NAME = "Holder"
        const val OTHER_HOLDER_NAME = "Other Holder"
        const val CREATED_AT_MS = 1_700_000_000_000L
        const val OTHER_CREATED_AT_MS = 1_700_000_001_000L
        const val USED_AT_MS = 1_700_000_005_000L
        const val FORGOTTEN_AT_MS = 1_700_000_009_000L
    }
}
