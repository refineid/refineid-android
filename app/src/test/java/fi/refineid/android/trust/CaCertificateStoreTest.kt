// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.trust

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class CaCertificateStoreTest {
    @Test
    fun loadOnEmptyDirectoryIndexesNothing() {
        val tempDir = Files.createTempDirectory("test-empty-ca").toFile()
        try {
            val store = CaCertificateStore(baseDirectory = tempDir)
            store.load()
            assertNull(store.rootCaDer)
            assertNull(store.intermediateCaDer)
            assertTrue(store.allCertificates().isEmpty())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun deletesExpiredCertificateOnLoad() {
        val tempDir = Files.createTempDirectory("test-expired-ca").toFile()
        try {
            val caDir = File(tempDir, CA_CERTIFICATES_DIRECTORY_NAME)
            caDir.mkdirs()
            val expiredFile = File(caDir, "expired.der")
            expiredFile.writeBytes(EXPIRED_CA_DER)
            assertTrue(expiredFile.exists())

            val store = CaCertificateStore(baseDirectory = tempDir)
            store.load()

            assertFalse("Expired CA certificate file must be deleted on load", expiredFile.exists())
            assertNull(store.rootCaDer)
            assertNull(store.intermediateCaDer)
            assertTrue(store.allCertificates().isEmpty())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun deletesCorruptedCertificateFileOnLoad() {
        val tempDir = Files.createTempDirectory("test-corrupt-ca").toFile()
        try {
            val caDir = File(tempDir, CA_CERTIFICATES_DIRECTORY_NAME)
            caDir.mkdirs()
            val corruptFile = File(caDir, "corrupt.der")
            corruptFile.writeBytes(CORRUPTED_BYTES)
            assertTrue(corruptFile.exists())

            val store = CaCertificateStore(baseDirectory = tempDir)
            store.load()

            assertFalse("Corrupted file must be deleted on load", corruptFile.exists())
            assertTrue(store.allCertificates().isEmpty())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    private companion object {
        private const val CA_CERTIFICATES_DIRECTORY_NAME = "ca-certificates"
        private const val HEX_RADIX = 16
        private const val HEX_CHARS_PER_BYTE = 2
        private const val NIBBLE_SHIFT = 4
        private val CORRUPTED_BYTES = byteArrayOf(1, 2, 3, 4)

        private fun decodeHex(hex: String): ByteArray {
            val clean = hex.trim().replace("\n", "").replace(" ", "")
            val len = clean.length
            val data = ByteArray(len / HEX_CHARS_PER_BYTE)
            for (i in 0 until len step HEX_CHARS_PER_BYTE) {
                val high = Character.digit(clean[i], HEX_RADIX)
                val low = Character.digit(clean[i + 1], HEX_RADIX)
                data[i / HEX_CHARS_PER_BYTE] = ((high shl NIBBLE_SHIFT) + low).toByte()
            }
            return data
        }

        // Self-signed CA certificate valid 2019-01-01 to 2020-01-01 (expired)
        val EXPIRED_CA_DER: ByteArray =
            decodeHex(
                "3082018030820125a00302010202146c7a2b75f5318e45ad0adc5831f0e9a0f16b71" +
                    "cd300a06082a8648ce3d04030230153113301106035504030c0a45787069726564" +
                    "204341301e170d3139303130313030303030305a170d3230303130313030303030" +
                    "305a30153113301106035504030c0a457870697265642043413059301306072a86" +
                    "48ce3d020106082a8648ce3d03010703420004dc29ae423e094c74b2c5f316c601" +
                    "d54e55f1807742457ec8069734ecbe498c964405e2771f1c1e3b0cf9b39c560ea6" +
                    "a78196b8edd79a00426fd7a5d68f9fbd2ea3533051301d0603551d0e04160414a0" +
                    "b26ee5ad8c63ac9ca0fd88a3d124be52a2b656301f0603551d23041830168014a0" +
                    "b26ee5ad8c63ac9ca0fd88a3d124be52a2b656300f0603551d130101ff04053003" +
                    "0101ff300a06082a8648ce3d0403020349003046022100d5e31918bbf084eb1732" +
                    "6186d06cc6593564f4b63d401c09c57cacae0dece38202210085cdb94a9cdf77c7" +
                    "9f64b35d60ca1d088f048709a77bad75b1fdcaecf5626e1f",
            )
    }
}
