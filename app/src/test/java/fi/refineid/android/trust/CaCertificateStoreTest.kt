// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.trust

import fi.refineid.android.testutil.TestCertificates
import org.junit.Assert.assertEquals
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
            expiredFile.writeBytes(expiredCertificate())
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

    @Test
    fun aCardIssuingCaAnchorsItsSignerAndARootNeedsItsIssuingCa() {
        val tempDir = Files.createTempDirectory("test-card-chain").toFile()
        try {
            val issuerKey = TestCertificates.keyPair()
            val signerKey = TestCertificates.keyPair()
            val issuer =
                TestCertificates.certificate(
                    subjectCommonName = ISSUING_COMMON_NAME,
                    subjectKey = issuerKey,
                    issuerCommonName = ISSUING_COMMON_NAME,
                    issuerKey = issuerKey,
                    serialNumber = ISSUER_SERIAL_NUMBER,
                    notBefore = CURRENT_NOT_BEFORE,
                    notAfter = CURRENT_NOT_AFTER,
                    certificateAuthority = true,
                )
            val signer =
                TestCertificates.certificate(
                    subjectCommonName = SIGNER_COMMON_NAME,
                    subjectKey = signerKey,
                    issuerCommonName = ISSUING_COMMON_NAME,
                    issuerKey = issuerKey,
                    serialNumber = SIGNER_SERIAL_NUMBER,
                    notBefore = CURRENT_NOT_BEFORE,
                    notAfter = CURRENT_NOT_AFTER,
                    certificateAuthority = false,
                )

            val store = CaCertificateStore(baseDirectory = tempDir)
            store.load()
            assertFalse(store.hasChainFor(signer))

            assertEquals(
                NOTHING_ADMITTED,
                store.admitCardChain(rootDer = issuer, issuingDer = null),
            )
            assertEquals(NOTHING_ADMITTED, store.admitCardChain(rootDer = null, issuingDer = signer))
            assertFalse(store.hasChainFor(signer))

            assertEquals(ONE_ADMITTED, store.admitCardChain(rootDer = null, issuingDer = issuer))
            assertTrue(store.hasChainFor(signer))

            val reloaded = CaCertificateStore(baseDirectory = tempDir)
            reloaded.load()
            assertTrue("the admitted CA persists", reloaded.hasChainFor(signer))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    private companion object {
        private const val NOTHING_ADMITTED = 0
        private const val ONE_ADMITTED = 1
        private const val CA_CERTIFICATES_DIRECTORY_NAME = "ca-certificates"
        private const val ISSUING_COMMON_NAME = "Test Issuing CA"
        private const val SIGNER_COMMON_NAME = "Test Document Signer"
        private const val ISSUER_SERIAL_NUMBER = 1
        private const val SIGNER_SERIAL_NUMBER = 2
        private const val CURRENT_NOT_BEFORE = "20260101000000Z"
        private const val CURRENT_NOT_AFTER = "20560101000000Z"
        private const val EXPIRED_NOT_BEFORE = "20190101000000Z"
        private const val EXPIRED_NOT_AFTER = "20200101000000Z"
        private val CORRUPTED_BYTES = byteArrayOf(1, 2, 3, 4)

        /** A self-signed CA whose validity ended in 2020; generated fresh like every fixture here. */
        private fun expiredCertificate(): ByteArray {
            val key = TestCertificates.keyPair()
            return TestCertificates.certificate(
                subjectCommonName = "Expired CA",
                subjectKey = key,
                issuerCommonName = "Expired CA",
                issuerKey = key,
                serialNumber = ISSUER_SERIAL_NUMBER,
                notBefore = EXPIRED_NOT_BEFORE,
                notAfter = EXPIRED_NOT_AFTER,
                certificateAuthority = true,
            )
        }
    }
}
