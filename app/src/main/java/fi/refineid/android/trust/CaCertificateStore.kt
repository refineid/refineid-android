// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.trust

import android.content.Context
import fi.refineid.android.core.AuthenticationIssuerCertificateSource
import fi.refineid.android.document.SignerAnchorSource
import java.io.File
import java.io.FileOutputStream
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * Persistent on-disk and in-memory cache for root and intermediate CA
 * certificates discovered on smart cards (refineid-core
 * doc/security/certificate-custody.md). The cached chain of a signer's
 * certificate also anchors the collection of its long-term validation
 * material; verification does not use it.
 */
@Suppress("TooManyFunctions")
internal class CaCertificateStore(
    private val context: Context? = null,
    baseDirectory: File? = null,
) : AuthenticationIssuerCertificateSource,
    SignerAnchorSource {
    private val lock = Any()
    private val directory = File(baseDirectory ?: context?.filesDir ?: File("."), CA_CERTIFICATES_DIRECTORY_NAME)
    private val certificates = mutableListOf<X509Certificate>()
    private val certsByFingerprint = mutableMapOf<String, ByteArray>()
    private var cachedRootDer: ByteArray? = null
    private var cachedIntermediateDer: ByteArray? = null

    val rootCaDer: ByteArray?
        get() = synchronized(lock) { cachedRootDer?.copyOf() }

    val intermediateCaDer: ByteArray?
        get() = synchronized(lock) { cachedIntermediateDer?.copyOf() }

    fun load() {
        synchronized(lock) {
            certificates.clear()
            certsByFingerprint.clear()
            cachedRootDer = null
            cachedIntermediateDer = null

            if (!directory.exists()) {
                directory.mkdirs()
            }
            val files = directory.listFiles { file -> file.extension == DER_FILE_EXTENSION } ?: emptyArray()
            for (file in files) {
                val cert =
                    runCatching { file.readBytes() }
                        .getOrNull()
                        ?.let(::parseCertificate)
                if (cert == null) {
                    file.delete()
                    continue
                }
                val isExpired =
                    try {
                        cert.checkValidity()
                        false
                    } catch (_: CertificateExpiredException) {
                        true
                    } catch (_: CertificateNotYetValidException) {
                        true
                    } catch (_: GeneralSecurityException) {
                        true
                    }
                if (isExpired) {
                    file.delete()
                } else {
                    indexCertificateLocked(cert, persistToDisk = false)
                }
            }
        }
    }

    fun saveCertificate(der: ByteArray): Boolean {
        val cert = parseCertificate(der) ?: return false
        if (cert.basicConstraints < CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM) {
            return false
        }
        synchronized(lock) {
            return indexCertificateLocked(cert, persistToDisk = true)
        }
    }

    /**
     * Admits the CA certificates a card supplied, under the custody rule: the
     * issuing CA when it is a CA certificate within its validity, the root
     * when it is besides self-signed and the verified issuer of that issuing
     * CA. Returns how many certificates were new.
     */
    fun admitCardChain(
        rootDer: ByteArray?,
        issuingDer: ByteArray?,
    ): Int {
        val issuing = issuingDer?.let(::parseCertificate)?.takeIf { it.isCurrentCertificateAuthority() }
        val root =
            rootDer
                ?.let(::parseCertificate)
                ?.takeIf { candidate ->
                    issuing != null &&
                        candidate.isCurrentCertificateAuthority() &&
                        candidate.isSelfSigned() &&
                        candidate.isDirectIssuerOf(issuing)
                }
        synchronized(lock) {
            return listOfNotNull(issuing, root).count { cert -> indexCertificateLocked(cert, persistToDisk = true) }
        }
    }

    /** True when the cache holds the chain of [leafDer] up to a self-signed root. */
    fun hasChainFor(leafDer: ByteArray): Boolean {
        val leaf = parseCertificate(leafDer) ?: return false
        return chainOf(leaf).lastOrNull()?.isSelfSigned() == true
    }

    /** The cached chain of [signerCertificate], issuer first, each copy owned by the caller. */
    override fun copyAnchorsFor(signerCertificate: ByteArray): List<ByteArray> {
        val leaf = parseCertificate(signerCertificate) ?: return emptyList()
        return chainOf(leaf).mapNotNull { certificate ->
            try {
                certificate.encoded
            } catch (_: GeneralSecurityException) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }
    }

    private fun chainOf(leaf: X509Certificate): List<X509Certificate> {
        val chain = mutableListOf<X509Certificate>()
        var current: X509Certificate? = leaf
        synchronized(lock) {
            while (current != null && chain.size < MAXIMUM_CACHED_CHAIN_LENGTH) {
                val subject = current
                val issuer =
                    certificates.firstOrNull { candidate ->
                        candidate !in chain &&
                            candidate != subject &&
                            candidate.isDirectIssuerOf(subject) &&
                            candidate.isCurrentCertificateAuthority()
                    }
                issuer?.let { chain += it }
                current = issuer?.takeUnless { it.isSelfSigned() }
            }
        }
        return chain
    }

    private fun X509Certificate.isCurrentCertificateAuthority(): Boolean {
        if (basicConstraints < CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM) return false
        return try {
            checkValidity()
            true
        } catch (_: CertificateExpiredException) {
            false
        } catch (_: CertificateNotYetValidException) {
            false
        }
    }

    fun hasIssuerFor(leafDer: ByteArray): Boolean {
        val leaf = parseCertificate(leafDer) ?: return false
        synchronized(lock) {
            return certificates.any { candidate -> candidate.isDirectIssuerOf(leaf) }
        }
    }

    override fun copyIssuerCertificate(leafCertificate: ByteArray): ByteArray? {
        val leaf = parseCertificate(leafCertificate) ?: return null
        val issuer =
            synchronized(lock) {
                certificates.firstOrNull { candidate -> candidate.isDirectIssuerOf(leaf) }
            } ?: return null
        val encoded =
            try {
                issuer.encoded
            } catch (_: GeneralSecurityException) {
                return null
            } catch (_: RuntimeException) {
                return null
            }
        return try {
            encoded.copyOf()
        } finally {
            encoded.fill(CLEARED_BYTE)
        }
    }

    fun allCertificates(): List<X509Certificate> =
        synchronized(lock) {
            certificates.toList()
        }

    private fun indexCertificateLocked(
        cert: X509Certificate,
        persistToDisk: Boolean,
    ): Boolean {
        val fingerprint = cert.sha256Fingerprint()
        val der =
            try {
                cert.encoded
            } catch (_: GeneralSecurityException) {
                return false
            } catch (_: RuntimeException) {
                return false
            }

        val isNew = !certsByFingerprint.containsKey(fingerprint)
        if (isNew) {
            certificates.add(cert)
            certsByFingerprint[fingerprint] = der.copyOf()
        }

        if (cert.isSelfSigned()) {
            if (cachedRootDer == null) {
                cachedRootDer = der.copyOf()
            }
        } else {
            if (cachedIntermediateDer == null) {
                cachedIntermediateDer = der.copyOf()
            }
        }

        if (persistToDisk && isNew) {
            writeCertificateToDisk(fingerprint, der)
        }
        return isNew
    }

    private fun writeCertificateToDisk(
        fingerprint: String,
        der: ByteArray,
    ) {
        if (!directory.exists()) {
            directory.mkdirs()
        }
        val targetFile = File(directory, "$fingerprint.$DER_FILE_EXTENSION")
        val tempFile = File(directory, "$fingerprint.tmp")
        try {
            FileOutputStream(tempFile).use { stream ->
                stream.write(der)
                stream.flush()
            }
            if (!tempFile.renameTo(targetFile)) {
                tempFile.copyTo(targetFile, overwrite = true)
                tempFile.delete()
            }
        } catch (_: Exception) {
            tempFile.delete()
        }
    }

    private fun parseCertificate(encoded: ByteArray): X509Certificate? {
        val certificate =
            try {
                CertificateFactory
                    .getInstance(X509_CERTIFICATE_TYPE)
                    .generateCertificate(encoded.inputStream()) as? X509Certificate
            } catch (_: GeneralSecurityException) {
                null
            } catch (_: RuntimeException) {
                null
            } ?: return null
        val canonical =
            try {
                certificate.encoded
            } catch (_: GeneralSecurityException) {
                return null
            } catch (_: RuntimeException) {
                return null
            }
        return try {
            certificate.takeIf { canonical.contentEquals(encoded) }
        } finally {
            canonical.fill(CLEARED_BYTE)
        }
    }

    private fun X509Certificate.isSelfSigned(): Boolean {
        if (subjectX500Principal != issuerX500Principal) {
            return false
        }
        return try {
            verify(publicKey)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun X509Certificate.isDirectIssuerOf(leaf: X509Certificate): Boolean {
        if (
            basicConstraints < CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM ||
            !allowsCertificateSigning() ||
            subjectX500Principal != leaf.issuerX500Principal
        ) {
            return false
        }
        return try {
            leaf.verify(publicKey)
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun X509Certificate.allowsCertificateSigning(): Boolean {
        val usage = keyUsage ?: return true
        return usage.size > KEY_CERTIFICATE_SIGNING_USAGE_INDEX &&
            usage[KEY_CERTIFICATE_SIGNING_USAGE_INDEX]
    }

    private fun X509Certificate.sha256Fingerprint(): String {
        val digest =
            MessageDigest
                .getInstance(SHA256_DIGEST_NAME)
                .digest(encoded)
        return try {
            digest.joinToString(separator = "") { byte ->
                byte
                    .toUByte()
                    .toInt()
                    .toString(HEX_RADIX)
                    .padStart(HEX_BYTE_WIDTH, HEX_ZERO_CHARACTER)
                    .uppercase(Locale.ROOT)
            }
        } finally {
            digest.fill(CLEARED_BYTE)
        }
    }

    private companion object {
        const val CA_CERTIFICATES_DIRECTORY_NAME = "ca-certificates"

        /** An issuing CA and its root: the chain a card carries (EF.4336, EF.4334). */
        const val MAXIMUM_CACHED_CHAIN_LENGTH = 2
        const val DER_FILE_EXTENSION = "der"
        const val X509_CERTIFICATE_TYPE = "X.509"
        const val SHA256_DIGEST_NAME = "SHA-256"
        const val CERTIFICATE_AUTHORITY_BASIC_CONSTRAINTS_MINIMUM = 0
        const val KEY_CERTIFICATE_SIGNING_USAGE_INDEX = 5
        const val HEX_RADIX = 16
        const val HEX_BYTE_WIDTH = 2
        const val HEX_ZERO_CHARACTER = '0'
        const val CLEARED_BYTE: Byte = 0
    }
}
