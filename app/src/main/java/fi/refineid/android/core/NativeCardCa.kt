package fi.refineid.android.core

/**
 * Native bridge for reading and caching card-delivered Root and Intermediate CA
 * certificates.
 */
internal object NativeCardCa {
    fun readRootCaCertificate(): ByteArray? =
        if (!NativeCore.isLoaded) {
            null
        } else {
            try {
                val bytes = readCardRootCaCertificateNative()
                bytes.takeIf { it.isNotEmpty() }
            } catch (_: LinkageError) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }

    fun readIntermediateCaCertificate(): ByteArray? =
        if (!NativeCore.isLoaded) {
            null
        } else {
            try {
                val bytes = readCardIntermediateCaCertificateNative()
                bytes.takeIf { it.isNotEmpty() }
            } catch (_: LinkageError) {
                null
            } catch (_: RuntimeException) {
                null
            }
        }

    fun setCachedCaCertificates(
        rootCa: ByteArray?,
        intermediateCa: ByteArray?,
    ): Boolean =
        if (!NativeCore.isLoaded) {
            false
        } else {
            try {
                val rootBytes = rootCa ?: ByteArray(0)
                val intermediateBytes = intermediateCa ?: ByteArray(0)
                setCachedCaCertificatesNative(rootBytes, intermediateBytes) == 1
            } catch (_: LinkageError) {
                false
            } catch (_: RuntimeException) {
                false
            }
        }

    @JvmStatic
    private external fun readCardRootCaCertificateNative(): ByteArray

    @JvmStatic
    private external fun readCardIntermediateCaCertificateNative(): ByteArray

    @JvmStatic
    private external fun setCachedCaCertificatesNative(
        rootCa: ByteArray,
        intermediateCa: ByteArray,
    ): Int
}
