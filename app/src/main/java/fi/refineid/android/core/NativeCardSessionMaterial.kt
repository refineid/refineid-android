package fi.refineid.android.core

/** Mutable authentication material owned by exactly one retained card session. */
internal class NativeCardSessionMaterial : AutoCloseable {
    private var isClosed = false
    private var authenticationCertificate: NativeAuthenticationCertificate? = null
    private var pin1Preflight: NativePin1Preflight? = null

    fun cacheAuthenticationCertificate(certificate: NativeAuthenticationCertificate) {
        checkOpen()
        authenticationCertificate?.close()
        authenticationCertificate = certificate
    }

    fun cachePin1Preflight(preflight: NativePin1Preflight) {
        checkOpen()
        pin1Preflight = preflight
    }

    fun requireAuthenticationCertificate(): NativeAuthenticationCertificate {
        checkOpen()
        return checkNotNull(authenticationCertificate) {
            "authentication certificate is not cached"
        }
    }

    fun copyAuthenticationCertificate(): NativeAuthenticationCertificate {
        return requireAuthenticationCertificate().copyOwned()
    }

    fun cachedPin1Preflight(): NativePin1Preflight? {
        checkOpen()
        return pin1Preflight
    }

    fun requirePin1Preflight(): NativePin1Preflight {
        checkOpen()
        return checkNotNull(pin1Preflight) {
            "PIN1 preflight is not cached"
        }
    }

    override fun close() {
        if (isClosed) {
            return
        }
        isClosed = true
        authenticationCertificate?.close()
        authenticationCertificate = null
        pin1Preflight = null
    }

    private fun checkOpen() {
        check(!isClosed) {
            "card session material is closed"
        }
    }
}
