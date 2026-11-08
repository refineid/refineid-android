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

    /**
     * A PIN command left on the held secure channel whose effect on the
     * PIN 1 count is not known: the cached preflight says nothing of the
     * count until the channel is opened afresh.
     */
    fun pin1CountUnknown() {
        checkOpen()
        pin1Preflight = pin1Preflight?.copy(state = NativePin1State.NoInformation, retryFloorPermits = false)
    }

    /**
     * The card accepted a VERIFY of PIN 1 on the held secure channel, which
     * sets the try counter to the PIN Try Limit (FINEID S1 v4.2 sections
     * 3.5 and 3.11): the cached preflight reads verified.
     */
    fun pin1Accepted() {
        checkOpen()
        pin1Preflight = pin1Preflight?.copy(state = NativePin1State.Verified, retryFloorPermits = true)
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
