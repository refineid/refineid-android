// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
package fi.refineid.android.browser

/**
 * One origin the browser may present the card's certificate to: the canonical
 * host name with the port that asked. A certificate request crosses the WebView
 * boundary once, through [of]; everything downstream compares origins, never
 * raw host strings, so consent given on one port never covers another, and two
 * spellings of one host name meet as one origin.
 */
internal class BrowserOrigin private constructor(
    val host: String,
    val port: Int,
) {
    /**
     * The origin as the consent prompt names it: the bare host on the HTTPS
     * port, host and port otherwise.
     */
    val displayName: String
        get() = if (port == HTTPS_PORT) host else "$host:$port"

    override fun equals(other: Any?): Boolean = other is BrowserOrigin && other.host == host && other.port == port

    override fun hashCode(): Int = HOST_HASH_STRIDE * host.hashCode() + port

    override fun toString(): String = displayName

    companion object {
        private const val HTTPS_PORT = 443
        private const val MIN_PORT = 1
        private const val MAX_PORT = 65535
        private const val HOST_HASH_STRIDE = 31

        /**
         * The origin [host] and [port] name, or null when the host holds no
         * name or the port is outside the TCP range. Host names are
         * case-insensitive (RFC 4343) and may carry the root dot, so both are
         * canonicalised here.
         */
        fun of(
            host: String?,
            port: Int,
        ): BrowserOrigin? {
            val canonicalHost = host?.trim()?.trimEnd('.')?.lowercase()
            if (canonicalHost.isNullOrEmpty() || port !in MIN_PORT..MAX_PORT) return null
            return BrowserOrigin(canonicalHost, port)
        }
    }
}
