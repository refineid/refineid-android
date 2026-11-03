// Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

package fi.refineid.android.rapp

import uniffi.refineid_rapp.rappRedialWindowMs

/**
 * The custodian's identity this requester offers to local consumers (RAPP
 * v26.11.2 section 8.4 item 3): the certificate the custodian confirmed by
 * fingerprint on a session, read afresh on any difference.
 *
 * While a session confirms the card present the offer stands. A report of
 * absence, and the session's end on a loss or a violation, start the grace:
 * the offer stands until [GRACE_MS] pass with no session confirming the
 * card present. Forgetting and revocation, a verified withdrawal, a
 * `card_unavailable` close, and a session reporting a different card
 * withdraw the offer at once through [withdraw]; the driver then reads the
 * card afresh before offering anything. Time is the driver's monotonic
 * milliseconds.
 */
internal class RappIdentityOffer {
    private var certificate: RappCertificate? = null

    /** When the offer ends, in the driver's monotonic milliseconds. */
    private var expiresAtMs: Long = NO_OFFER

    /** Whether a certificate is offered at [nowMs]. */
    fun offered(nowMs: Long): RappCertificate? {
        if (certificate != null && nowMs >= expiresAtMs) withdraw()
        return certificate
    }

    /**
     * A session confirmed the card present and [certificate], of the
     * reported fingerprint, was read: offer it with no expiry while the
     * session stands.
     */
    fun confirmCard(certificate: RappCertificate) {
        this.certificate = certificate
        expiresAtMs = Long.MAX_VALUE
    }

    /**
     * The custodian reported absence, or the session ended on a loss or a
     * violation, at [nowMs]: the offer, if any, stands through the grace.
     */
    fun startGrace(nowMs: Long) {
        if (certificate != null && expiresAtMs == Long.MAX_VALUE) {
            expiresAtMs = nowMs + GRACE_MS
        }
    }

    /** Withdraw the offer at once. */
    fun withdraw() {
        certificate = null
        expiresAtMs = NO_OFFER
    }

    companion object {
        /** How long the offer outlives its session or a report of absence (section 8.4 item 3). */
        val GRACE_MS: Long = rappRedialWindowMs().toLong()

        private const val NO_OFFER = 0L
    }
}
