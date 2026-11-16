# ADR 0050: Trusted-list timestamps and bound signing destinations

## Status

Accepted. This defines timestamp trust for configured authorities and the
transport behavior used by signing and document validation.

## Decision

The configured authority chooses where to request a timestamp, not which
certificate to trust. `Rfc3161TimestampClient` obtains independent anchors from
`TrustedListTimestampAnchors` at the request-bound token's generation time.
`TimestampTokenVerifier` requires an explicit, nonempty trust set and never
promotes token-embedded certificates to anchors. Embedded certificates remain
path-building candidates only. Missing anchors or an unsuccessful PKIX path
use the existing untrusted-signer failure.

The runtime provider uses refineid-core's
[ETSI TS 119 612 parser](https://github.com/refineid/refineid-core/blob/main/crates/doc-sign/src/verification/trusted_list.rs).
The core authenticates the European Commission List of Trusted Lists (LOTL)
under its existing Commission list-signing bootstrap identities. Each national
list is authenticated under the signer identities in the verified LOTL.
Only qualified timestamp services (`TSA/QTST`) from fresh verified national
lists contribute anchors, with the core's service-status history determining
whether each anchor is granted at the token's generation time. Missing,
unverifiable, stale, or future-issued national lists contribute no anchors;
they do not disable other countries' fresh lists. The LOTL itself must be
verified, current, and not future-issued. No TSA certificate or fingerprint is
bundled by the Android shell.

An in-memory native cache lasts at most one hour and never beyond the earliest
next update of the LOTL or a national list contributing anchors. Cache use
rejects clock rollback before its fetch time. Freshness is checked again after
fetching, before returning anchors. No trusted-list cache is persisted.
Every list is fetched through `HttpSigningNetwork` with a 16 MiB response cap.
The native-to-Kotlin reply has bounded certificate count, certificate size,
and total size. Returned certificate buffers belong to the caller and are
cleared after verification.

The shipped authority uses HTTPS. Credential-free holder-configured HTTP
services remain permitted because a response must still authenticate to the
independent trusted-list anchors. Basic credentials require HTTPS and remain
confined to the initial origin. Restoring defaults selects the shipped HTTPS
address; stored holder addresses are used as supplied.

All signing destinations, including configured authorities, pass the public
address policy. DNS answers are vetted once per exchange and the selected
numeric address is supplied to OkHttp's DNS implementation for that exchange.
The request URL keeps its logical hostname for Host, TLS SNI, and platform TLS
certificate and hostname verification. Automatic redirects, proxies, response
caching, and connection-failure retries are disabled. Redirects return to the
shared policy and receive fresh address checks. Response streams retain their
caller-selected bounds. Neither a second platform DNS lookup nor a configured
proxy can substitute a local destination.

## STPA

This record applies the losses and hazards in the shared
[STPA record](https://github.com/refineid/refineid-core/blob/main/doc/security/stpa-rapp.md)
to the local timestamp and network controllers. It does not change RAPP.

The timestamp client requests a response and receives nonce/digest binding,
CMS authentication, PKIX feedback, and independently authenticated service
status. The list provider receives signature, issue-time, next-update, role,
and granted-period feedback. The transport receives DNS answers and redirect
locations and controls the numeric connection destination.

- UCA-T1: return a verified token based only on the response's embedded keys,
  producing a misleading signing success (H-5). CC-T1: require independent
  qualified timestamp anchors granted at generation time before promotion.
- UCA-T2: use expired list data or a service outside its granted period,
  producing misleading trust feedback (H-5). CC-T2: verify list signatures,
  freshness and role, enforce granted periods, bound cache age, and fail closed.
- UCA-T3: connect to a local destination after checking a different DNS answer,
  exposing activity to a third party (L-4/H-6). CC-T3: apply public-address
  checks to both endpoint kinds, bind the selected numeric destination,
  preserve TLS identity, disable proxies, and revalidate every redirect.
- UCA-T4: read an unbounded list or responder body, preventing signing or
  validation (L-3). CC-T4: bound each network response and the JNI reply;
  unavailable trust cannot be reported as successful verification (H-5).

## Verification

Hermetic HTTPS tests observe the numeric socket destination and server-side
SNI for both endpoint kinds while the injected resolver would return loopback
on a second lookup. A certificate for another logical hostname is rejected.
A configured proxy cannot override the vetted connection destination. Private
authority URLs and private DNS answers are refused before a socket opens.

OpenSSL generates synthetic request-bound timestamps. The client accepts an
independent anchor, resolves anchors at the token's generation time, clears
transferred anchor buffers, and rejects empty or unrelated trust even when the
response embeds its own chain. Native tests cover role and granted-period
selection, cache expiry and rollback, duplicate services, and malformed LOTL
rejection before any national fetch.
