# ADR 0028: Bounded signing network

## Status

Accepted.

## Context

PAdES-B-LTA needs a timestamp authority plus AIA, OCSP, and CRL retrieval.
Timestamp-authority addresses are holder configuration, while certificate
material supplies the other addresses as untrusted input. Even though the
returned certificate and revocation bytes must authenticate themselves before
use, an unchecked request could still disclose credentials, reach a local
service, follow an attacker-controlled redirect chain, or consume unbounded
memory and time.

The document core in ADRs 0024 and 0025 deliberately has no implicit network
access. Its injected live implementation therefore needs one explicit policy
boundary. The Android release build also remains offline until product trust
configuration and orchestration are complete.

## Decision

`HttpSigningNetwork` is a synchronous, injectable transport with distinct
`AUTHORITY` and `CERTIFICATE_MATERIAL` endpoint policies. It accepts only exact
HTTP or HTTPS hierarchical URLs without user information, invalid ports, or
more than 8,192 characters. Request bodies are capped at 65,536 bytes, header
and credential components have explicit character limits, each exchange has a
30-second connect and read timeout, caches and automatic redirects are off,
and response bodies are accumulated only inside their caller-selected bound.
The transport-level response ceiling is 64 MiB.

All signing destination hosts reject local names, alternate numeric spellings,
zoned IPv6 literals, and non-global IPv4 or IPv6 ranges. The classification is
conservative relative to the current IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
special-purpose registries. A DNS name may return at most eight distinct
addresses and every answer must pass the same public-address test. HTTP and HTTPS connections use the first vetted numeric address through
OkHttp's per-exchange DNS implementation. The request URL retains the logical
hostname for Host, SNI, and platform TLS certificate and hostname verification.
Proxies and automatic connection retries are disabled. See
[ADR 0050](0050-trusted-list-timestamps.md).

Certificate material may follow at most two public HTTP(S) redirects. A
configured authority may follow one redirect only on its original origin, or
upgrade the same host from HTTP to HTTPS. Basic credentials are allowed only
over HTTPS and remain on the exact original HTTPS origin. Statuses 301, 302,
and 303 turn a POST into a bodyless GET; 307 and 308 retain its method and body.
Empty, oversized, non-success, malformed-location, and over-budget responses
are typed failures. Only reachability failures and the explicit 408, 425, 429,
500, 502, 503, and 504 status set are classified as transient for authority
retry policy.

`SigningNetworkValidationDependencies` maps AIA certificates to the existing
65,536-byte certificate cap, CRLs to the existing 16 MiB cap, and OCSP POSTs to
the 65,536-byte short-response cap. It also injects UTC time and bounded secure
randomness into `ValidationMaterialCollector`.

`Rfc3161TimestampClient` owns a copy of the requested SHA-384 digest, generates
a fresh 32-byte nonce, sends the bounded RFC 3161 request, binds the response to
that exact digest and nonce, and verifies the token against explicit trust
certificates or independently authenticated runtime EU trusted-list timestamp
anchors before returning `VerifiedTimestampToken`. Its authority
configuration owns its trust bytes and optional credentials, and clears
clearable working buffers when closed or after each attempt.

The layer contains no logging. Calls must run away from the UI thread. No
network address, credential, response, certificate, or document byte is
written to diagnostics.

## Verification

Unit tests cover public and special IPv4/IPv6 ranges, alternate numeric hosts,
mixed and oversized DNS answer sets, HTTP pinning, raw path and query
preservation, credential and redirect containment, redirect method semantics,
timeout configuration and classification, declared and streamed response
overflow, empty bodies, status classification, exact adapter limits,
ownership, clearing, and RFC 3161 request dispatch. A loopback HTTP server is
created only inside the host-side transport tests and carries synthetic bytes.

No live authority, card identity, credential, certificate, or network
identifier is stored in the repository or test reports.

## Consequences

The existing authenticated timestamp and validation core now has a bounded
live adapter, but it is not exposed by product UI or release orchestration.
The release manifest still has no Internet permission. The debug manifest
initially kept application-wide cleartext off so HTTPS could be exercised
first. ADR 0030 now permits cleartext in the debug variant only, behind this
transport's vetted certificate-endpoint policy; release cleartext and Internet
access remain off.

ADR 0030 supplies pinned debug trust, retry, cancellation, and off-main
orchestration. Product release still needs holder-managed authority
configuration and a reviewed production revocation-transport policy.
