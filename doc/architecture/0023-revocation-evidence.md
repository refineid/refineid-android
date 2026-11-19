# ADR 0023: Revocation-evidence authentication

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

A PDF DSS is only a byte carrier. A certificate, OCSP response, or CRL must not
be retained as validation evidence merely because a server returned it. Each
object has to identify the intended certificate and issuer, authenticate its
signer, cover the required time, and carry a usable status. A revoked or unknown
OCSP answer must be authenticated before it can affect the result.

The platform X.509 API is useful for public-key operations and PKIX checks, but
it does not expose every exact signed field needed by OCSP. Revocation checks
therefore also need bounded parsing of the original DER bytes.

## Decision

The validation boundary extracts exact issuer names, subject names, serial
numbers, subject-public-key bits, and bounded AIA and CRL addresses from the
certificate encoding. A candidate issuer is accepted only after a direct,
revocation-disabled PKIX check at the explicit verification time.

An OCSP request uses the RFC 6960 SHA-1 `CertID` for certificate identification
and a fresh 32-byte nonce. SHA-1 is not used as a signature algorithm. A response
is accepted only after strict DER parsing, exact `CertID` matching, nonce
comparison when echoed, time-policy checks, responder authorization, and a
signature over the exact encoded `ResponseData`. Supported response signatures
are RSA or ECDSA with SHA-256, SHA-384, or SHA-512.

The issuing CA may sign an OCSP response directly. A delegated responder must
be a directly issued end-entity certificate with the OCSP-signing extended key
usage, digital-signature key usage when constrained, and the exact signed
`id-pkix-ocsp-nocheck` extension. Without that extension, responder revocation
evidence is still missing and verification fails closed.

A CRL is accepted only as a complete direct CRL. Its exact issuer, signing
authorization, signature, validity interval, and target serial verdict are
verified. Delta, indirect, scoped, or unsupported critical-extension CRLs are
rejected. DER and strict PEM input are supported within explicit size bounds.

Verified OCSP and CRL capabilities own the original received bytes and clear
them when closed. Parsing and authentication perform no networking. Fetching,
path construction, bounded fallback, and DSS assembly remain a separate
orchestration layer.

## Verification

Synthetic certificate tests cover exact field extraction, bounded addresses,
direct issuer validation, and nonce-bound request encoding. OpenSSL interop
tests cover good and revoked CRLs in DER and PEM form, tampering, wrong issuers,
missing CRL-signing authorization, and invalid time windows.

OCSP interop covers direct and delegated responders, required delegated
authorization, nonce mismatch, signature tampering, authenticated revoked
status, certificate mismatch, malformed envelopes, responder errors, and
invalid time windows. Deterministic tests additionally cover the seven-day
maximum age for responses that omit `nextUpdate`.

## Consequences

Android has strict primitives for deciding whether downloaded revocation bytes
are admissible evidence. ADR 0024 applies them while constructing the complete
signer and timestamp-authority paths. Product orchestration must still append
that result to the signed PDF before claiming PAdES-B-LT.
