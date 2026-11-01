# ADR 0020: Timestamp-token verification

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

Request binding proves only that a timestamp response repeats the requested
signature digest and nonce. It does not prove that the returned generation time
was signed by the intended timestamp authority. An unverified token must never
be embeddable as PAdES signature evidence.

Timestamp CMS is attacker-controlled input. Signer selection, signed
attributes, certificate purpose, and trust must remain unambiguous even when a
token contains extra certificates or the device has unrelated system roots.

## Decision

`TimestampTokenVerifier` is the sole promotion boundary from
`UnverifiedTimestampToken` to `VerifiedTimestampToken`. It requires all of the
following before creating the verified capability:

- one CMS digest algorithm and one version-coupled signer identifier;
- exactly one distinct embedded certificate matching issuer-and-serial or
  subject-key-identifier;
- canonical signed attributes containing one matching content type and one
  digest of the exact encapsulated TSTInfo;
- a valid ECDSA, RSA PKCS #1 v1.5, or explicitly parameterized RSA-PSS
  signature using SHA-256, SHA-384, or SHA-512;
- one RFC 2634 or RFC 5035 ESS signing-certificate attribute whose first
  reference hashes the selected signer and whose optional issuer/serial also
  matches it;
- a non-CA signer certificate with a sole critical timestamping extended key
  usage, compatible key usage, and validity at signed `genTime`;
- an optional `TSTInfo.tsa` directory name or mailbox that exactly identifies
  the selected certificate; and
- a PKIX path at `genTime` ending in one of the caller's non-empty, exclusive
  trust anchors.

PKIX receives only the certificates embedded in the token and the explicit
anchors. Revocation lookup is disabled at this stage, no system roots are
added, and no network certificate store is configured. Dynamic revocation
decisions belong to the later validation-evidence stage.
Configured authorities obtain independent runtime EU trusted-list timestamp
anchors before promotion, as described in [ADR 0050](0050-trusted-list-timestamps.md).

The verified token owns and clears its token and certificate encodings. Its
string representation exposes only sizes, counts, time, and closed state.

An interoperability test creates an ephemeral root, timestamp-only leaf, and
private keys in an operating-system temporary directory. OpenSSL produces and
independently verifies the response. The Android verifier must build the leaf
to the separate explicit root, and must reject another root, malformed trust,
or a changed CMS signature. All generated material is deleted after the test;
no private-key fixture is stored in the repository.

## Consequences

Only a cryptographically authenticated and explicitly trusted timestamp can
cross the type boundary used by the PAdES-B-T assembly in ADR 0021. A token
still does not provide long-term validation by itself: revocation evidence,
DSS construction, the document timestamp, and archive validation remain
subsequent work.
