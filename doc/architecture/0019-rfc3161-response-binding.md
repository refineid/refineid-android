# ADR 0019: RFC 3161 response binding

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

A signature timestamp is obtained after the PIN2-gated card signature. Before
the timestamp token is useful, its TSTInfo must name SHA-384, repeat the exact
signature-value digest, echo the request nonce, and carry a usable generation
time. These checks alone do not authenticate the token: its CMS signature,
signer certificate profile, and trust path still require separate validation.

Timestamp responses and their ASN.1 fields are untrusted network input. Parsing
must be bounded, canonical, and incapable of accidentally promoting an
unauthenticated claim into a PAdES timestamp.

## Decision

`Rfc3161Timestamp` builds a version-one SHA-384 request with a bounded nonce and
an explicit certificate request. The response parser accepts at most 64 KiB,
requires a complete TimeStampResp, admits only the two granted statuses, and
distinguishes a refusal from a granted response with no token.

The encapsulated TSTInfo is parsed in field order. Integer, object-identifier,
GeneralizedTime, Accuracy, ordering, TSA-name, and extension encodings are
checked before the SHA-384 imprint and canonical nonce INTEGER are compared.
The accepted result is deliberately named `UnverifiedTimestampToken`; it owns
and clears its bytes, and no CMS assembly API accepts it.

The timestamp parser follows the stricter mature implementation where it goes
beyond the Apple parser, including canonical optional fields, Accuracy ranges,
and bounded nanosecond precision. It retains the deployed compatibility rule
that permits an explicit FALSE critical flag only in TSTInfo extensions.

## Consequences

Network-response substitution and replay are rejected at a typed boundary, but
PAdES-B-T is not complete at this boundary. ADR 0020 adds CMS, signer-profile,
and explicit-trust verification and creates the verified-token capability;
ADR 0021 attaches only that capability as a signature timestamp.
