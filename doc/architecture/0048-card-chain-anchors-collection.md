# ADR 0048: The signer's card chain anchors validation-material collection

## Status

Accepted. Maintainer decision of 2026-11-08.

## Context

Collecting a signature's long-term validation material (ADR 0024) walks the
document signer's path to one of the path's explicit anchors and finds each
missing issuer through the certificate's CA Issuers address. The anchors were
the bundled FINEID intermediates alone. An organisation TEST card's qualified
certificate names no CA Issuers address and chains to a CA no bundle holds,
so archival stopped with `ISSUER_UNAVAILABLE` after the card had signed.

The card itself carries the chain: the issuing CA in EF.4336 and the root in
EF.4334, under the MF (FINEID S4-1 section 8.1.16). refineid-core's
`doc/security/certificate-custody.md` keeps them on every platform in an
owner-only cache until they expire. On Android that cache is
`CaCertificateStore`. It was filled only at a card's open, and only when the
native statics that the application seeds at start from the cache were
empty; with any card's CAs cached, an organisation card's own CAs were never
read.

## Decision

When signing, in every build, the signer's chain from the cache anchors the
collection beside the configured trust: `NetworkQualifiedPdfValidationSource`
asks its `SignerAnchorSource`, the `CaCertificateStore`, for the cached chain
of the signer's certificate at collection time, and adds it to both the
signer anchors and the issuer candidates of that one request, within the
request's certificate bounds. Verification is unchanged: the independent
validator and the trusted lists decide whether a signature is valid; the
card chain only lets the collector finish a path and fetch its status.

When the cache holds no chain up to a self-signed root for the qualified
certificate, an organisation card's PIN 2 channel reads EF.4334 and EF.4336
after the signature is made, so no answer to those reads can touch the
signature. The cache admits the issuing CA when it is a CA certificate within
its validity, and the root only when it is besides self-signed and the
verified issuer of that issuing CA. Each read records the step the card
stopped at (SELECT MF, SELECT of the file, READ BINARY, or a certificate the
core does not admit) and the card's status word; the debug trace writes them
as `card-ca:read`.

Whether an organisation card answers these reads on the PIN 2 channel is not
yet observed: the scripted tests prove the command sequence and the
recording, not the card. The first signature with an empty cache answers the
question in the debug trace.

## Consequences

- A signer whose card chain is cached completes archival without a CA
  Issuers address.
- A cache entry can only add an anchor for collection; it cannot make an
  invalid signature verify.
- Citizen cards, whose CAs the CAN channel reads at the open, already fill
  the cache at the open; this change adds no CA read to the USB reader path.
