# ADR 0021: PAdES Baseline T assembly

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

A signature timestamp covers the value stored in `SignerInfo.signature`, not
the CMS signed attributes, the enclosing OCTET STRING, or the PDF. Attaching a
valid token to another signature would create misleading evidence even if the
token itself had an authentic TSA signature and trusted certificate path.

Only the authenticated capability from ADR 0020 may enter document assembly.
Raw RFC 3161 responses and request-bound but unauthenticated tokens must remain
unrepresentable at this boundary.

## Decision

`QualifiedDocumentCms.signatureTimestampDigest` hashes the exact CMS signature
value with SHA-384. For RSA this is the modulus-wide card result. For P-384 it
is the canonical X9.62 DER pair produced from the card's fixed-width `r || s`
result.

`QualifiedDocumentCms.assembleTimestamped` requires at least one open
`VerifiedTimestampToken`. Every token's authenticated message imprint must
equal the digest of that exact signature value. A closed token or mismatch
fails before CMS output is returned.

Each distinct token is encoded as its own
`id-aa-signatureTimeStampToken` unsigned attribute. Attribute instances are
deduplicated, DER-sorted, and carried in SignerInfo's `[1] IMPLICIT` field.
The signed-attribute bytes sent to the card are unchanged.

The baseline assembly API remains available without timestamps for internal
B-B staging and tests. The product release stays hidden until validation
evidence, DSS construction, and the archive timestamp complete the B-LTA path.

## Verification

An interoperability test generates an ephemeral RSA-3072 document signer and
an independently rooted timestamp authority. OpenSSL signs the production
signed attributes and issues the RFC 3161 response. Android verifies the token,
binds it to the stored signature value, builds the timestamped CMS, and fills
the production PDF placeholder. OpenSSL parses the result, qpdf validates the
PDF structure, and Poppler validates the detached document signature and its
byte range.

The same test rejects an empty timestamp list, a trusted token made for a
different signature digest, and a verified token after its owner is closed. It
also proves that supplying the same token twice produces one attribute. All
private keys and intermediate artifacts exist only in an operating-system
temporary directory and are deleted afterward.

## Consequences

The document layer can now construct a cryptographically bound PAdES-B-T stage
without accepting arbitrary ASN.1 from callers. Network acquisition,
revocation evidence, a document timestamp, archive validation, and user-facing
orchestration remain separate work. ADR 0022 provides the DSS carrier but does
not claim LT until its material has passed the later validation collector.
