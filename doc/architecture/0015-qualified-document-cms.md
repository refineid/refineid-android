# ADR 0015: Qualified-document CMS

Status: Superseded by [ADR 0046](0046-document-signing-on-core.md)

Date: 2026-08-15

## Context

A PDF signature first signs a canonical CMS signed-attribute value and then
places the resulting detached SignedData in the PDF signature container. Any
change in the certificate, document byte-range digest, attribute encoding, or
signature representation must fail closed. The document layer must also keep
ASN.1 and PDF concerns outside the reusable smart-card core.

The card returns fixed-width raw signatures. RSA-3072 already has the CMS
shape, while P-384 returns `r || s` and therefore needs a canonical X9.62 DER
pair before it is carried in SignerInfo. PAdES owns signing time in the PDF
signature dictionary; adding a CMS signing-time attribute changes the profile.

## Decision

The Android document package owns a minimal strict DER codec and canonical
detached CMS assembly. It has no Android framework dependency and accepts only
the two qualified-signing algorithms already enforced by the card boundary.

The exact signed value is a DER SET containing only:

1. content-type with id-data;
2. message-digest with the 48-byte SHA-384 PDF byte-range digest; and
3. signing-certificate-v2 with an explicit SHA-384 ESSCertIDv2 hash of the
   exact signer certificate.

The SET form is sent unchanged to the card and is retagged to SignerInfo's
implicit context-specific field without rebuilding it. Assembly reparses the
message digest, rebuilds all three attributes, and requires byte-for-byte
canonical equality. It parses the certificate, checks its public-key profile,
copies the issuer and serial directly from TBSCertificate, and verifies the
signature over the exact signed-attribute bytes before emitting CMS.

RSA-3072 signatures remain modulus-wide and use SHA-384-with-RSA with a NULL
parameter. P-384 `r || s` signatures become canonical DER and use
ECDSA-with-SHA-384 with absent parameters. SignedData carries one signer
certificate, detached id-data content, SHA-384 with absent parameters, one
SignerInfo, and no unsigned attributes.

Timestamp tokens and revocation evidence are not accepted by this boundary
yet. They require typed validation before CMS assembly rather than an API that
can embed arbitrary ASN.1 supplied by a caller.

## Verification

Unit tests cover strict DER lengths, integers, OIDs, SET ordering, safe
retagging, malformed encodings, canonical attribute reconstruction, raw
issuer-and-serial extraction, certificate/profile rejection, and malformed
signature shapes. Public-only known-answer fixtures independently generated
for RSA-3072 and P-384 prove local signature verification and exact CMS
signature representation. Both production CMS results also parse as detached
SignedData with OpenSSL.

## Consequences

The result is the deterministic PAdES baseline CMS payload needed by the PDF
placeholder layer. It is not yet a complete signed document: bounded PDF
incremental update, holder-facing orchestration, independent PDF validation,
trusted timestamping, and archival revocation evidence remain separate work.
