# ADR 0022: PDF validation-store revisions

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

A PAdES-B-T signature proves when its card signature existed, but long-term
validation also needs the issuing certificates and authenticated OCSP responses
or CRLs. Those bytes belong in the PDF document security store (DSS) after the
signature revision. Appending them must not alter any earlier byte covered by a
signature.

A document may already contain a DSS. Replacing it without understanding its
top-level syntax can silently discard earlier evidence, VRI data, or extensions.
Searching for `/DSS` text is unsafe because the same bytes may occur inside a
string or nested dictionary. PDF source is byte-oriented Latin-1 syntax and
must not be transcoded through UTF-8.

## Decision

`PdfValidationStore.append` writes one incremental revision and preserves the
newest cross-reference shape: classic and hybrid inputs receive a table, while
cross-reference-stream inputs receive a stream. Each distinct new certificate,
OCSP response, and CRL becomes an unfiltered stream whose `/Length` covers
exactly the evidence bytes. A new DSS dictionary references those streams, and
a new version of the existing catalog references that DSS. The prior document
remains an exact prefix of the result.

The existing token-aware PDF parser resolves a direct DSS or one indirect DSS
dictionary. Direct or indirect arrays under `/Certs`, `/OCSPs`, and `/CRLs` are
retained in first-seen order. An existing direct or indirect `/VRI` dictionary
and unrecognized top-level DSS entries are copied without re-encoding. Escaped
names are compared by decoded value while their original spelling is retained.
An unreadable prior store fails closed instead of being replaced.

`PdfValidationMaterial` owns copies of its inputs, clears transient copies and
owned buffers, and refuses use after close. It rejects empty blobs, excessive
counts, certificates or OCSP answers above 64 KiB, CRLs above 16 MiB, and more
than 64 MiB of new evidence in one revision. The CRL ceiling deliberately
covers the public FINEID lists observed above 13 MiB while keeping allocation
bounded.

The DSS layer is a carrier, not an authenticity decision. It does not parse or
trust certificates, OCSP answers, or CRLs. The validation-material collector
must authenticate complete signer and timestamp-authority paths before product
orchestration may treat this revision as the LT stage.

## Verification

Unit tests cover first and repeated stores, content deduplication, owner
lifetime, all material bounds, direct and indirect category arrays, direct and
indirect VRI dictionaries, extension retention, malformed-store rejection,
escaped names, nested and quoted false matches, raw eight-bit catalog and DSS
values, and token-aware trailer identifiers. They also prove that a DSS
appended after a signature preserves the entire signed revision as an exact
prefix and that a stream-shaped input retains its shape. qpdf independently
accepts the resulting file.

## Consequences

Android can now preserve validation material in the correct incremental PDF
layer without weakening an earlier signature. This does not yet constitute
PAdES-B-LT: certificate-path construction and signed, current revocation
verdicts remain mandatory. Archive timestamping and final independent B-LTA
validation follow those checks.
