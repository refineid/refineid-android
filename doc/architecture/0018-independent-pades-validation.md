# ADR 0018: Independent PAdES validation

## Status

Accepted.

## Context

The PDF writer, CMS encoder, and orchestration tests can agree with one another
while sharing the same defect. A complete baseline signature therefore needs a
verifier that does not reuse any RefineID parsing or cryptographic code.

Permanent private-key fixtures are also inappropriate for a public repository,
even when they are labelled as synthetic.

## Decision

An optional JVM interoperability test creates fresh RSA-3072 and P-384 keys and
self-signed certificates with OpenSSL inside an operating-system temporary
directory. OpenSSL stands in for the card and signs the exact attributes handed
to the qualified-card boundary. The production coordinator, PDF writer, and CMS
encoder build each signed PDF.

Two independent tools then inspect that output:

- `qpdf --check` must accept the complete incremental PDF revision.
- Poppler `pdfsig -nocert` must validate the cryptographic signature and report
  that it covers the whole document.

The test changes one signed byte while preserving a valid PDF header and
requires `pdfsig` to reject the signature. Temporary certificate, signature,
attribute, PDF, and private-key files are deleted after each run. No generated
key material enters the source tree or test fixtures.

Like the Apple interoperability tests, this check skips when any external tool
is unavailable. It runs as part of the ordinary JVM suite on development hosts
that provide OpenSSL, qpdf, and pdfsig.

## Consequences

Both supported qualified-key profiles now cross an independent PAdES boundary.
The result is evidence for PAdES-B-B only; timestamp, validation evidence, DSS,
and document archive timestamp work remain required before release exposure.
