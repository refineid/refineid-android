# ADR 0025: PDF archive timestamp

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

PAdES-B-LTA needs a document timestamp after the PAdES-B-T signature and its
authenticated long-term validation material. Timestamping the PDF before the
DSS would leave that evidence outside the archive timestamp. Accepting a token
for another digest would make the final revision appear protected when it is
not.

The prepared PDF revision retains the complete document until an RFC 3161
response returns. That state must have an explicit lifetime and must not be
silently reusable after completion.

## Decision

`PdfArchiveTimestamp.prepare` first appends the `PdfValidationMaterial` produced
by the authenticated collector from ADR 0024. It then appends a
`/Type /DocTimeStamp` revision with `/SubFilter /ETSI.RFC3161` and computes
SHA-384 over the revision's exact PDF byte ranges. The DSS therefore precedes
the document timestamp and is covered by it.

The result is a one-use `PreparedPdfArchiveTimestamp`. It exposes a copy of the
digest for timestamp acquisition but accepts only an open
`VerifiedTimestampToken` whose authenticated message imprint equals that exact
digest. A mismatch is a typed failure and leaves the preparation available for
the correct response. Successful completion consumes the preparation and
returns an owned `SignedPdfDocument`.

PDF placeholders now have an explicit close operation. Closing clears their
retained document, and every later access fails. The incremental builder clears
its transient revision after the placeholder takes ownership. Qualified-signing
orchestration closes the placeholder on every success and failure path.

No transport or logging is part of this layer. A product adapter must acquire
timestamps and validation evidence away from the UI thread with bounded
network operations, then pass only authenticated capabilities into assembly.

## Verification

Unit tests prove DSS-before-timestamp ordering, exact token embedding,
single-use and closed-owner behavior, and rejection of a token for another
digest without consuming the correct preparation.

The interoperability test generates all signing, timestamp-authority,
certificate, and CRL material in an operating-system temporary directory. It
creates a PAdES-B-T signature, authenticates the TSA path and its signed CRL,
collects the resulting validation material, appends the DSS, and issues the
final document timestamp. The production timestamp verifier checks the token,
OpenSSL independently verifies it against the exact PDF digest and temporary
root, qpdf accepts the final PDF structure, and Poppler identifies the original
valid signature plus a document timestamp covering the whole final file.
Poppler currently reports ETSI RFC 3161 document timestamps as unverified, so
the OpenSSL check is the independent cryptographic timestamp assertion.

No private key, identity, certificate, revocation list, or generated PDF is
checked into the repository.

## Consequences

The core document layer can assemble the complete synthetic PAdES-B-LTA order:
card signature, signature timestamp, authenticated validation material, DSS,
and final document timestamp. Release exposure still requires bounded live TSA
and validation transports, product failure policy, and user-facing
orchestration.
