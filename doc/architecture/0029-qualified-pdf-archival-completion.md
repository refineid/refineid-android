# ADR 0029: Qualified PDF archival completion

## Status

Accepted.

## Context

The qualified-PDF coordinator in ADR 0017 originally consumed the locally
verified card signature immediately to produce PAdES-B-B. The timestamp,
validation-material, DSS, and document-timestamp components were subsequently
implemented as separate strict layers. Product orchestration now needs to join
them without retaining the card session across network work or weakening any
ownership boundary.

Timestamp and revocation requests are synchronous at the protocol boundary but
must never run on the Android UI thread. Live authority selection, offline
trust, retry, cancellation, and product exposure are separate configuration
decisions.

## Decision

Qualified card signing may now return a one-use
`PreparedQualifiedPdfSignature`. It owns the prepared PDF placeholder, exact
signed attributes, locally verified card signature, and qualified signer
certificate. The existing baseline-signing entry point remains compatible by
immediately consuming this capability as PAdES-B-B.

`QualifiedPdfArchivalCompletion` consumes the capability synchronously in this
fixed order:

1. copy the qualified signer certificate and derive SHA-384 over the stored CMS
   signature value;
2. acquire a verified RFC 3161 token for that exact signature digest;
3. assemble the timestamped CMS and fill the prepared PDF as PAdES-B-T;
4. collect authenticated signer and TSA validation material using the signer
   certificate and signature timestamp;
5. append that material as a DSS and prepare the whole-document timestamp
   revision;
6. acquire a verified RFC 3161 token for the exact archive digest; and
7. complete the document timestamp and return the owned PAdES-B-LTA document.

Timestamp and validation access are injected through narrow source interfaces.
Both digests and the signer-certificate input are borrowed. Verified timestamp
tokens and validation material transfer to the orchestrator. Each returned
timestamp is checked again against the requested digest before use.

All intermediate owners close on every result. Digest, certificate, signed
attribute, card-signature, CMS, timestamp-token, validation-material, and
intermediate-PDF buffers are cleared where the runtime permits. Only the final
`SignedPdfDocument` transfers to a successful caller. Failures preserve the
timestamp phase and typed CMS, PDF, and validation-path causes, while source
availability and unexpected failures remain coarse and retain no network
address, response, credential, or throwable.

Debug builds trace only stage names, duration, public document length, and
typed outcome. The release trace sink remains empty and release bytecode is
checked after shrinking.

### Level below B-LTA

The caller passes a `PadesLevelPolicy`, and the signing screen derives it
only from `BuildConfig.DEBUG` through `PadesLevelPolicy.forBuild`; no setting
selects it at run time.

- A release build uses `LONG_TERM_ONLY`. A failure at any step discards the
  card signature and every intermediate document, and nothing is saved. The
  holder reads that the signature was made, why long-term completion failed
  (for example that the issuer of the certificate could not be found), that
  no signed document was made, and what to do.
- A debug build uses `HIGHEST_REACHED`. A failure of the signature timestamp
  returns the PAdES-B-B document; a failure after step 3 returns a copy of the
  PAdES-B-T document. The result names the level and the failure. The saved
  file name ends in `-dev-B-B` or `-dev-B-T`, and the status line says it is a
  development-build document without long-term validation material, and why.

ASiC-E completion has no reduced level: a failure discards the container in
both builds.

The certificate chain is not checked before PIN 2 is entered. On a
contactless card the signing certificate is read inside the tap that the
holder starts after entering PIN 2, so a check before the prompt would need
the certificate earlier than the session reads it. A failure after signing
therefore spends no PIN retry, only the holder's effort.

STPA. Controller: the signing screen. Control action: hand a signed document
to the save picker. UCA: providing a document below B-LTA in a release build
as if it were a long-term signature leads to a signature that cannot be
validated later. CC: a release build refuses every document below B-LTA, the
policy is fixed at compile time, and a development document carries its
level in its name and status line.

## Verification

Framework-free unit tests prove the exact phase order, both requested digest
lifetimes, DSS-before-document-timestamp ordering, successful PDF parsing,
one-use completion, and clearing of all observable owners. They exercise
unavailable and wrong-imprint tokens independently at the signature and
archive phases, typed validation failure, coarse validation-source failure,
and timestamped-CMS failure. They prove that the release policy refuses
each reducible failure and that the debug policy returns the B-B or B-T
document it reached. Existing cryptographic interoperability tests
continue to independently validate the lower-level PAdES-B-T and PAdES-B-LTA
output with OpenSSL, qpdf, and Poppler.

No live authority, card identity, credential, certificate, document, or
network identifier is used by these tests or stored in the repository.

## Consequences

The document layer now has a complete injected PAdES-B-LTA product sequence,
and the card-owned material no longer needs to survive as loose byte arrays.
The sequence is deliberately not reachable from product UI yet. Shipping still
requires approved signer and TSA trust configuration, retry and cancellation
policy, debug-only off-main integration, and a clear Android policy for any
authenticated HTTP certificate endpoints.
