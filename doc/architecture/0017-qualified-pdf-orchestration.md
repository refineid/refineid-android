# ADR 0017: Qualified PDF orchestration

Status: Superseded by [ADR 0046](0046-document-signing-on-core.md)

Date: 2026-08-15

## Context

The PDF writer, canonical CMS encoder, and PIN2 card boundary are independently
strict, but their order is also security-critical. A credential must not be
submitted for a document that cannot be prepared locally. The card signature
must bind the final PDF byte-range digest and the exact qualified certificate,
and no mutable intermediate may accidentally survive into another request.

The current CMS boundary produces PAdES-B-B. The Apple product continues from
that card material through a signature timestamp, validation evidence, and an
archive timestamp before presenting PAdES-B-LTA as complete. Android must keep
that distinction explicit while the later stages are ported.

## Decision

An Android-framework-free coordinator owns one baseline signing request in this
order:

1. prepare the complete incremental revision and fixed byte ranges;
2. read the qualified certificate without a credential;
3. map only RSA-3072 and P-384 certificate profiles to their qualified signing
   algorithms;
4. hash the exact PDF ranges and build canonical certificate-bound CMS signed
   attributes;
5. transfer one `Pin2Submission` and those exact attributes to the retained
   card session;
6. rely on the card boundary's certificate reread and mandatory local
   signature verification;
7. revalidate and assemble CMS, then fill the PDF hole without moving bytes.

Malformed PDF input, unsupported key profiles, and CMS preparation failures
close PIN2 before the credential path. Once the request is transferred, the
card service owns its one-shot consumption. Certificates, signatures, digests,
signed attributes, CMS bytes, and signed output all have explicit ownership;
intermediates are cleared and the returned signed-document owner clears its
buffer when closed.

Failures retain typed document, certificate, card, and CMS causes for terse UI
mapping and sanitized diagnostics. Debug tracing records only operation timing,
public lengths, and typed outcomes. The release implementation remains an
empty sink and is checked after shrinking.

## Verification

Coordinator tests use only synthetic values. They cover both supported key
profiles, exact attribute transfer, fixed-PDF completion, failure before card
access, certificate failure, unsupported profiles before credential use, card
failure, CMS failure on both sides of signing, one-shot PIN2 ownership, and
zeroization of every returned mutable owner. The PDF, CMS, card-signature, and
independent qpdf checks remain separate lower-level gates.

## Consequences

Android can now drive a testable PAdES-B-B journey through the real card
service. This boundary is a construction stage, not an archival-completion
claim. Product completion still requires authenticated RFC 3161 signature
timestamping, LT validation material, a document timestamp, and the associated
failure policy before matching the Apple PAdES-B-LTA promise.
