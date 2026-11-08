# ADR 0049: XAdES archive timestamp for ASiC-E

## Status

Accepted. Maintainer decision of 2026-11-08: release builds produce only
long-term archival (B-LTA) signatures for every format; development builds
keep the level reached and name the file by it.

## Context

The PDF path reaches PAdES-B-LTA with a document timestamp over the DSS
(ADR 0025, ADR 0029). The ASiC-E path signed its XAdES signature with a
signature timestamp, CertificateValues and RevocationValues, and stopped:
XAdES-B-LT, with no archive timestamp. ETSI EN 319 132-1 V1.3.1 table 2 of
clause 6.3 makes `xadesv141:ArchiveTimeStamp` mandatory at XAdES-B-LTA and
forbids the 1.3.2-namespace `ArchiveTimeStamp` there. A B-LT container
cannot be validated once the signer's or the authority's certificates expire
or their algorithms weaken; the archive timestamp is what carries it past
that point.

refineid-core (Rust) and refineid-apple (Swift) write the same element with
the same bytes, so a container from any of them reads the same everywhere.

## Decision

`QualifiedAsicArchivalCompletion` completes a prepared ASiC-E signature in
this order:

1. a verified RFC 3161 token over SHA-384 of the canonical
   `ds:SignatureValue` element (the signature timestamp);
2. authenticated validation material for the signer and that token's
   authority (ADR 0024), written as CertificateValues and RevocationValues;
3. a verified RFC 3161 token over the archive imprint below, from the same
   injected timestamp source the PDF archive timestamp uses; and
4. the container, with the archive timestamp last in
   `UnsignedSignatureProperties`, Id `SIG-1-ATS-0`.

The archive imprint follows clause 5.5.2.3, not the distributed case, and
uses the signature timestamp's digest, SHA-384. Concatenated without
separators:

- each data object's content in `ds:Reference` order (a detached reference
  without transforms dereferences to an octet stream), then the canonical
  SignedProperties (the reference with the exclusive-canonicalisation
  transform);
- the canonical SignedInfo, SignatureValue and KeyInfo;
- every unsigned signature property before the archive timestamp, in
  document order;
- nothing for `ds:Object`, whose only content is the QualifyingProperties.

The writer has no canonicaliser: every element is written already in
Exclusive XML Canonicalization form, so the canonical form of each subset is
its own bytes. Each subset the imprint digests alone - KeyInfo, each
SignatureTimeStamp, CertificateValues, RevocationValues and the archive
timestamp - declares the prefixes it visibly uses at its apex, and a
descendant declares one no ancestor in the subset uses, such as `ds` on a
timestamp's CanonicalizationMethod and the 1.3.2 `xades` prefix on the
archive timestamp's EncapsulatedTimeStamp. Each property is written without
a trailing line break; the line breaks between them lie outside every
subset.

The archive token is accepted only when its message imprint equals the
requested digest and its signer certificate, verified chain and trust
anchor all appear in the CertificateValues already written. The collector
walks the signature timestamp authority's path to its anchor and gathers the
revocation evidence of every certificate on it, so the same certificates
mean the container already holds what a verifier needs for the archive
token; a token from another path is refused rather than written with
evidence the container lacks.

### Levels

The signing screen passes `ArchivalLevelPolicy.forBuild(BuildConfig.DEBUG)`,
the same compile-time policy the PDF path uses.

- A release build uses `LONG_TERM_ONLY`. A failure at any step - no
  signature or archive token, a token for another imprint, an archive token
  whose path the CertificateValues do not cover, failed or unavailable
  validation material - discards the card signature, and no container is
  produced or saved. The holder reads that the signature was made, why, and
  that nothing was saved.
- A debug build uses `HIGHEST_REACHED`. A lost signature timestamp yields
  XAdES-B-B, failed validation material XAdES-B-T, and a lost archive
  timestamp XAdES-B-LT. The file name ends in `-dev-B-B`, `-dev-B-T` or
  `-dev-B-LT` before `.asice`, and the status line names the format, the
  level and the cause.

The coordinator no longer finishes a container on its own; every container
passes through this completion.

STPA. Controller: the signing screen. Control action: hand a signed
container to the save picker. UCA: providing a container below B-LTA in a
release build as if it were a long-term signature leads to a signature that
cannot be validated later (the hazard ADR 0029 records for PDF). CC: a
release build refuses every container below B-LTA, the policy is fixed at
compile time, an archive token is written only for the exact imprint and a
covered path, and a development container carries its level in its name and
status line.

## Verification

JVM unit tests drive the completion with a synthetic timestamp source. They
check that the container holds exactly one `xadesv141:ArchiveTimeStamp`,
after CertificateValues and RevocationValues and last among the unsigned
signature properties, and that its token was issued for the digest the test
recomputes by slicing every input element out of the written XML. They prove
that the release policy refuses each reducible failure with no container and
that the debug policy returns the B-B, B-T or B-LT container it reached, with
its `-dev-` name.

An interoperability test signs a container with an OpenSSL key, timestamps
it with an OpenSSL authority and collects that authority's material through
the production collector. OpenSSL verifies both tokens against digests
recomputed from the written XML, and `AsicValidator` accepts the container.
Setting `REFINEID_LTA_SAMPLE_OUT` to a path writes that container there for
other verifiers; nothing is written otherwise.

## Consequences

Both Android formats now reach B-LTA in release builds or produce nothing.
`AsicValidator` checks the signature value and reference digests; it does
not verify either timestamp token.
