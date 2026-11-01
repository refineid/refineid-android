# ADR 0024: Validation-material collection

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

PAdES-B-LT needs complete certificate paths and authenticated current status
for every non-anchor certificate in both the document-signer and timestamp-
authority paths. Returning a partial path or an unauthenticated server body as
PDF validation material would turn a transport failure into a false trust
claim.

Certificate extensions are untrusted input. Path length, address count, input
size, network attempts, and retained bytes therefore need explicit bounds.
Trust must also terminate only at an anchor approved by the policy that
authenticated the corresponding signature.

## Decision

`ValidationMaterialCollector` accepts the card certificate, already verified
timestamp-token capabilities, explicit card-path anchors, optional issuer
candidates, and injected GET, POST, clock, and secure-random dependencies. Its
core performs no implicit networking and emits no logs.

Timestamp-authority paths are checked before the document-signer path so a TSA
revocation cannot be hidden by a later card-path failure. At most two paths are
accepted, each complete path is capped at 12 certificates, and each certificate
may cause at most three distinct AIA, OCSP, or CRL addresses to be tried. A
self-issued name is not an anchor. The exact certificate bytes must match one
of the path's explicit anchors.

Issuer candidates come from verified timestamp paths, embedded timestamp
certificates, caller-supplied candidates, or a bounded AIA fetch. Fetched
certificates must be one exact DER object or one strict standard-PEM object.
Every selected relationship passes the direct-issuer check at the path's
reference time. The TSA reference time is its authenticated generation time;
the document path uses the first signature timestamp, or the evidence time when
no timestamp exists.

Every non-anchor certificate needs status at one fixed evidence time. The
collector first sends a fresh 32-byte nonce-bound OCSP request to each bounded
responder. If no authenticated good response is available, it tries each
bounded full-CRL address. A secure-random failure does not prevent a valid CRL
fallback, but is reported if no CRL succeeds. An authenticated revoked answer
is terminal and retains whether it belongs to the document signer or timestamp
authority. Unknown, malformed, stale, mismatched, or unauthenticated answers do
not become evidence.

Available parents above an already authenticated service anchor are retained
only as best-effort enrichment and stay within the unused path-depth budget.
They cannot change the strict trust result below the anchor. Output is ordered,
deduplicated, owned, and bounded. It excludes the document-signer leaf already
present in CMS while retaining the TSA signer, selected issuers, and only
authenticated OCSP or canonical full-CRL bytes.

The dependency call is synchronous. A live adapter must invoke collection away
from the UI thread, apply transport timeouts and response-size limits, and
return fresh owned byte arrays. Release logging remains absent.

## Verification

Unit tests generate ephemeral P-256 keys, exact X.509 certificates, a signed
nonce-bound OCSP response, and signed good and revoked CRLs at runtime. They
cover OCSP preference, CRL fallback, random failure, unavailable issuers and
status, explicit and missing anchors, malformed signers, role-preserving card
and TSA revocation, TSA-first ordering, deduplication, path bounds, address
bounds, and strict DER/PEM certificate input. No private key or identity fixture
is checked into the repository.

## Consequences

The collector can now produce `PdfValidationMaterial` whose contents have
passed path and revocation authentication. The next stage must integrate it
after PAdES-B-T, append the DSS as the LT revision, issue the archive timestamp,
and independently validate the resulting PAdES-B-LTA document.
