# ADR 0030: Debug archival network integration

## Status

Superseded by [ADR 0046](0046-document-signing-on-core.md).

## Context

ADR 0029 leaves timestamp and validation-material sources injected. The debug
document harness needs a real PAdES-B-LTA target without weakening the release
application, trusting the Android system root set implicitly, retaining the
card session during network work, or blocking the UI thread.

The Apple product retries one configured timestamp authority after transient
failures with capped exponential delay. When several authorities are
configured, it asks each once in order. Android needs the same selection
semantics while preserving interruption for coroutine cancellation.

## Decision

The debug build contains one explicit authority configuration:

- `https://timestamp.sectigo.com/qualified`;
- the self-signed `Sectigo Qualified Time Stamping Root R45` as the exclusive
  offline timestamp anchor; and
- no credentials.

The root certificate is copied from Sectigo's published
[`SectigoQualifiedRootCAs.zip`](https://www.sectigo.com/uploads/files/SectigoQualifiedRootCAs.zip)
bundle and pinned to SHA-256 fingerprint
`F871F8976B4068D700D5F281084B4A29EAF4B8F35743330BA062FAB46F58C2ED`.
The certificate and authority URL exist only in the debug source set. The
release manifest still has no Internet permission and the release artifact has
neither this endpoint configuration nor the root resource.

The debug manifest permits cleartext because the current TSA and FINEID
certificate profiles publish AIA, OCSP, and CRL locations over HTTP. Authority
requests remain configured as HTTPS, Basic credentials remain forbidden on
HTTP, and every certificate-controlled request still passes the public-address,
DNS-answer, redirect, timeout, and size policy from ADR 0028 before the
transport connects to its vetted numeric address. The debug WebView remains
pinned to its single HTTPS diagnostic origin. Release cleartext remains off.

Signer-path trust uses the four existing fingerprint-pinned public FINEID
intermediates. They are supplied both as exclusive signer anchors and as path
candidates. The timestamp token retains the exact root that authenticated its
TSA path, so the validation collector walks the TSA path to that same anchor.

`NetworkQualifiedPdfTimestampSource` owns its authority configurations. A sole
authority is retried only for transport failures and the designated transient
HTTP statuses. Delays are 1, 2, 4, 8, 16, 32, then 60 seconds. Multiple
authorities are each attempted once in order. Protocol rejection, malformed or
untrusted tokens, random failure, and configuration failure are terminal for
an attempt. No authority address or underlying exception survives in the
document-layer result. An interrupted retry escapes rather than becoming a
normal signing failure.

`NetworkQualifiedPdfValidationSource` owns copies of signer anchors and path
candidates. Authenticated collector failures retain their typed path role;
transport and unexpected source failures become a coarse validation-source
failure. Closing either source clears its clearable owned configuration.

The debug harness now asks the card coordinator only for its owned prepared
signature. It then runs all timestamp, validation, DSS, and archive work with
`runInterruptible` on the I/O dispatcher. Lifecycle cancellation interrupts
retry waits, every prepared or completed document is closed on cancellation,
and the Compose UI retains only its existing terse signing, saving, success,
unavailable, and error states.

## Verification

Host tests cover the exact retry schedule and cap, transient versus terminal
classification, ordered multi-authority fallback without waits, interruption,
configuration ownership, trust copies, clearing, typed validation failure, and
coarse network failure.

An instrumentation test loads the debug root and all four signer anchors on a
physical Pixel without network access. A separate opt-in test sends only a
synthetic SHA-384 digest to the configured authority and requires an exact
request-bound token whose certificate path verifies under the pinned root. On
2026-08-16 that live check passed on the Android 13 Pixel 4 over wireless
debugging. No card, credential, identity, response, token, or device/network
identifier is written to test output or source control.

A third opt-in test reads the qualified certificate without a credential and
runs both pinned paths through live revocation retrieval. It accepts only
complete authenticated material or the collector's authenticated, role-bound
`REVOKED` verdict. That check also passed on the connected development card;
the same run first proved that keeping debug cleartext disabled correctly
failed closed as `REVOCATION_UNAVAILABLE`.

The normal verification task inspects the merged release manifest and fails if
it requests Internet access or does not explicitly disable cleartext traffic.

## Consequences

The debug file-picker path now targets PAdES-B-LTA with live HTTPS timestamp
trust, policy-bounded HTTP certificate evidence, and cancellable off-main
orchestration. Full live document completion is still intentionally unclaimed
because the available development card is revoked. Product release still needs
holder-editable authority and credential storage, a reviewed production HTTP
revocation policy, and a non-revoked-card completion test.
