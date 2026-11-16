# ADR 0032: Debug timestamp-authority settings integration

## Status

Accepted. This supersedes ADR 0030's fixed debug timestamp-authority and
bundled timestamp-root decisions. Its pinned FINEID signer trust, bounded
transport, retry, cancellation, and release-isolation decisions remain active.

## Context

ADR 0031 adds Android Keystore custody for the Apple-compatible ordered
timestamp-authority configuration, but no user surface or signing consumer.
The debug PDF harness still constructs one fixed HTTPS authority and authenticates
it with a bundled offline root. That no longer represents the Apple product,
where the holder selects the service and runtime EU trusted lists authenticate its tokens.

The integration must not perform SharedPreferences or Keystore work on the UI
thread. More importantly, it must validate and decrypt authority configuration
before PIN2 reaches the card. Discovering broken configuration only after a
qualified signature would waste a credential use and a card operation.

## Decision

Debug builds expose one terse expandable `Timestamp` control on the main
screen. It contains only Address, Username, Password, Up, Down, Delete, Add,
Save, Restore, Close, and coarse state labels. There is no explanatory product
copy. The list retains one through eight authorities, preserves order, and
uses Restore to recover the shipped Apple-compatible endpoint.

The password uses Material 3 `SecureTextField` with hidden text and password
semantics. Editor state is retained only with `remember`, never
`rememberSaveable`. Closing or replacing an editor clears its address, username,
and password buffers. Copying a password into a configuration uses a mutable
`CharArray`, which is cleared immediately after the configuration takes its own
copy. The activity continues to disable screenshots, autofill, and content
capture for the complete view hierarchy.

Initial load, Save, and Restore run on `Dispatchers.IO`. Loaded configurations
remain owned until their values have been transferred on the main dispatcher,
then are closed on every success, failure, or cancellation path. UI failures
remain the terse `Error`; storage details and field values never enter an
exception, status label, test output, or trace.

Each debug signing attempt loads the latest stored list and constructs its
network sources on the I/O dispatcher before calling the card coordinator.
Only after that succeeds is ownership of PIN2 transferred to the coordinator.
The configured sources stay bound to that one attempt across the asynchronous
card callback and are closed after failure, cancellation, archival completion,
or harness disposal.

`DebugDocumentSigningSources` converts every transferred holder configuration
to `SigningTimestampAuthority.configured`. Timestamp tokens therefore use the
independent runtime EU trusted-list timestamp anchors described in
[ADR 0050](0050-trusted-list-timestamps.md). The old debug-only Sectigo root resource is
removed. Fingerprint-pinned FINEID signer anchors remain unchanged.

The shipped authority is credential-free HTTPS. Holder
credentials remain restricted to HTTPS. Multiple authorities are tried once
in holder order; the sole authority retains the existing bounded transient
retry. Address probing or scheme inference is not performed merely by opening
settings.

The settings surface remains debug-only while release document signing and
release network access are intentionally absent. The common repository and
custody boundary remain available for later product enablement. Release still
contains no logging calls, Internet permission, cleartext permission, or
manual signing surface.

## Verification

Google's native Compose UI Test v2 drives the surface on the Android 13 Pixel
4. Synthetic tests prove secure password semantics, ordered reordering, an
empty-but-present Basic password, Save and Restore on non-main threads, and
reload of the shipped authority. Isolated Keystore tests from ADR 0031 remain
unchanged.

A source-construction instrumentation test proves ownership transfer, one
configured authority, and all four pinned FINEID issuers without network
access. A live card-free test obtains and authenticates a request-bound RFC
3161 token through the shipped configured authority. A second live test reads
the development card's qualified certificate without a credential and reaches
an authenticated validation result through the same configured path. No PIN,
identity, certificate, token, endpoint response, device identifier, or network
address is recorded.

## Consequences

Debug PDF signing now consumes the same ordered holder settings and credential
custody model as Apple, and configuration failure occurs before any PIN2 card
operation. The fixed debug timestamp root is no longer shipped or maintained.

Release enablement, scheme-less address resolution after explicit holder
editing, and a successful full B-LTA run with a non-revoked card remain later
milestones. Normal-browser authentication remains the product boundary and is
independent of this debug document-signing surface.
