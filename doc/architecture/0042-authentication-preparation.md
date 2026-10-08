# Authentication preparation for Browser and Remote Access

Status: Active

## Entry behavior

Browser is actionable on an NFC-capable phone before identity priming. Opening
it prepares local authentication before creating the WebView. Creating a Remote
Access offer or enabling Remote Access uses the same preparation. Cancelling
preparation leaves pairing management accessible; disabling sharing and deleting
pairings do not need card credentials.

A connected USB reader with a present card takes priority. Otherwise preparation
uses NFC. It collects only missing CAN and PIN1, opens the card, reads the
public authentication certificate, and verifies PIN1 before continuing. A primed
certificate and previously accepted local PIN1 allow immediate continuation.
Reader availability, rather than the colour of a feature icon, determines whether
an action can start.

## Proof and custody

The standalone JNI verification operation selects PKCS#15, resolves the PIN
reference scheme, probes the retry state without presenting a credential, and
applies the existing consumer authentication retry policy. It then sends exactly
one credential-bearing VERIFY. It does not generate a signature. An already
validated card session is insufficient proof of a newly entered candidate:
FINEID S1 v4.2 section 3.5 distinguishes header-only status checks from VERIFY
with verification data. Successful credential verification resets the retry
counter and establishes the validated state.

Accepted PIN1 stays on the phone in owned, zeroizable memory. For a primed NFC
identity it also uses the existing Android Keystore ciphertext store. RAPP never
transports PIN1; remote callers receive public certificates and signature results.
Fresh browser or RAPP candidates require standalone verification before they can
be retained, even if an open card session was already validated.

A primed NFC certificate can be supplied before another tap. Signing waits for a
local card session when needed and uses the accepted local PIN1. A retained
session can sign without another credential VERIFY while its validated state
remains active. A new card session must establish its own validated state.

## Failure and lifecycle

A wrong or locked PIN stops the operation without retry. The app clears accepted
PIN1, CAN, primed identity, certificates, photo and session caches and disconnects
the active remote connection. Established pairings remain. Rejected candidates
remain represented only by the existing process-local keyed negative cache.

Preparation owns its continuation and submitted buffers. Cancellation suppresses
the continuation and wipes the buffers. Transport and custody generations reject
superseded verification results. Storage clearing completes before a new
preparation can retain credentials; stale successful operations cannot restore a
cleared PIN cache.

Verification runs only on the exact card session that preparation proved ready.
It never waits for, or prompts for, another card. Cancellation before the
credential command starts sends no PIN. A VERIFY already on the card runs to
completion. Its rejection is recorded and tears down custody on the thread that
observed it, even when the holder has cancelled meanwhile. The rejection path
owns its own copy of the candidate. An acceptance that arrives after
cancellation is discarded and never retained.

When an NFC verification finds its held secure channel gone, it releases that
channel's native keys before reconnecting and running PACE again. A reconnect
that fails, or ends on an activation-required card, leaves no native session
behind.

The app trusts card continuity within a prepared session. It does not introduce
periodic certificate or card fingerprint checks. Credential rejection tears down
the cached state on the first reported failure.

## Evidence boundaries

Rust tests exercise standalone VERIFY, rejection even with an already validated
session, and retry-policy refusal. JVM tests cover preparation, ownership,
cancellation before and during an in-flight VERIFY, negative caching, stale cache
retention, and malformed JNI replies. The NFC reconnect path and native key release
have no JVM test, because they need a live tag handle.
Android instrumentation exercises the UI and shipped JNI library using synthetic
card replies. These checks do not prove NFC field stability, physical USB-reader
behaviour, or successful authentication at Suomi.fi. Those require a holder-entered
PIN on a physical card and an observed site authentication.
