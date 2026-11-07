# ADR 0035: Transport-selecting external-key provider

Status: Accepted

Date: 2026-08-17

Status note, 2026-11-07: `TransportSelectingCardSession`, the USB and NFC
provider views and the provider generations the reader controllers minted
for them moved with the provider to
[refineid-hack's `aosp-keychain-external-key/app-provider/`](https://github.com/refineid/refineid-hack/tree/main/aosp-keychain-external-key/app-provider).
The decision below describes that parked code.

## Context

The privileged KeyChain external-key provider (ADR 0012) consumed only
the retained USB session, so a system browser could reach the card only
through a connected reader. The contactless session (ADR 0034) now
offers the same certificate custody and one-shot signing, and
system-browser login is the product end state for both transports. A
system browser is foreground while this application is stopped, so
whatever the provider consumes must outlive the activity.

## Decision

One provider-facing card session selects across transports. Identity
queries return the first transport holding a card, USB preferred.
Signing routes strictly by the request's provider generation: the
credential is submitted only to the transport that published the
matching identity, and an unknown generation closes the PIN without
touching any card. Every transport mints its generation from the same
positive 63-bit space, which keeps generations distinct across
transports and preserves the established generation-change semantics
when a card moves between transports.

The contactless session becomes application-scoped. Detaching the
activity disables reader mode but keeps the session — the cached public
material and the session CAN — so the provider can serve a foreground
browser. Adapter loss, card loss, card replacement, and process stop
still close the session and zeroize the CAN.

Signing over NFC while this application is in the background depends on
the resting tag staying usable after reader mode suspends; that is a
hardware question, not a design assumption. If the tag does not
survive, the provider's own PIN-prompt activity is the foreground
window in which the resting card can be reacquired before the one-shot
signing operation runs. The observed behavior decides which path ships.

## Verification

Unit tests lock the selector's preference order, generation routing,
identity absence, and PIN custody on unknown generations. System-browser
hardware evidence — the KeyChain chooser offering the card identity and
a PIN-prompted login completing — is pending for both transports on the
patched platform build.

## Physical evidence

On 2026-08-17, on the physical Pixel 4, an open contactless session
survived one minute in the background: returning to the activity
re-armed reader mode, the stack re-polled the resting card, and the
session adopted the fresh tag handle without losing its material. The
same run showed the boundary that remains: the platform later killed
the backgrounded process outright, taking the memory-only session and
CAN with it, which is the intended custody outcome. The privileged
provider is expected to hold the process through a login via KeyChain's
service binding; after a process death the holder reconnects in the
app. Recovery from process death was observed as a clean fresh start.
