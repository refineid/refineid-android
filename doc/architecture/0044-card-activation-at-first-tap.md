# ADR 0044: Card activation detected at the first tap

## Status

Accepted.

## Context

A citizen card that has not been taken into use is recognised on the iPhone
at the first tap, inside the one PACE session that reads the certificate,
and routed to the activation form before anything else. On Android the same
recognition ran only for a card in a USB reader. The contactless open
answered "activated" for every card, on the belief that the probes needed
for the answer end the PACE channel.

FINEID S4-1 section 4.6 names two procedures by issuance generation. Cards
issued before 13 January 2026 ship with both PINs blocked, and the
eight-digit activation code is the PUK: an unblock sets each new PIN. Cards
issued from that day ship with both PINs set to a seven-digit single-use
activation PIN: a change sets each new PIN. The card enforces the entry
length itself, and a wrong length spends a try, so the procedure has to be
known before any entry is sent, and only the PINs the card still waits for
may be asked for: under the preset scheme the activation PIN stops being a
PIN's value the moment that PIN is changed.

## Decision

- **Scheme from the issue date.** DVV defines the cutover by issue date
  alone, so the scheme comes from the validity start of the card's public
  authentication certificate (`activation_scheme`, through the core's
  `ActivationScheme::from_validity_start`), as on the Apple platforms. The
  chip generation does not name it: a Thales MultiApp v5 card with ECC
  keys issued before the cutover uses the activation code. An
  organisational issuer, or a validity start that cannot be read, names no
  scheme, and the card is opened as an activated one.
- **No identity before activation.** The open reads the authentication
  certificate first, inside the secure channel after the PKCS#15
  selection, and classifies it. A card awaiting activation has no identity:
  the certificate serves the classification only, so no name is shown,
  nothing is stored for it but the access number, and nothing is offered
  to a browser or a paired computer.
- **Needs from the card.** With a scheme in hand, the open asks the core's
  `activation_needs`, which reads each PIN's changed-since-manufacture
  record and counter-safe status; an unchanged PIN awaits activation under
  either scheme. It runs on a phone and on a reader alike. A probe the card
  refuses leaves the card treated as activated, so a transient fault never
  routes an activated card to activation. The health probe behind the
  activation form classifies the same certificate the same way.
- **The reply names the procedure.** The contactless open reply for a card
  awaiting activation is the scheme byte and the needs byte and nothing
  else, with the management reply's vocabulary; Kotlin refuses a reply with
  no scheme, no needs, or any other shape. Card management derives the entry
  length from the scheme and never submits an activation for a scheme it
  does not know; the native side refuses the same, instead of guessing the
  newer procedure as it did.
- **Straight to the form.** A reading that says the card awaits activation
  shows the activation form in place of the home screen, from the first
  frame, as the iPhone's flow routes an unactivated card. A holder who
  leaves the form finds the identity row reading "Activate Card" and
  leading back to it; the home screen carries no banner. The identity row
  shows a chevron only where a tap opens a page, so the card-reading prompt
  has none.
- **The access number stays.** PACE proved the card access number against
  the card, so the open keeps it for a card awaiting activation as for an
  activated one: the holder types it once, and a mismatch on a later tap
  forgets it as for any card. Whatever an earlier card left in memory or
  in the store, a name or a certificate, goes with it.
- **Signing waits for an identity.** The home screen offers document
  signing only with an identity read from an activated card, as the
  iPhone's drop area appears with the identity.
- **Every build.** Activation is in release builds as in debug builds, as
  on the Apple platforms.

## STPA

Controller: the app at the first tap. Control action: route the holder to
the activation form, and later send the activation entry to the card.
Feedback: the certificate and the per-PIN probes.

- UCA-1: the app sends an activation entry to a PIN the card has already
  set (H: a try spent on a value that cannot match). CC: the needs come from
  the card per PIN, and the form asks only for the PINs still waiting.
- UCA-2: the app sends an entry of the wrong length, or over the wrong
  command, on a guessed scheme (H: a try spent). CC: the scheme comes from
  the certificate's issue date; an unnamed scheme gets no attempt, on
  either side of the bridge.
- UCA-3: the app routes an activated card to activation on a stale or
  failed reading (H: the holder enters codes for nothing). CC: a refused
  probe reads as activated; the form re-probes before it submits.

## Verification

Scripted: the classifier against synthetic certificates on both sides of
the cutover, organisational and unfamiliar issuers, unreadable validity, and
malformed or truncated DER; the open reply encoding
and the Kotlin decoder with scheme and needs, and the decoder's refusals.
Hardware, observed on 2026-10-24: over NFC, an activated card opened as
ready, which proves the changed-record read survives the secure channel,
and a card awaiting activation was routed to activation. A Thales MultiApp
v5 test card with ECC keys and an authentication certificate issued before
the cutover answers both PIN counters exhausted with the changed flags
unchanged, so it awaits activation under the activation-code scheme. The
activation itself, which each card serves once, is not yet observed on
Android.

## Consequences

Android and the iPhone classify every card by the same rule, the
authentication certificate's issue date. The native crate carries a small
X.509 walk for the issuer and the validity start, which the public core
excludes by design.
