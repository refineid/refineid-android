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

- **Scheme from the certificate.** `activation_scheme` in the native crate
  reads the authentication certificate's validity start and applies the
  core's cutover rule (`ActivationScheme::from_validity_start`). An issuer
  whose common name marks an organisational card answers nothing, since
  section 4.6 covers citizen cards alone. When the validity cannot be read,
  the issuer's generation marker and key-family letter stand in; anything
  unfamiliar answers nothing. This is the Apple reference's
  `ActivationScheme.classify`, line for line.
- **Needs from the card.** With a scheme in hand, the open asks the core's
  `activation_needs`: for the activation-code scheme a counter-safe VERIFY
  probe per PIN, where a blocked PIN is a factory-fresh one; for the preset
  scheme the changed-since-manufacture record per PIN. Both run inside the
  secure channel after the PKCS#15 selection and the certificate read, as
  on the iPhone. A probe the card refuses leaves the card treated as
  activated, so a transient fault never routes an activated card to
  activation.
- **The reply names the procedure.** The contactless open reply for a card
  awaiting activation carries the scheme byte and the needs byte ahead of
  the certificate, with the management reply's vocabulary; Kotlin refuses a
  reply with no scheme or no needs. Card management derives the entry
  length from the scheme and never submits an activation for a scheme it
  does not know; the native side refuses the same, instead of guessing the
  newer procedure as it did.
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
  the certificate's issuance date; an unnamed scheme gets no attempt, on
  either side of the bridge.
- UCA-3: the app routes an activated card to activation on a stale or
  failed reading (H: the holder enters codes for nothing). CC: a refused
  probe reads as activated; the form re-probes before it submits.

## Verification

Scripted: the classifier against synthetic certificates on both sides of
the cutover, organisational and unfamiliar issuers, unreadable validity, and
malformed or truncated DER; the open reply encoding and the Kotlin decoder
with scheme and needs, and the decoder's refusals. Hardware: an activated
card at the first NFC tap opens as ready, which proves the changed-record
read survives the secure channel; a card awaiting activation is the open
item, since each one serves once.

## Consequences

Android and the Apple platforms classify the same way from the same
certificate fields. The native crate carries a small X.509 walk for the
issuer and the validity start, which the public core excludes by design.
