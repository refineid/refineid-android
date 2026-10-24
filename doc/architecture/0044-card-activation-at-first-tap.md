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

- **No identity before activation.** A card awaiting activation has no
  identity: nothing of it is read beyond its counters, so no name is shown,
  nothing is stored for it but the access number, and nothing is offered
  to a browser or a paired computer. The scheme therefore comes from what
  the card answered at reset, before anything is read: the three MultiApp
  generations DVV has issued name it (v3 and v4 use the activation code,
  v5 the preset activation PIN; `activation_scheme`, after the Apple
  reference's `FineidCardTypeValues`), from the historical bytes the NFC
  stack reports or from the full answer a reader reports. An unfamiliar
  answer names nothing, and the card is opened as an activated one.
- **Needs from the card.** With a scheme in hand, the open asks the core's
  `activation_needs`: for the activation-code scheme a counter-safe VERIFY
  probe per PIN, where a blocked PIN is a factory-fresh one; for the preset
  scheme the changed-since-manufacture record per PIN. Both run inside the
  secure channel after the PKCS#15 selection and before any identity read,
  on a phone and on a reader alike. A probe the card refuses leaves the
  card treated as activated, so a transient fault never routes an activated
  card to activation. The health probe behind the activation form takes
  the same answer to reset, so it reads no certificate either; for an
  activated card whose answer names no scheme it reads the certificate, as
  the card is activated.
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
  what the card answered at reset; an unnamed scheme gets no attempt, on
  either side of the bridge.
- UCA-3: the app routes an activated card to activation on a stale or
  failed reading (H: the holder enters codes for nothing). CC: a refused
  probe reads as activated; the form re-probes before it submits.

## Verification

Scripted: the classifier against synthetic certificates on both sides of
the cutover, organisational and unfamiliar issuers, unreadable validity, and
malformed or truncated DER; the answer-to-reset table against the three
generations, a full answer and an unfamiliar one; the open reply encoding
and the Kotlin decoder with scheme and needs, and the decoder's refusals.
Hardware, observed on 2026-10-24: over NFC, an activated card opened as
ready, which proves the changed-record read survives the secure channel,
and a card awaiting activation was routed to activation; in a USB reader,
a card awaiting activation answered at reset as a fifth-generation MultiApp
and its changed records reported both PINs waiting under the preset
scheme, which is the table's row and the probe's reading. The activation
itself, which each card serves once, is not yet observed on Android.

## Open question

For the activation-code scheme the core reads a PIN as factory-fresh when
the counter-safe probe answers "blocked" (FINEID S4-1 v4.2 section 4.6.1:
"PIN1 and PIN2 have been blocked"), while the Apple reference records
"reference data invalidated" as the answer a factory-fresh PIN gives and
counts a blocked PIN as one written to since manufacture. Android follows
the core. Which answer such a card gives at the probe is a hardware
observation still to be made on Android; until then the old scheme's
detection is covered by scripted tests only.

## Consequences

Android classifies a card awaiting activation from its answer to reset
alone, where the iPhone reads the certificate's issuance date first and
falls back to the same table; the two agree on every card the table names.
The native crate carries a small X.509 walk for the issuer and the validity
start, used only for an activated card's health report, which the public
core excludes by design.
