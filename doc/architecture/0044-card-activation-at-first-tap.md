# ADR 0044: Card activation detected at the first tap

## Status

Accepted.

## Context

A card that has not been taken into use is recognised at the first tap,
inside the one PACE session that reads the certificate, and routed to the
activation form before anything else, on a phone and on a reader alike.

FINEID S4-1 v4.2 section 4.6 defines two procedures. Under section 4.6.1
both PINs ship blocked, and the eight-digit activation code is the PUK: a
RESET RETRY COUNTER sets each new PIN. Under section 4.6.2 both PINs ship
set to one seven-digit preset activation PIN: a CHANGE REFERENCE DATA sets
each new PIN. The card enforces the entry length itself, and a wrong
length spends a try, so the procedure has to be known before any entry is
sent, and only the PINs the card still waits for may be asked for: under
section 4.6.2 the activation PIN stops being a PIN's value the moment that
PIN is changed. The rules are recorded in refineid-core's
[card activation reference](https://github.com/refineid/refineid-core/blob/main/doc/reference/card-activation.md).

## Decision

- **The core decides the scheme.** `refineid_auth::ActivationScheme::
  from_numbering_and_validity_start` is the one decision, from the card's
  resolved credential numbering and its authentication certificate's
  validity start. Organization numbering (FINEID S4-2 v4.0 section 4.2,
  the Idemia Cosmo X organization card) is section 4.6.1 whatever the
  date. Under citizen numbering the validity start decides: from
  13 January 2026 section 4.6.2, before it section 4.6.1. A citizen card
  whose validity start cannot be read has no scheme, and the card is
  opened as an activated one. The native crate only reads the validity
  start from the certificate (`certificate_validity`); the open resolves
  the numbering and asks the core, and the health probe hands the date to
  the core's `probe_credential_health`, which does the same. Neither the
  chip generation, nor the certificate key family, nor the issuer name
  names the scheme.
- **No identity before activation.** The open reads the authentication
  certificate first, inside the secure channel after the PKCS#15
  selection, for its validity start. A card awaiting activation has no
  identity: the certificate serves the decision only, so no name is shown,
  nothing is stored for it but the access number, and nothing is offered
  to a browser or a paired computer.
- **Needs from the card.** With a scheme in hand, the open asks the core's
  `activation_needs`, which judges each PIN by its PIN changed flag and,
  where the card does not return the flag, under section 4.6.1 by its
  counter-safe status; under section 4.6.2 a PIN without a readable flag
  is not judged to await activation. A probe the card refuses leaves the
  card treated as activated, so a transient fault never routes an
  activated card to activation.
- **The reply names the procedure.** The contactless open reply for a card
  awaiting activation is the scheme byte and the needs byte and nothing
  else, with the management reply's vocabulary; Kotlin refuses a reply with
  no scheme, no needs, or any other shape. Card management derives the entry
  length from the scheme and never submits an activation for a scheme it
  does not know, and the native side refuses the same. The activation code
  is validated against the scheme and carries it to the core's
  `activate_card`, which sends that scheme's commands.
- **Management stays inside the secure channel.** A card opened under PACE
  refuses a plain command and ends its channel. On a phone each management
  operation runs its own PACE handshake; on a USB reader's contactless
  antenna the session the open held carries every card command after the
  open: management, the qualified-certificate read, the PIN 2 preflight
  and both signatures.
- **Straight to the form.** A reading that says the card awaits activation
  shows the activation form in place of the home screen, from the first
  frame. The form is titled "Organisation card activation" for an
  organization card and "Identity card activation" otherwise. A holder who leaves
  the form finds the identity row reading "Activate Card" and leading back
  to it; the home screen carries no banner. The identity row shows a
  chevron only where a tap opens a page, so the card-reading prompt has
  none.
- **The access number stays.** PACE proved the card access number against
  the card, so the open keeps it for a card awaiting activation as for an
  activated one: the holder types it once, and a mismatch on a later tap
  forgets it as for any card. Whatever an earlier card left in memory or
  in the store, a name or a certificate, goes with it.
- **Signing waits for an identity.** The home screen offers document
  signing only with an identity read from an activated card.
- **Every build.** Activation is in release builds as in debug builds.

## STPA

Controller: the app at the first tap. Control action: route the holder to
the activation form, and later send the activation entry to the card.
Feedback: the credential numbering, the certificate's validity start, and
the per-PIN probes.

- UCA-1: the app sends an activation entry to a PIN the card has already
  set (H: a try spent on a value that cannot match). CC: the needs come from
  the card per PIN, the form asks only for the PINs still waiting, and a
  section 4.6.2 PIN without a readable flag is never served the entry.
- UCA-2: the app sends an entry of the wrong length, or over the wrong
  command, on a guessed scheme (H: a try spent). CC: the core decides the
  scheme from the numbering and the validity start; an undecided scheme
  gets no attempt, on either side of the bridge.
- UCA-3: the app routes an activated card to activation on a stale or
  failed reading (H: the holder enters codes for nothing). CC: a refused
  probe reads as activated; the form re-probes before it submits.
- UCA-4: the app sends a plain command to a card opened under PACE (H:
  the card ends the channel mid-operation). CC: while a reader holds the
  PACE session, every card command runs inside it, and the plain select
  and certificate read send nothing.

## Verification

Scripted: the validity start read from synthetic certificates in both time
forms, unreadable times, and malformed or truncated DER; the scheme
decision under organization numbering on both sides of the cutover and
without a date, under citizen numbering, and with no resolvable
numbering; activation refused without a scheme or with an entry of the
other scheme's length; held-session management, qualified-certificate
read, PIN 2 preflight and qualified signature with no held session
sending nothing; the open reply encoding and the Kotlin decoder with
scheme and needs, and the decoder's refusals.

## Consequences

Android classifies every card by the core's rule, decided in one place.
The native crate carries a small X.509 walk for the validity start, which
the public core excludes by design.
