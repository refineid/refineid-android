# 0047. The organization card on the contactless interface

## Status

Accepted. Unit-tested against core's synthetic organizational card; hardware
validation on the phone is pending.

## Context

The organization card has no Card Access Number. PACE takes PIN 1, PIN 2 or
the PUK as its password (FINEID S1 v4.0, organizational cards, section 2.1;
FINEID S4-2 v4.0 section 6), and before PACE the card answers nothing but
EF.CardAccess (refineid-core `doc/reference/supported-cards.md`). A completed
PACE with a PIN counts as that PIN verified, and the card does not answer the
header-only VERIFY with a counter over secure messaging, so nothing that floors
on that probe can run on its channels.

## Decision

- **The kind comes from EF.CardAccess, before any password.** Citizen cards list
  brainpoolP384r1 alone; the organization card lists NIST P-256 and P-384 alone.
  A file listing both families, or no generic-mapping suite, names no kind, and
  no password goes to that card. The native boundary decides on every operation:
  the UI's kind is a hint for what to ask, never the guard.
- **Each operation runs its own PACE with the credential it spends, and drops
  the field afterwards.** No channel is held, so no state outlives the operation
  and every signature carries a fresh presentation.
- **The floor is `MSE:Set AT`'s answer**, which spends no try. `run_pace` applies
  core's rule to it. The counters the UI and the custody rules read come from the
  same command sent alone, in plain, with no secret.
- **Nothing is asked before a card answers.** The prompt shows after the card has
  named its kind: an access number for a citizen card, Basic PIN 1 for an
  organization card.
- **Only public certificates rest in the store** for this card; PIN 1 is held as
  for any card, in memory, only when its counter read five before the handshake.

## Paths

| Operation | Channel | Floor |
| --- | --- | --- |
| Open, read certificates | PIN 1 PACE | `MSE:Set AT` in `run_pace` |
| PIN 1 verification, login | PIN 1 PACE, no VERIFY | `MSE:Set AT` in `run_pace` |
| Qualified signature | PIN 2 PACE, `qualified_key_after_pin2_pace`, no VERIFY | `MSE:Set AT` in `run_pace` |
| PIN 1 change | PIN 1 PACE, `change_pin1_after_pin1_pace(PresentAgain)` | `MSE:Set AT`, then the channel's record |
| PIN 2 change | PIN 2 PACE, `change_pin2_after_pin2_pace(PresentAgain)`, which selects DF.ESIGN itself | `MSE:Set AT`, then the channel's record |
| PIN 1 or PIN 2 reset | PUK PACE, `reset_pin*_after_puk_pace(PaceHandshake)` | `MSE:Set AT` on the PUK's counter |
| Counters, health | none, plain `MSE:Set AT` | no try can be spent |

## What core does not offer yet

- **A counter read without a handshake.** `set_authentication_template` is private,
  so this repository assembles the same `MSE:Set AT` from core's `MseSetAt`.
- **A held-PIN admission in `run_pace`.** Only the floor runs between `MSE:Set AT`
  and the first `GENERAL AUTHENTICATE`. A held PIN 1's stricter rule, a count of
  five, is read by a separate `MSE:Set AT` just before the handshake.
- **Identifying the card before PACE.** Nothing tells one organization card from
  another before a password is named, so a held PIN 1 offered to a substituted
  organization card is refused there and costs that card a try; the holder sees
  the refusal and the count, and the value is dropped.

## STPA

Grounded in `doc/security/stpa-rapp.md` in refineid-core. The controller is the
phone's card session; its process model is which kind of card is in the field and
what the card's counter reads.

- UCA-1: a PIN is named to a citizen card's PACE, or a CAN to an organization
  card's. CC-1: the native boundary reads EF.CardAccess on every operation and
  names a password only to the kind it belongs to.
- UCA-2: a try is spent at the last two, or silently. CC-2: core's floor reads
  `MSE:Set AT` before the first `GENERAL AUTHENTICATE`; a refusal carrying no count
  has the counter read back; the holder sees the card's count.
- UCA-3: a stale kind in the UI asks for the wrong credential. CC-3: the prompt
  follows the last probe, and the boundary of CC-1 decides anyway.
- UCA-4: a held PIN 1 goes to the card with a counter below five. CC-4: the
  custody rule reads the counter by `MSE:Set AT` before every use of a held value.
