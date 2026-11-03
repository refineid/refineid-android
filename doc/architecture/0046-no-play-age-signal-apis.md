# 0046. No Play age-signal APIs

## Context

Google's Age Signals API offers an age signal behind a consent prompt,
distributed as a beta library with an age-signal support dependency
underneath. Play Integrity offers neighbouring verdicts on tampering
and licensing from the same shelf, silently and stable.

## Decision

RefineID uses neither. The app holds no age-gated content, so an age
verdict cannot change what it does; the API would add a consent prompt
and a beta dependency for a signal nothing acts on. Play Integrity's
verdicts are consumed server-side, and this app has no server: its
trust decisions come from the card and the platform, not from a Play
verdict. Only the Play Console target-audience declaration matters,
and that is paperwork, not code.

## Verification

No age, integrity or verdict API appears in the dependencies or the
manifest. A proposal to add one is measured against this record: what
product decision would change, and what would consume the verdict.

## Consequences

If the store ever requires an age verdict for this category, the
decision is revisited with the requirement in hand, not before.
