# 0045. Typed entry survives a rotation

## Context

A phone lying on a desk beside a card reader, or held flat over a card
during an NFC tap, flips between portrait and landscape on its own. Each
flip recreated the activity, and with it every dialog the holder had
open: the access number, PIN or pairing code typed so far was gone and
the dialog had to be reopened. The app holds secrets in memory only, so
saving them into instance state to survive the recreation was never an
option.

## Decision

Both activities declare in the manifest that they handle the
configuration changes a rotation produces (orientation, screen size,
screen layout, smallest screen size, keyboard visibility). The activity
and its composition stay alive across the rotation, Compose re-lays the
screen out for the new size, and every remembered state, including the
text in an open secure field, is untouched.

Orientation is not locked: the app keeps following the device so that
large screens and foldables lay it out as the platform prefers.

## Verification

The manifest instrumentation test asserts the declaration on both
activities. The behaviour is checked by hand: open the access number
dialog, type a few digits, rotate, and read the same digits.

## Consequences

Changes outside the declared set (locale, font scale, dark mode) still
recreate the activity, so the lifecycle code that distinguishes a
configuration change from a real stop remains in use.
