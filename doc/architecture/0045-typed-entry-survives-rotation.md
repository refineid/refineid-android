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
configuration changes a rotation, a fold or a move to another display
produces (orientation, screen size, screen layout, smallest screen size,
density, keyboard visibility). The activity and its composition stay
alive across the change, Compose re-lays the screen out for the new
size, and the remembered state, including the text in an open secure
field, is untouched.

Secrets and typed entry live in plain `remember` state, never in
`rememberSaveable`: nothing typed into a secure field goes into the
saved instance state.

The main screen requests portrait, so a phone lying flat or tilted over
a card no longer turns the screen on its own, in either direction. On
screens of 600 dp or wider running Android 16 or later the platform
ignores that request and lays the screen out as it prefers, which is why
the configuration-change declaration stays in place beside it; on older
large-screen devices the request is honoured with letterboxing. The PIN
prompt raised over a browser requests the orientation of the activity
beneath it, so it appears the way the browser is held and does not turn
on its own either.

## Verification

The manifest instrumentation test asserts that both activities declare
exactly this set, so a wider set cannot creep in unnoticed, that the
main screen requests portrait and that the PIN prompt requests the
orientation of the activity beneath it. These are the declared
requests; whether a given device honours them is the platform's rule
above. The behaviour is checked by hand on a phone: lay it flat and tilt it
and watch the main screen stay put; then, with a browser held in
landscape, raise the PIN prompt, type a few digits, rotate the phone and
read the same digits.

## Consequences

Changes outside the declared set (locale, font scale, dark mode) still
recreate the activity, so the lifecycle code that distinguishes a
configuration change from a real stop remains in use.

A portrait request costs the app the tablet-optimised listing on the
store and shows older tablets a letterboxed screen. The app is a phone
companion for a card; that trade is accepted.
