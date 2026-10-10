# ADR 0034: Contactless session boundary

Status: Accepted

Date: 2026-08-17

## Context

ADR 0033 proved contactless discovery and `EF.CardAccess` recognition.
Every FINEID PKCS#15 operation on the contactless interface is protected
by PACE with the card access number followed by secure messaging
(FINEID S4-2; BSI TR-03110). The public core carries both: the PACE
handshake produces session keys, and its secure-messaging layer is
itself a card transport, so the reviewed selection, certificate-read,
preflight, and one-shot signing operations run unchanged above it.

The existing JNI border is one-shot: each native call owns a complete
logical operation over a callback exchange, and no native state survives
the call. Holding a secure channel across calls would break that
property for session keys — the most sensitive state the app handles.

## Decision

The one-shot border is kept. Each contactless native operation owns one
ISO-DEP connection for its whole lifetime: reconstruct the typed CAN,
run PACE, wrap the transport in secure messaging, select the PKCS#15
application, perform exactly one reviewed operation, and return. Session
keys never survive a JNI call; the next operation runs PACE again. The
per-operation handshake costs a few card exchanges and is accepted for
this slice.

Two operations cross the border. The session opener runs the PKCS#15
selection, the authentication-certificate read, and the counter-safe
PIN1 preflight inside one secure-messaging session, so everything the
browser path caches arrives under a single handshake. The signing
operation runs the one-shot preflight, VERIFY, and signing sequence.
The generalized certificate read and the already transport-generic
preflight and signer are reused verbatim; contactless adds composition,
not protocol.

A card left inside an earlier secure-messaging session refuses the next
plain command once: ISO 7816-4 terminates secure messaging when a plain
APDU arrives, and the production card rejects that terminating command
(observed on hardware; a second handshake on one connection failed in
milliseconds at its first plain exchange). Every secure-channel open
therefore begins with one replay-safe, credential-free SELECT MF whose
status word is deliberately not interpreted, returning any such
connection to plain state before PACE.

A PACE refusal is a first-class outcome. `AuthMismatch` and a
non-success handshake status word — almost always a wrong CAN — map to
one typed `PACE_REJECTED` value in each reply vocabulary, distinct from
transport faults, so the holder is told to check the CAN rather than
shown a generic error. The USB paths treat the value as a local
impossibility.

Kotlin owns the session shape. A discovered tag resting in the field is
retained, and a holder-entered CAN opens a session on the worker thread
through the single native opener. The NFC stack re-polls a resting card
after each closed connection; an open session survives that by adopting
the freshly delivered handle instead of tearing down. Card substitution
during adoption is safe because every operation starts with PACE
against the session CAN: a different card fails the handshake before
any credential could reach it. The session retains the CAN — collected
on device, held only as mutable memory, zeroized on card loss,
replacement, detach, and shutdown — beside the cached public
certificate. The PIN transfers to exactly one native call and is never
retained.

Browser login composes, not duplicates: the contactless session
implements the same `AuthenticationCardService` the USB controller
implements, including mandatory local verification against the cached
certificate. The debug browser harness takes a transport-neutral
readiness flag and is handed whichever service owns a ready card, USB
preferred when both are present.

The UI stays terse: a CAN field and Connect action after recognition,
Wrong CAN on a refused handshake, Ready with card presence once the
session holds the certificate. Qualified signing over contactless
remains out of scope (ADR 0013: MF traversal can tear the channel down).

## Access number rule

Contactless access to the card always needs its access number (CAN); a
card in the USB reader never does. When an operation, local or requested
from a paired computer, will run over NFC and no access number is known,
the phone asks for it, before the card is presented or as soon as it is
recognized. It never waits on the card in silence: the remote card prompt
shows the access number field, and the wait runs on to its limit while
the holder types. A request arriving while the app is in the background
reaches the holder through its notification, which opens that prompt.

While a remote operation waits, the prompt names what the reader is
doing (reading, card lost, access number needed or wrong), and any
recognized card whose access number is known is opened at once, so a
card presented during any wait completes that request. A wait ends after
30 seconds without a change in the reader's state and never later than
90 seconds after it began.

## Failure story

A wrong CAN never consumes a PIN retry; the holder corrects it and
reconnects. Card loss at any stage closes the session, zeroizes the CAN,
and returns the reader to waiting; the resting card is rediscovered by
another tap. The signer's counter-safe gate is unchanged: preflight
refusal at the retry floor, exactly one VERIFY, no automatic credential
retry. Debug traces record coarse results, lengths, and timings; never
CAN digits, PACE payloads, or secure-messaging material. Release builds
trace nothing.

## Verification

Rust unit tests lock the CAN shape gate, the PACE error mapping, the
`PACE_REJECTED` wire tags, and the unchanged USB vocabularies. Kotlin
unit tests lock the CAN custody type, the extended reply decoders, and
the recognition mapping. The full PACE handshake is verified by the
public core's own tests; this crate composes it.

## Physical evidence

On 2026-08-17, with a production old-generation card resting on the
physical Pixel 4 and its CAN entered on device, the session opener
completed in about three seconds: one PACE handshake, then the PKCS#15
selection, the RSA-3072 authentication-certificate read, and the
counter-safe PIN1 preflight (citizen scheme, full retries, consumer
authentication permitted) inside one secure-messaging session. The
debug browser harness then served the cached leaf to the TLS
client-certificate request, and one holder PIN produced an RSA-PSS
SHA-256 signature under secure messaging in about six seconds; local
verification against the cached certificate passed and the diagnostic
origin accepted the login. The same run had earlier demonstrated the
stale-session refusal documented above, in milliseconds, before the
single-handshake opener replaced the two-handshake connect. No PIN
retry was consumed and no identifying value was recorded.
