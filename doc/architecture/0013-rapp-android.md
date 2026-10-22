# RAPP on Android

Status date: 2026-08-16. This describes the Android side of the Remote
Authorization Proxy Protocol: what exists now, why it is built this way, and
what the next agent has to do.

## Why Android needs it

RAPP is what lets a computer use a card it cannot read itself. The holder
presents the card to their phone, approves the operation there, and the
computer receives only the result. On Android that makes the phone the
authorizer: the card, the CAN, PIN 1 and PIN 2 stay on the device the holder
is holding, and a laptop needs no card reader at all.

Apple already implements both roles. Android implementing the same protocol is
what turns a proven pair of devices into a cross-platform one.

## Roles

Android pairs only as the custodian: the phone shows the pairing code, serves
the RAPP v26.10.22 offer over the stream transport, and holds the card. No
screen pairs the phone as a requester, so the app never calls
`RappPairingBridge.fromBootstrap`.

`RemoteCardModel` and `RappRequesterClient` open sessions for a stored pairing
whose role is requester, but the app cannot create such a pairing, so in
practice they are idle. Giving Android a requester role needs a product
decision and a pairing entry point (dial a phone in pairing mode, read its
offer, type its code); the session side is already in place.

`RappStoredPairs` loads every catalogued pairing through the core. A record
in a format the core no longer decodes is removed from the catalog and the
vault when the app starts, and its device pairs again.

The binding's flat action records are typed once, at the binding border:
`RappBridgeOutcome.from` turns each `RappBridgeAction` into a sealed outcome
with a checked `RappOperationId`, a typed `RappRequest`, a `RappCardStatus`
of `Present(fingerprint)` or `Absent`, and a `RappAnswer`; `RappPairing.of`
does the same for pair-record metadata (`RappPairId`, role, and the
`Unconfirmed`, `Active` or `Forgotten` state). The rest of the app consumes
only these; raw bytes stay in transit to and from the binding and the
transport.

## Custodian behaviour

- The listener holds one session at a time. Operations take the card one
  at a time through one lock; an operation that finds it held by another
  session's operation is reported `queued` once (section 8.2 item 2).
- `card.status` follows `session.ready` before any operation runs, and again
  whenever the card or the USB card reader changes. Presence is the card the
  phone holds: a card in the USB reader from insertion until removal or the
  reader's detachment, and an NFC card from the holder adding it to the phone
  until the holder removes it there, named by its authentication
  certificate. `reader_attached` is true while a CCID reader is connected to
  the phone, with or without a card or the app's permission, and false
  otherwise, including while the phone serves an NFC card; detaching the
  reader leaves an added NFC card present. An operation the card did not
  answer ends with `card_error` and leaves presence unchanged; the next
  operation asks the holder to present the card again (section 8.4 item 1;
  core STPA CC-81).
- Reads ask the holder nothing. Authentication and document signing ask for
  their PIN on the phone, and entering it is the holder's consent; every PIN
  prompt on screen reports `consent_shown`. There is no other consent view
  (section 8.2 item 3). The prompt names the paired computer and, for an
  authentication, the program the operation context names, each under its
  own label. It never names a site: the phone cannot know one (core STPA
  CC-55).
- PIN 1 is asked once and held only in memory, never in storage, bound to
  the card that accepted it, named by its authentication certificate. It is
  held only when that card's PIN 1 counter read pristine before the VERIFY;
  otherwise it serves its one operation. A PIN 1 held for one card is never
  presented to another: that card has no held PIN and the holder is asked.
  It ends when the reader card is removed, the NFC card is removed from the
  phone or another card replaces it, the card rejects it, the card's counter
  reads below pristine or cannot be read, the holder clears it, or the
  process ends; while it is held a browser authentication runs with no
  prompt. A card in the reader whose status reads "verified" from the last
  VERIFY is at its try limit (FINEID S1 v4.2 section 3.5), so it keeps the
  hold. Opening Remote Access or starting to serve never asks for PIN 1; the
  first authentication a computer requests does. PIN 2 is asked for every
  signature or batch and never held (section 11 item 2; credential
  custody).
- The native card session reads the PIN status with a header-only VERIFY
  before every verification and, without sending one, refuses one or two
  remaining attempts, a blocked PIN, and a status that carries no count and
  is not "verified"; the operation then ends as `retry_floor` and the holder
  is told the attempts are reserved for the issuer's software. A wrong PIN
  with at least three attempts left re-prompts on the phone with the count;
  the requester learns nothing of it (section 10.2).
- A PIN command the card did not answer is sent again, once the card is
  back, only when the PIN's attempts read before and after, from the same
  card, show the card did not count it. Attempts that fell mean the card counted the PIN wrong: it is
  forgotten and the holder asked again, subject to the floor. Without both
  counts the PIN is not sent again and the operation ends with `card_error`;
  a held PIN 1 outlives the failure.
- Forgetting a pairing with its session open closes it with
  `pairing_revoked` and destroys the record. Otherwise the record is kept,
  hidden from the list, still announced and routed, and its next session
  carries only the close; a record that kept its key for 30 days is
  destroyed when the served pairings are next loaded (section 4.6). A
  received `pairing_revoked` close destroys the record at once.

## The protocol is not implemented here

`refineid-rapp` in the refineid-core repository (`crates/rapp`) is the
original protocol engine for RAPP framing, state transitions, role legality,
failure policy, and cryptography, and it is what Android links; nothing in
Kotlin decides protocol. The only RAPP combinations proven live so far are in
the Apple-native implementation (iPhone attaching a Mac, and iPad), built on
Apple platform transports and Swift protocol code. The Rust engine has not
been proven live between independent peers: treat the Apple implementation as
the behavioural reference, and expect the Rust engine to be simplified
against live-proven behaviour rather than treated as normative. It remains
the shared engine for platforms without a native implementation - Android
now, Linux as an intended future target.

Change the protocol in Rust first, make its tests pass, regenerate this
binding, and only then adapt the Android integration.

## What is in the repository

`native/refineid-rapp-android/` is a thin crate whose only job is to produce a
shared object for Android:

- It depends on `refineid-rapp` with the `bindings` feature and re-exports
  it, which links that crate's UniFFI scaffolding into a `cdylib`. The library
  crate itself builds as `rlib` and `staticlib` for the Apple binding and
  cannot produce a `.so` for Android on its own.
- The shared object must be named `librefineid_rapp.so`, because the
  generated binding loads its Rust side by the scaffolding crate's name. That
  is why this wrapper sets `[lib] name = "refineid_rapp"`.
- `src/bin/refineid-uniffi-bindgen-kotlin.rs` generates the binding, mirroring
  the Apple repository's Swift generator.
- `generated/uniffi/refineid_rapp/refineid_rapp.kt` is the generated
  binding, in package `uniffi.refineid_rapp`. It is
  committed so a build does not depend on regenerating it, and it must be
  regenerated and committed together with the Rust revision that defines its
  ABI.

The Gradle wiring in `app/build.gradle.kts` follows the existing pinned-core
pattern: `buildRappDebug` and `buildRappRelease` run `cargo ndk` for
`arm64-v8a` and `x86_64`, their output directories are added as `jniLibs`, and
the generated Kotlin is added as a source directory. The binding calls Rust
through JNA, which the application did not previously need, so `jna` with the
`aar` artifact type is now a dependency.

## Rebuilding the binding

From the crate directory, with the NDK available:

```sh
cargo ndk -t arm64-v8a -t x86_64 -o jniLibs build --release --locked
cargo run --bin refineid-uniffi-bindgen-kotlin -- \
    generate --library jniLibs/arm64-v8a/librefineid_rapp.so \
    --language kotlin --out-dir generated --no-format
```

The crate depends on `refineid-rapp` from the refineid-core repository using
the same pattern as the pinned core crates: a git dependency on
`refineid-core` `main` with a `[patch]` to the sibling `refineid-core`
checkout for local development.

## Measured so far

- `refineid-rapp` compiles for `aarch64-linux-android` and
  `x86_64-linux-android` with the pinned 1.98.1 toolchain.
- The wrapper produces `librefineid_rapp.so` for both ABIs.
- The Kotlin binding generates from the built library and exposes the RAPP
  surface: `RappPairingBridge`, `RappSessionBridge`, `RappOperationBridge`,
  `RappPairRecord`, `RappPairVault`, and the operation and pairing value
  types.
- Gradle configures with the tasks registered.

### Proven Live on 2026-09-03

- **Devices**: Samsung Galaxy S22 (`SM-S901B`, Android 16) paired with Apple Mac
  (`m1`, macOS 26.6.2).
- **Physical Card**: Finnish Citizen Identity Card (FINEID S1, P-384 authentication
  profile).
- **Pairing Ceremony**: Mutual Noise XXpsk3 pairing completed over mDNS local
  TCP stream using a 6-digit numeric pairing code. Automated end-to-end via
  `scripts/test-pairing-e2e.sh`.
- **Connection Management**: Persistent storage in `RappPairCatalog` and
  `AndroidRappVault`. Paired computers can be removed individually from the UI;
  when all pairs are deleted, the background stream listener stops.
- **Card Status & Identity Reading**: Remote identity probe read the 1066-byte
  authentication certificate (`EF.4331`) over the stream relay in 540 ms.
- **Browser Authentication Signing**: Safari on macOS requested TLS 1.3 client
  certificate authentication for `https://card.refineid.fi`. The request routed
  through macOS `RefineIDRappTokenExtension` across the encrypted stream relay
  to the phone. The phone presented `RappAuthorizationDialog` ("Requested by m1"),
  verified PIN 1 on the physical card via NFC, and returned a valid 96-byte
  ECDSA P-384 hardware signature. Safari verified the signature and completed
  login.

