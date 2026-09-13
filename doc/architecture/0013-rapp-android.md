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
  `RappPairVault`, `RappOperationVault`, and the operation, pairing and
  liveness value types.
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

