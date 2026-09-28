# Security Remediation Report: RefineID Android (September 2026)

## Executive Summary

This report documents the security remediations implemented in RefineID Android in September 2026. Static inspection, architectural audit, and verification identified five security vulnerabilities and design weaknesses spanning pairing protocol security, PIN handling and memory hygiene, screen capture protection, and RAPP session lifecycle management. All identified issues have been remediated, verified against the project quality floor (`./gradlew check`), and tested without regression.

---

## 1. CPace Pairing & Elimination of Offline Dictionary Attacks

### Problem
Previously, manual pairing code exchange embedded an offer identifier and pairing secret directly into rendezvous naming (`StreamRendezvousName`), exposing the pairing code to an offline dictionary attack by an eavesdropping or scanning adversary on the local network relay. Furthermore, the pairing protocol handshake did not complete balanced CPace PAKE exchange over the relay stream.

### Remediation
- **CPace Protocol Integration**: Integrated balanced CPace PAKE bindings (`beginCpace`, `createRequesterCodeOffer`, `fromProxyCodeOffer`, `writeCpaceFrame`, `readCpaceFrame`) in `RappPairingModel`, `RappPairingBridge`, and UniFFI bindings.
- **Rendezvous De-identification**: Decoupled the rendezvous service name from the pairing code by introducing `MANUAL_PAIRING_SERVICE_NAME = "rf-pairing"`.
- **Secret Removal**: Removed `pairingSecret` and `offerIdentifier` from `RappPairingCode`, ensuring pairing codes only act as low-entropy passwords passed directly to the CPace state machine.
- **Full Frame Exchange**: `RappPairingModel` now executes the CPace frame sequence (Requester CPace frame -> Proxy CPace response) before proceeding with Noise handshake, Hello exchange, and Confirmation.
- **Verification**: Added cross-platform `RappCpacePairingFlowTest` verifying that pairing succeeds between requester and proxy with matching codes, and cryptographically fails when mismatched codes are presented.

### Static Rendezvous & Collision Threat Model
- **Offline Attack Elimination**: Replacing dynamic offer-specific rendezvous names with static `rf-pairing` prevents eavesdroppers on the local subnet from capturing candidate offer identifiers or pre-computing offline dictionary hashes.
- **Subnet Collision Handling**: When multiple devices initiate pairing concurrently on the same subnet, mDNS service registration resolves name collisions using standard mDNS numeric disambiguation (`rf-pairing-2`, etc.), or peers may connect to an existing listener.
- **Cryptographic Fail-Closed**: In the event that a proxy connects to an unrelated requester, or a malicious peer pre-advertises `rf-pairing`, CPace mutual PAKE ensures that without the exact shared pairing code, key derivation fails. The handshake terminates immediately at step 0 without exposing certificates, device identifiers, or protocol secrets.
- **Graceful Recovery**: Any failed handshake or early socket disconnection drops cleanly and resets `RappPairingModel` back to the offering or waiting state for subsequent attempts.

---

## 2. Prevention of Unverified PIN1 Caching and Premature Acceptance

### Problem
Unverified candidate PINs were prematurely recorded into `AuthenticationPinCache` via `recordVerified()` or `writePin1()` prior to receiving card-level verification confirmation (SW 9000). Furthermore, candidate PINs were not checked against known-rejected PIN history before card submission, risking unnecessary physical-card retry counter consumption. Additionally, sharing a single byte buffer between `recordVerified` and `writePin1` caused a double-ownership bug where `writePin1` zeroized the array held by the cache.

### Remediation
- **Premature Call Removal**: Removed all premature calls to `recordVerified()` and `writePin1()` from:
  - `NfcReaderController.kt` (lines previously setting verified state on submission rather than upon verified card response)
  - `RappPairingScreen.kt`
  - `RappPhoneProxyDispatcher.kt`
- **Rejection Verification Preflight**: In `RappPhoneProxyDispatcher.kt`, candidate PINs are checked against `pinCache.isRejected(sub)` prior to card presentation. If previously rejected, the request is rejected immediately with `respondCredentialRejected()` without contacting the card.
- **Zero-Allocation Fingerprinting**: Added `AuthenticationPinCache.isRejected(submission: Pin1Submission)`, which uses `submission.peekBytes { ... }` to borrow the buffer under lock and hash it without heap copy or memory leakage.
- **Independent Ownership**: In `handleBrowserAuthSuccess`, independent copies via `pin1Submission.copyBytes()` are supplied to `pinCache.recordVerified()` and `primedCanStore.writePin1()`, ensuring that `writePin1`'s consumer zeroization in `finally` does not mutate the cached PIN.
- **Rejection History Retention**: In `AuthenticationPinCache`, `clear()` zeroizes the cached PIN memory while strictly preserving the recorded rejection history (`rejectedPinDigests`).
- **Clean Fallback**: Removed `peekPin()` from `AuthenticationPinCache` to prevent external modules from reading credentials without consuming them.

---

## 3. Owned Zeroizable PIN Types and Memory Hygiene

### Problem
PIN values and candidate strings were held in immutable strings and unmanaged byte buffers across UI fields, coroutine states, and proxy callbacks, allowing residual credentials to remain in JVM heap memory.

### Remediation
- **Owned Zeroizable Types**:
  - `Pin1Submission`: Provides single-owner zeroization upon `close()`, a non-copying borrowing accessor `peekBytes()`, and an explicit `copyBytes()` when ownership transfer is required.
  - `Pin2Submission`: Provides single-owner zeroization upon `close()`, non-copying borrowing accessor `peekBytes()`, and explicit `copyBytes()`.
- **UI State Hygiene**:
  - In `RappPairingScreen.kt` and `RappAuthorizationDialog.kt`, Compose `TextField` string states are cleared to `""` immediately upon submission or cancel.
  - While JVM `String` instances remain immutable until reclaimed by garbage collection, digit characters are parsed directly into zeroizable owned byte buffers (`Pin1Submission`, `Pin2Submission`) and are never written to logs, diagnostics, or persistent state.
- **Proxy Dispatcher Lifecycle**:
  - `RappPhoneProxyDispatcher` maintains `pendingPin1: ConcurrentHashMap<String, Pin1Submission>` and `pendingPin2: ConcurrentHashMap<String, Pin2Submission>`.
  - Added `clearPendingPins()`, zeroizing all pending PIN submissions on disconnect, session close, cancellation, or error.
  - All card operations consume PINs within `try-finally` blocks ensuring `close()` is always invoked.
  - Intermediate ephemeral buffers (such as CPace random buffers and liveness challenges) are zeroized with `.fill(0)` in `finally` blocks immediately after use.

---

## 4. Comprehensive Screen Capture & Leakage Protection

### Problem
`FLAG_SECURE` and `setRecentsScreenshotEnabled(false)` were conditionally omitted in debug builds, and Compose dialogs did not explicitly specify `SecureFlagPolicy.SecureOn`. Additionally, `MainActivity` contained an intent handler (`handleAuthPinIntent`) capable of parsing auth PINs from external intents.

### Remediation
- **Unconditional Window Flags**: In `MainActivity.kt`, `FLAG_SECURE` and `setRecentsScreenshotEnabled(false)` are now enabled unconditionally across both release and debug builds.
- **Diagnostic Configuration**: In `BuildDiagnostics.kt`, `SCREEN_CAPTURE_ALLOWED` is permanently set to `false`.
- **Compose Dialog Policies**: Configured `DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)` on:
  - `RappAuthorizationDialog`
  - `RappCardTapDialog`
  - `BrowserHarness` (Client certificate & PIN dialogs)
  - `MainScreen` (ReadCardNfcDialog & ReaderCanDialog)
- **Intent Vector Removal**: Removed `handleAuthPinIntent` from `MainActivity`, ensuring credentials can never be injected or extracted via IPC/Intents.

---

## 5. RAPP Protocol Lifecycle & State Hardening

### Problem
The remote proxy listener lacked strict socket-level handshake deadlines, did not poll bridge liveness periodically, mixed monotonic and wall clock domains, did not respect `closeSessionAfterSend` or terminal action kinds from the Rust bridge, and reused Compose authorization dialog state across distinct request IDs.

### Remediation
- **Stream Relay Deadlines**: `StreamRelayListener` now enforces an absolute handshake deadline via `authDeadlineJob` (cancelled once authentication is established via `clearSocketTimeout()`) and sets an established read timeout (`ESTABLISHED_READ_TIMEOUT_MS = 60_000`).
- **Periodic Liveness Polling**: `RappPhoneProxyDispatcher` runs a continuous liveness loop (`startLivenessLoop`) invoking `bridge.pollLiveness` with high-entropy challenges (`LIVENESS_CHALLENGE_BYTES = 32`) and monotonic timestamps (`RappClock.monotonicMs()`).
- **Monotonic Clocks**: Switched session lifecycle and bridge polling to `RappClock.monotonicMs()` to prevent clock skews and NTP step disruptions.
- **Bridge Terminal Actions & Frame Sending**: Any action carrying an attached frame transmits the frame before executing action logic. Handled `action.closeSessionAfterSend`, `SESSION_CLOSED`, `PAIR_REVOKED`, `CANCELLED`, and `TERMINAL` actions properly, dismissing pending inbox requests on the Main dispatcher and zeroizing pending PIN submissions.
- **Request State Scoping**: Keyed `RappAuthorizationDialog` Compose state to `requestId`, preventing input leakage or stale validation between sequential authorization requests.

---

## Verification

The remediations were validated using the full quality suite:
- `cargo test` in `native/refineid-android-core`: 75/75 tests passed.
- `./gradlew check`:
  - `testDebugUnitTest`: 463 unit tests passed (including CPace pairing flow and PIN cache regression tests).
  - `detekt`: 0 issues.
  - `spotlessKotlinCheck`: All formatting checks passed.
  - `verifyReleaseNoLogging`: 0 logging statements or forbidden trace literals detected in release DEX.
  - `verifyReleaseNetworkIsolation`: Release manifest validates `usesCleartextTraffic="false"`.
  - `verifyReleaseAbis`: Identical native libraries verified across all supported ABIs (`arm64-v8a`, `x86_64`).
