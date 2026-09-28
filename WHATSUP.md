# WHATSUP

branch: agent/security-fixes
purpose: Fix security issues in RefineID Android: CPace pairing, credential custody, zeroization, FLAG_SECURE, and RAPP lifecycle.
started: 2026-09-28T18:20+03:00 by petri
heartbeat: 2026-09-28T19:13+03:00
status: verified

## Completed Tasks
1. CPace Pairing & Relay Hardening:
   - Integrated balanced CPace PAKE bindings (`beginCpace`, `createRequesterCodeOffer`, `fromProxyCodeOffer`, `writeCpaceFrame`, `readCpaceFrame`).
   - Replaced dynamic rendezvous with static manual pairing service name (`MANUAL_PAIRING_SERVICE_NAME = "rf-pairing"`), removing pairing secret from discovery.
   - Removed `pairingSecret` and `offerIdentifier` from `RappPairingCode`.
   - Implemented CPace frame exchange in `RappPairingModel`.
   - Added `RappCpacePairingFlowTest`.
2. PIN Verification & Cache Integrity:
   - Removed premature `recordVerified()` and `writePin1()` calls in `NfcReaderController`, `RappPairingScreen`, and `RappPhoneProxyDispatcher`.
   - Added preflight checks against known-rejected PIN history (`pinCache.isRejected`) before invoking card.
   - Updated `AuthenticationPinCache` to preserve rejection history on `clear()`.
   - Removed `peekPin()` to prevent unconsumed access.
3. Owned Zeroizable Types & Memory Hygiene:
   - Extended `Pin1Submission` and `Pin2Submission` with owned byte buffers and auto-close zeroization.
   - Replaced mutable lists with `pendingPin1` and `pendingPin2` ConcurrentHashMaps in `RappPhoneProxyDispatcher`, ensuring prompt zeroization on close/cancel/disconnect.
   - Zeroized text input states in `RappPairingScreen` and `RappAuthorizationDialog`.
4. Screen Capture Protection:
   - Unconditionally set `FLAG_SECURE` and `setRecentsScreenshotEnabled(false)` in `MainActivity` across debug and release.
   - Set `SCREEN_CAPTURE_ALLOWED = false` in `BuildDiagnostics`.
   - Set `SecureFlagPolicy.SecureOn` on all sensitive Compose dialogs.
   - Removed `handleAuthPinIntent` from `MainActivity`.
5. RAPP Lifecycle Hardening:
   - Added absolute handshake deadline (`authDeadlineJob`) and socket read timeout in `StreamRelayListener`.
   - Added periodic liveness polling loop in `RappPhoneProxyDispatcher` using monotonic timestamps.
   - Handled `closeSessionAfterSend`, terminal actions, cancellations, and revocations.
   - Keyed `RappAuthorizationDialog` state to `requestId`.

## Verification Results
- `./gradlew check`: PASSED (all tests, detekt, spotless, lint, verifyReleaseNoLogging, verifyReleaseAbis, verifyReleaseNetworkIsolation).
- `cargo test`: PASSED (75/75 in native/refineid-android-core).
