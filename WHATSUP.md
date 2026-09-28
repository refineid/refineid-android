# WHATSUP

branch: agent/security-fixes
purpose: Fix security issues in RefineID Android: CPace pairing, credential custody, zeroization, FLAG_SECURE, and RAPP lifecycle.
started: 2026-09-28T18:20+03:00 by petri
heartbeat: 2026-09-28T19:55+03:00
status: verified

## Review Fixes Applied (Round 2)
- Replaced dynamic exception messages with static strings in `RappPairingModel` failure phases and `RappPhoneProxyDispatcher` traces.
- Named constants extracted (`SESSION_NONCE_BYTES = 32`, `EMPTY_CBOR_MAP_BYTE = 0xa0.toByte()`, `STREAM_CANDIDATE_ID = "stream-1"`) and session nonces zeroized in `finally` across handshake paths.
- Enforced unified `Dispatchers.Main` policy for all `RappAuthorizationInbox` operations (`dismissInbox`, `askBrowserAuth`, `askDocumentSign`, `showTapPrompt`, `dismissTapPrompt`).
- Moved `freshCert` into `try-finally` before `pin2Submission.copyBytes()` to guarantee certificate cleanup, and added graceful `IllegalStateException` handling.
- Zeroized liveness challenge copy in `finally` block to protect against polling exceptions.
- Added strict KDoc on `peekBytes` in `Pin1Submission` and `Pin2Submission` prohibiting retention or mutation.
- Extracted `handleRelayFrame` to resolve detekt `LongMethod` gate cleanly.
- Updated `2026-09-remediation-report.md` with Android `NsdManager` conflict resolution, local NFC cache retention, and synthetic test PIN invariant documentation.

## Review Fixes Applied (Round 1)
- Fixed double-ownership bug in `handleBrowserAuthSuccess` by providing independent `copyBytes()` buffers to `pinCache.recordVerified` and `primedCanStore.writePin1`.
- Added regression test `independentOwnershipPreservesCachedPinWhenSecondaryConsumerZeroizes` in `AuthenticationPinCacheTest`.
- Replaced `rawBytes()` in `Pin1Submission` and `Pin2Submission` with non-copying borrowing accessor `peekBytes { ... }`.
- Added `AuthenticationPinCache.isRejected(submission: Pin1Submission)` to check rejection status without exposing or leaking byte copies.
- Eliminated raw intermediate copies in `performBrowserAuthWithRetry` and `BrowserPinCoordinator`.
- Extracted named constants for magic values (`CPACE_RANDOM_BYTES`, `STREAM_CANDIDATE_ID`, `LIVENESS_CHALLENGE_BYTES`, `LIVENESS_JITTER_MS`, `DEFAULT_PAIRING_PROFILES`) and zeroized CPace random arrays in `finally`.
- Transmitted attached frames on all bridge actions before evaluating close/drop triggers.
- Ensured inbox dismissal is dispatched to `Dispatchers.Main`.
- Made `RappCpacePairingFlowTest` cross-platform across macOS (`.dylib`), Linux (`.so`), and Windows (`.dll`).
- Updated remediation report documentation regarding UI String GC limits and static-rendezvous collision model.

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
