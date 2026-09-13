# RefineID Android repository instructions

- RULE #1: PIN CODES NEVER TRAVEL OVER ANY NETWORK.
  PIN1 and PIN2 NEVER leave the phone when accessed via RAPP.
  RAPP MUST ABSOLUTELY DENY AND PRECLUDE ALL ATTEMPTS TO TRANSPORT PIN CODES ANYWHERE.
  PIN1 stays cached on the mobile device. PIN2 prompts appear strictly on the mobile
  device screen. Remote clients and browsers operate via a protected authentication
  path and never prompt for, receive, or handle PIN codes.
- RULE #2: ZERO PIN DATA AND CANDIDATE PIN-LENGTH LOGGING ACROSS ALL ENVIRONMENTS.
  Never log, trace, display, or format PIN bytes, character offsets, supplied/candidate
  PIN lengths, or development PIN role identifiers in log sinks, audit records, or
  error strings. Only static specification policy bounds may be reported. Never commit
  test PINs or card secrets.

## Product

- System-browser authentication remains the end state. The in-app browser is
  a supported login vehicle on stock Android: any HTTPS site, both card
  transports, every signature behind the holder's PIN.
- Android also serves as the RAPP reader for the other RefineID platforms.
- User-facing UI is terse. Explanations, status, and diagnostics belong in
  documentation and developer tooling, not product copy.
- Keep card transport, identity-card protocol, browser integration, and UI as
  separate boundaries. Keep Android framework types out of protocol logic so
  JVM unit tests can use synthetic descriptors and byte sequences.
- fineid-spec governs protocol behavior. Prefer refineid-core for reusable
  shipped logic; refineid-mono-internal is the implementation oracle and
  RefineID-Apple the product-behavior and UX reference.

## Security

- Do not leak personal or private information in commits: no real PIN, PUK,
  CAN, private key, card serial, personal certificate, identity code, device
  serial, network address, APDU capture, or reader/card dump.
- Committed tests use synthetic identities and protocol fixtures. Real-card
  evidence stays local and contains no identifying values.
- Shipped code collects PIN and CAN on device, holds them only as mutable
  short-lived memory, and zeroizes them after use.
- Debug tracing serves development and may record whatever protocol detail the
  work needs; keep credential values out of anything persisted or committed.
  Release builds emit no logs and no Internet access; keep the sink in variant
  source sets and inspect release artifacts for trace literals.
- Do not deliberately consume a PIN retry unless the recovery procedure and
  retry count are known.
- Disable application backup and screen capture wherever sensitive data can
  appear.
- Dependency & supply-chain audits:
  - Push-time gates stay fast: pre-push runs `./gradlew check` and locked `cargo audit`.
    Never wire slow vulnerability scanners (like OWASP Dependency-Check) into git hooks
    due to NVD API rate limits and long database sync times.
  - Periodic deep vulnerability scans: Run `Scripts/audit-dependencies.sh` (which runs
    `cargo audit`, `osv-scanner`, and OWASP `dependency-check`) whenever:
    1. Adding or modifying dependencies in `gradle/libs.versions.toml` or `build.gradle.kts`.
    2. Modifying native Rust dependencies in `Cargo.toml` or `Cargo.lock`.
    3. Preparing a production release (`Scripts/build-release-apk.sh` or `Scripts/release-play-store.sh`).
    4. Explicitly asked to audit dependencies or investigate supply-chain vulnerabilities.

## Engineering

- Verify from specifications, don't wild guess. Cite what a source proves, and
  say what it does not. Where observation contradicts documentation, the
  recorded exchange wins and is cited as observation, not spec.
- If something is not working, it is by default a bug in our code or test
  harness, not a feature of the platform. "Impossible/blocked" claims require
  exchange-level evidence from a clean-slate repro.
- Hardware claims require an observed exchange on a physical device.
- Every transport parser validates lengths, message type, slot, sequence, and
  response status before exposing payload bytes.
- Add tests for malformed and truncated inputs, not just successful paths.
- No magic codes: name every protocol code, size, offset, and limit, or derive
  it from a named domain constant.
- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments.
- Record findings and durable knowledge as repository documentation under
  `doc/`, written for public distribution, not in private or per-session
  assistant memory. A committed document is the shared source of truth; redact
  anything the Security section forbids before writing it down.
- Kotlin follows standard Kotlin conventions; ASCII only in source and
  committed fixtures unless protocol fidelity requires exact bytes.
- Keep the toolchain strict: warnings are errors everywhere (Kotlin extra
  warnings, full Android lint, detekt, ktlint via Spotless, Clippy, rustfmt,
  ShellCheck). `./gradlew check` runs all of it.
- The quality gates are mandatory git hooks, not suggestions. Run
  `Scripts/install-hooks.sh` once per clone (`Scripts/bootstrap-macos.sh`
  does it); pre-commit runs the fast gates, pre-push runs the full
  `./gradlew check`. Never commit or push with `--no-verify`, never disable,
  weaken, or work around a gate to land a change, and never leave the hooks
  uninstalled. This binds every contributor, human and AI agent alike: fix
  the finding, or raise the policy question openly instead of dodging it.
  GitHub Actions reruns the same `./gradlew check` floor on every push and
  pull request; a red check on the remote is a defect to fix immediately,
  not a status to explain away.
- Commit often when the build and lint are clean. Push when a feature is
  ready. Subject and body only: no AI attribution, co-author, sign-off, or
  review trailers.
- One task, one worktree (`~/src/wt/refineid-android-<topic>`) on one
  `agent/<topic>` branch, one pull request per branch. Each worktree carries
  a `WHATSUP.md` work log; run `Scripts/agent-housekeeping.sh` when starting
  and keep the house clean. Merge the pull request once CI is green, then
  remove the worktree and branch and fast-forward `main`. Full workflow:
  `doc/process/agent-worktrees.md`.
- Never put a git worktree under `/tmp` or directly in `~/src/`; all worktrees
  must live under `~/src/wt/`.
- Never poll background commands or set rapid check timers (e.g. 10s-30s). When running builds, tests, or async tasks, execute asynchronously and wait strictly for system completion notifications.
- When stuck, research with fellow AI available.

## Licensing

- This repository and the referenced RefineID sources are Apache-2.0.
- Retain existing copyright and license notices when adapting source between
  repositories.

## Commits and integration

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once the
  required checks pass. Sync local `main` with the merged remote.
  Use merge commits to preserve the branch history; do not squash it.
