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
  Release builds emit no logs, zero telemetry, and zero third-party network egress.
  Network access (android.permission.INTERNET) in release builds is strictly reserved
  for RAPP (local-network TCP stream relay to paired requesters) and the user-directed
  in-app browser authentication harness. Keep tracing sinks in variant source sets
  and inspect release artifacts for trace literals.
- Debug builds make every error visible: every failure path (refusal, transport
  close, card or NFC error, failed operation) reports through one debug-only error
  sink, an interface the protocol layers call and the debug source set implements.
  It writes the event and its cause to logcat under one tag and to an on-screen
  error list with copy and clear-list. An error message carries type and case
  names only, never a value read from the card, the network, the device or the
  user: no PIN or PUK data (RULE #2), card access numbers, names, identity codes,
  certificate content, APDUs, addresses, or device or card serials. Debug tracing
  stays separate from this list. Release builds contain no error sink and no
  logging code; inspect the release artifact for it as for trace literals.
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
- No Magic Codes - define everything (see [Types and numbers](#types-and-numbers)).
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
  GitHub Actions runs the same `./gradlew check` floor weekly on Linux and
  on demand. It is portability coverage; local mandatory hooks remain the
  per-change gate.
- Commit often when the build and lint are clean. Push when a feature is
  ready. Subject and body only: no AI attribution, co-author, sign-off, or
  review trailers.
- Reading does not require a worktree; writing does. The main checkout is
  never edited directly. Before writing code or modifying files for any task,
  create a dedicated git worktree strictly under `../wt/`
  (`../wt/refineid-android-<topic>`) on a `<topic>` branch. Never work
  directly on `main` or modify files in the main checkout.
- All worktrees MUST live strictly under `../wt/`, never loose beside
  repositories or in parent directories.
- Never put a git worktree under `/tmp`. It is cleared on reboot and takes the
  branch's only checkout with it.
- One task, one worktree, one branch (`<topic>`), one pull request per branch.
  Run `Scripts/agent-housekeeping.sh` when starting and keep the house clean. Merge
  the pull request once CI is green, then remove the worktree and branch and
  fast-forward `main`. Full workflow: `doc/process/agent-worktrees.md`.
- Never poll background commands or set rapid check timers (e.g. 10s-30s). When running builds, tests, or async tasks, execute asynchronously and wait strictly for system completion notifications.
- Whenever modifying Android application code or UI, proactively build and install the debug APK to any connected physical test device (`adb install -r app/build/outputs/apk/debug/app-debug.apk`) without waiting for explicit user instructions. When a device is attached over USB, also configure and maintain Wi-Fi debugging (`adb tcpip 5555 && adb connect <ip>:5555`) so deployment and verification continue smoothly if the cable is detached. Always verify installation success. If no device is attached or reachable, notify the user immediately.
- When stuck, research with fellow AI available.

## Licensing

- This repository and the referenced RefineID sources are Apache-2.0.
- Retain existing copyright and license notices when adapting source between
  repositories.

## Code reviews and AI reviewers

- For automated code reviews and multi-turn pull request discussions with the Muse Code agent (`muse`), always invoke with:
  ```bash
  muse --model muse-spark-1.3-contributor --reasoning-effort max
  ```
  Helper scripts `discuss-with-muse` and `review-with-muse` default to these options.
- Codex review is reserved strictly for maintainer-requested reviews (invoked only on explicit maintainer request due to expense and low quota). When requested, invoke with:
  ```bash
  codex --model gpt-6-astra -c model_reasoning_effort=high
  ```

## Commits and integration

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once the
  required checks pass. Sync local `main` with the merged remote.
  Use squash merges to keep the `main` history linear; do not use merge commits.

## Record deferred findings

- While working, file a GitHub issue in the owning repository for each
  confirmed, actionable defect or quality gap that cannot reasonably be
  fixed within the current task. Filing these issues is authorized; do not
  wait for a separate instruction for each finding.
- Search existing open issues first. Reuse the matching issue and add only
  new, useful evidence instead of creating a duplicate. Group findings only
  when they share a cause and can be resolved by one focused change.
- State the observed behavior, expected behavior, affected repository-relative
  paths, reproduction or inspection evidence, impact, and acceptance checks.
  Distinguish observations from hypotheses and specification requirements.
  Never claim an unexecuted test or hardware operation was verified.
- Keep speculative improvements in working notes until they have a concrete
  problem and useful acceptance criteria. Avoid issue spam and severity claims
  unsupported by evidence.
- Never put credentials, PIN data or candidate lengths, card secrets,
  personal data, private workspace paths, or persistent device identifiers
  in issue text, logs, screenshots, attachments, or reproduction fixtures.
  Report security-sensitive findings through the repository's private
  reporting process; if no safe channel is available, notify the user
  without publishing sensitive details.
- An issue does not excuse a broken gate or incomplete work needed to make
  the current task correct. Fix findings required for the task before handing
  it over; file independently deferred work with a clear scope.
- Link newly filed or reused issues in the task handoff. If issue creation is
  unavailable, preserve a sanitized finding locally and report that it was
  not filed; never silently discard it.

## Types and numbers

Two rules from refineid-core bind this repository too: refinement types
and no magic numbers. Define everything.

Refinement types:

- Read
  [refinement-types.md](https://github.com/refineid/refineid-core/blob/main/docs/architecture/refinement-types.md)
  and its case study before designing or reviewing a type.
- A type is a predicate: input from the wire, the card, the platform or
  storage crosses one border, with one constructor that checks every
  specification predicate once, and downstream code trusts the result.
- Every byte is meaning, transit or citation. Nothing raw sits beside a
  typed value, and no byte-like parameter stands where a nominal type
  belongs.
- The policy's review questions are the checklist for writing and review.

No magic numbers:

- No anonymous numeric literal in production code or ordinary tests. Every
  protocol code, status word, tag, size, offset, limit, timeout and count
  is a named constant or derives from one. Writing a hexadecimal value in
  decimal does not name its meaning.
- No hand-typed hexadecimal arrays, not even in tests. A wire buffer or an
  expected fixture is assembled from the same named constants the
  serializer uses; a synthetic test payload is an ASCII string.
- A raw wire value lives only in the initializer of a truthful named
  constant, or in one named constant holding an opaque, externally
  specified block, such as a known-answer vector, a registered identifier
  or an object identifier, with a citation to its source.

## STPA in design

Every design includes a short System-Theoretic Process Analysis (STPA),
sized to the change. [stpa-rapp.md](https://github.com/refineid/refineid-core/blob/main/docs/security/stpa-rapp.md) is the worked example and the
record for RAPP and its applications.

- Ground the analysis in the losses (L-n) and hazards (H-n) the record
  already names. Add a loss only when a real stakeholder could suffer it
  and no recorded loss covers it, and a hazard only for a real system
  state that leads to a loss.
- Do not invent imaginary losses, hazards or threats to fill the method.
  A few real ones beat a long list.
- Describe the control structure the change touches: the controllers,
  their control actions, and the feedback each gets. Look first for
  missing, late or misleading feedback; a controller acting on a stale
  process model is the usual cause of an unsafe control action.
- List the unsafe control actions (UCA-n) the affected controllers could
  issue or fail to issue, the hazards each leads to, and the controller
  constraints (CC-n) the design enforces against them.
- A small change records its analysis in the pull request, and a change
  with no control action or feedback to analyse says so in one line. A
  change to the control structure updates the STPA record that covers it.

## No backwards compatibility

- When code, a script, a command, an API, a file format or a setting is
  replaced, remove the old one in the same change. Do not leave
  compatibility wrappers, deprecated aliases, forwarding shims, fallback
  readers or migration paths behind.
- Update every caller, hook, CI job and document to the replacement in that
  same change instead of keeping the old entry point alive for them.

## Independent review

- Before a pull request merges, review its diff independently with the `agy`
  CLI and the `gemini-3.8-flash-high` model.
- Run `agy` headless in its sandbox and plan mode, from an empty directory,
  with the diff pasted into the prompt and no tool use. Frame the request as
  a code review from the project's author.
- Check every finding against the code. Fix the real ones and list the
  rejected ones, with the reason, in the pull request description.

## Working method

Read [doc/process/working-method.md](doc/process/working-method.md) before starting: the roles (front agent, implementation agents), what a brief contains, the feedback loops, and which documentation is kept. The same file is in every RefineID repository.
