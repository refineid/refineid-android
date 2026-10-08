# ADR 0042: Autonomous Multimodal Testing with ARTEMIS

Status: Accepted

Date: 2026-10-08

## Context

RefineID Android maintains an instrumented test suite using Compose UI Test and UI Automator 2.4 (ADR 0010) for deterministic local and CI verification. However, testing physical Android hardware fragmentation, system dialogs, dynamic layout reflows, and cross-application flows (such as the in-app browser and RAPP remote pairing) requires extensive manual device time.

[ARTEMIS](https://github.com/google/artemis) provides an autonomous, vision-language-driven testing agent architecture that controls attached physical Android devices and emulators over ADB using multimodal perception (screenshots, UI accessibility trees, and scrcpy video streaming).

## Decision

We integrate ARTEMIS into the RefineID Android development and verification pipeline following a two-tier testing architecture:

### 1. Two-Tier Testing Architecture

- **Tier 1 (Mandatory Fast Gate — Local & CI Pre-Push)**:
  - `./gradlew check` remains the sole gate enforced by git hooks and GitHub Actions.
  - Runs JVM unit tests, strict linters (Android lint, detekt, Spotless ktlint, Clippy, rustfmt, ShellCheck), and offline synthetic `UiAutomator` tests.
  - 100% deterministic, offline, and sub-minute execution with zero external network or LLM dependencies.
- **Tier 2 (Autonomous Multimodal Device Verification — Development & Lab)**:
  - Driven by ARTEMIS via the native CLI tool `Scripts/test-artemis.sh` and the Model Context Protocol (MCP) server integrated into developer AI environments (such as Antigravity).
  - Runs on demand against connected test hardware (e.g., Samsung Galaxy S22 `SM-S901B`) over USB or Wi-Fi ADB.
  - Exercises end-to-end user journeys, exploratory edge cases, and visual layout rendering.
  - Insights and stable UI trajectories discovered by ARTEMIS are codified back into deterministic Tier 1 `UiAutomator` tests.

### 2. Mainline Test Suites (`Scripts/test-artemis.sh`)

`Scripts/test-artemis.sh` provides unified execution of predefined test suites:

- **`smoke`**: Verifies app launch, system permission handling, main screen surface loading (`UiAutomationIds.MAIN_SCREEN`), and navigates into Diagnostics to inspect live NFC and CCID reader states.
- **`browser`**: Exercises the in-app browser harness (`BrowserHarness.kt`), verifies URL navigation controls, and inspects mutual TLS client-authentication triggers (tracked in Issue #83).
- **`signing`**: Exercises the Document Signing interface (`DocumentSigningCard.kt`), format toggles between PDF and ASiC-E containers, CAN entry, and status transitions (tracked in Issue #84).
- **`management`**: Exercises Card Management (`CardManagementScreen.kt`), verifying attempt counter banners, task modes (Change PIN, Reset PIN via PUK), and safe attempt threshold guidance (tracked in Issue #85).
- **`rapp`**: Exercises Remote Authentication Provider Protocol controls, verifying CPACE pairing switch activation, offer code generation, and countdown timers (tracked in Issue #86).
- **`doctor`**: Runs ARTEMIS system prerequisite and device readiness checks.
- **`ui`**: Launches the interactive ARTEMIS Web Console for real-time screen projection, live streaming, and execution replays.
- **`custom <goal>`**: Executes an arbitrary natural-language testing prompt.

### 3. Execution Profiles

- **Flash Profile (`--profile flash`)**: Fast reactive Observe-Think-Act loop (~3–5s per action step). Used for deterministic UI navigation, sanity checks, and linear smoke testing.
- **Pro Profile (`--profile pro`)**: Multi-agent graph (Planner, Operator, Checker, Safety Net) with milestone checkpoints and incident recovery (~15–40s per step). Used for multi-step exploratory testing, continuous monitoring, and structured diagnostic reports.

### 4. Credential & Security Boundaries

- **Zero PIN Logging in Repository**: Test PINs, card secrets, or personal certificate identifiers are never committed to the repository, hardcoded in test scripts, or exported to version control.
- **Development Cards**: Physical testing uses dedicated development cards with known test PINs and available PUK recovery.
- **PUK Protection**: In accordance with RefineID security policy, the app's internal safeguards prevent exhausting the final two PUK attempts (`refuse_low_attempts_puk`), ensuring physical test cards cannot be permanently damaged by software.
- **Local Trace Isolation**: ARTEMIS execution traces and recorded session media remain in local developer directories (`traces/`) and are never committed to git.
