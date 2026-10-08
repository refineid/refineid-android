# Artemis Multimodal Testing Guide

This guide documents how to use [ARTEMIS](https://github.com/google/artemis) for physical Android device testing in RefineID.

## Overview

ARTEMIS is an autonomous multimodal mobile agent that drives real Android phones and emulators using vision-language models (e.g. Gemini 3.8 Flash). It perceives the device screen via screenshots, accessibility hierarchies, and scrcpy video streaming, and executes touch/keyboard actions over ADB.

In RefineID, ARTEMIS operates as our **Tier 2** testing layer: verifying complex physical UI journeys, testing visual layout integrity, and exploring edge cases that are then codified into fast, deterministic **Tier 1** `UiAutomator` tests.

For architectural context, see [ADR 0042: Autonomous Multimodal Testing with ARTEMIS](../architecture/0042-artemis-multimodal-device-testing.md).

---

## Prerequisites

1. **Python Runtime & Package Manager**:
   - Python 3.12+ (managed via `uv`).
2. **Video Toolchain**:
   - `ffmpeg` and `scrcpy` (install via `brew install ffmpeg scrcpy` on macOS).
3. **Android Device**:
   - At least one connected physical device (e.g. Samsung Galaxy S22) or running emulator with USB debugging enabled.
   - Verify via `adb devices`.
4. **Multimodal LLM Credentials**:
   - A valid Gemini API key configured in the Artemis `.env` file (`GEMINI_API_KEY`).

---

## CLI Usage (`Scripts/test-artemis.sh`)

RefineID provides a mainline runner script at `Scripts/test-artemis.sh` that wraps ARTEMIS tasks for RefineID:

```bash
# Verify system readiness and attached device connectivity
./Scripts/test-artemis.sh doctor

# Run the primary smoke test (app launch, main screen, diagnostics reader check)
./Scripts/test-artemis.sh smoke

# Test the in-app browser harness and authentication controls
./Scripts/test-artemis.sh browser

# Test the Document Signing UI and container format toggles
./Scripts/test-artemis.sh signing

# Test Card Management views, attempt counters, and task selectors
./Scripts/test-artemis.sh management

# Test RAPP remote pairing switch and countdown timers
./Scripts/test-artemis.sh rapp

# Launch the interactive Artemis Web Console
./Scripts/test-artemis.sh ui

# Execute an arbitrary custom natural-language goal
./Scripts/test-artemis.sh custom "Open RefineID, go to Settings, and check Timestamp Authority servers"
```

### Options

- `--serial, -s <device_serial>`: Target a specific Android device when multiple are connected.
- `--profile, -p <flash|pro>`: Choose between `flash` (fast reactive loop, ~3–5s/step) and `pro` (deep planning, checkpoint verification, ~15–40s/step). Defaults to `flash`.

---

## Model Context Protocol (MCP) Integration

ARTEMIS provides a native MCP server for AI IDEs (Antigravity, Codex, Claude Code):

1. **Install Configuration**:
   ```bash
   (cd ~/src/artemis && uv run artemis mcp --install antigravity)
   ```
2. **Available Agent Tools**:
   - `mobile_run_task`: Execute an autonomous testing goal on the device.
   - `mobile_get_device_state`: Capture the live screenshot, UI hierarchy, and foreground activity.
   - `mobile_diagnose`: Self-heal ADB connections and verify environment health.
   - `mobile_inspect_trace`: Query step-by-step logs and execution recordings.

---

## Tracking Issues

Specific test suite implementations and test cases are tracked under the following GitHub issues:

- [#83](https://github.com/refineid/refineid-android/issues/83): In-App Browser & TLS Client Certificate Authentication Flows
- [#84](https://github.com/refineid/refineid-android/issues/84): Qualified Document Signing (PAdES-LTA / ASiC-E) & Validation
- [#85](https://github.com/refineid/refineid-android/issues/85): Card Management, PIN Change, and PUK Recovery
- [#86](https://github.com/refineid/refineid-android/issues/86): RAPP Remote Authentication Pairing & Authorization
