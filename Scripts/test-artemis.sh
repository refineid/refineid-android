#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Execute autonomous multimodal Artemis test suites against connected Android devices.
#
# Supported suites:
#   smoke       - Verify app launch, main navigation, and hardware diagnostics
#   browser     - Test in-app browser harness and authentication controls
#   signing     - Test document signing UI, format toggles, and status cards
#   management  - Test card management views, attempt banners, and task modes
#   rapp        - Test RAPP pairing switch, offer generation, and timers
#   doctor      - Run Artemis system diagnostics and readiness checks
#   ui          - Launch the Artemis web test console
#   custom      - Execute an arbitrary natural-language test goal
#
# Usage:
#   Scripts/test-artemis.sh [suite] [--serial <serial>] [--profile <flash|pro>]
#   Scripts/test-artemis.sh custom "<natural language goal>" [--serial <serial>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Resolve Artemis repository directory
ARTEMIS_DIR="${ARTEMIS_HOME:-}"
if [[ -z "${ARTEMIS_DIR}" ]]; then
  if [[ -d "${REPO_DIR}/../artemis" ]]; then
    ARTEMIS_DIR="$(cd "${REPO_DIR}/../artemis" && pwd)"
  elif [[ -d "${HOME}/src/artemis" ]]; then
    ARTEMIS_DIR="${HOME}/src/artemis"
  fi
fi

if [[ -z "${ARTEMIS_DIR}" || ! -d "${ARTEMIS_DIR}" ]]; then
  echo "Error: Artemis repository not found." >&2
  echo "Please set ARTEMIS_HOME or clone Artemis into ~/src/artemis" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "Error: 'uv' package manager not found on PATH." >&2
  exit 1
fi

SUITE="${1:-smoke}"
shift || true

SERIAL="${ANDROID_SERIAL:-}"
PROFILE="flash"
CUSTOM_GOAL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial|-s)
      SERIAL="$2"
      shift 2
      ;;
    --profile|-p)
      PROFILE="$2"
      shift 2
      ;;
    *)
      if [[ "${SUITE}" == "custom" && -z "${CUSTOM_GOAL}" ]]; then
        CUSTOM_GOAL="$1"
        shift
      else
        echo "Unknown argument: $1" >&2
        exit 1
      fi
      ;;
  esac
done

# If no device serial explicitly specified, pick the first connected adb device
if [[ -z "${SERIAL}" ]]; then
  SERIAL=$(adb devices | grep -v "List of devices" | grep -w "device" | awk '{print $1}' | head -n 1 || true)
fi

if [[ -z "${SERIAL}" && "${SUITE}" != "doctor" ]]; then
  echo "Error: No connected Android device found via adb." >&2
  echo "Please connect a device via USB/Wi-Fi or start an emulator." >&2
  exit 1
fi

case "${SUITE}" in
  doctor)
    echo "Running Artemis environment diagnostics..."
    (cd "${ARTEMIS_DIR}" && uv run artemis doctor)
    exit 0
    ;;
  ui)
    echo "Starting Artemis Web Console..."
    exec uv --directory "${ARTEMIS_DIR}" run artemis ui
    ;;
  smoke)
    GOAL="Open the RefineID app (package fi.refineid.android), verify the main screen loads, dismiss any initial system permission popups, navigate into Diagnostics, inspect the NFC and USB reader status lines, and navigate back to the main screen."
    ;;
  browser)
    GOAL="Open the RefineID app (package fi.refineid.android), tap the Browser row to open the in-app browser harness, verify the URL address bar, back, forward, and reload buttons are visible and active, then navigate back to the main screen."
    ;;
  signing)
    GOAL="Open the RefineID app (package fi.refineid.android), tap the Sign row to enter the Document Signing screen, verify the document selection button, format switch (PDF vs ASiC container), and PIN2 entry fields are rendered, then navigate back."
    ;;
  management)
    GOAL="Open the RefineID app (package fi.refineid.android), navigate to Card Management, verify the card status overview, task selector (Change PIN, Reset PIN, Activate Card), and attempt counters, then return to home."
    ;;
  rapp)
    GOAL="Open the RefineID app (package fi.refineid.android), locate the Remote Access card on the home screen, toggle the remote access switch, verify the CPACE pairing offer and countdown timer appear, then toggle it off."
    ;;
  custom)
    if [[ -z "${CUSTOM_GOAL}" ]]; then
      echo "Error: 'custom' suite requires a goal description string." >&2
      exit 1
    fi
    GOAL="${CUSTOM_GOAL}"
    ;;
  *)
    echo "Error: Unknown test suite '${SUITE}'." >&2
    echo "Available suites: smoke, browser, signing, management, rapp, doctor, ui, custom" >&2
    exit 1
    ;;
esac

echo "============================================================"
echo " Starting ARTEMIS Test Suite: ${SUITE}"
echo " Target Device : ${SERIAL}"
echo " Profile       : ${PROFILE}"
echo " Goal          : ${GOAL}"
echo "============================================================"

(
  cd "${ARTEMIS_DIR}"
  uv run artemis run "${GOAL}" \
    --device-serial "${SERIAL}" \
    --profile "${PROFILE}"
)
