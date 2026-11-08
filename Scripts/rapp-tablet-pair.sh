#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Pair the bridged tablet emulator (RAPP requester) with the physical phone
# (custodian) without a hand on either device.
#
# Usage:
#
#   Scripts/rapp-tablet-pair.sh [--phone <serial>] [--tablet <serial>]
#
# The phone must be reached over Wi-Fi debugging and hold a primed card; the
# tablet must run from Scripts/start-tablet-emulator.sh. The pairing code is
# read from the phone's screen into a variable and typed on the tablet; it is
# never printed. Progress goes to stdout; the last line is "paired" on
# success. See doc/process/tablet-emulator.md.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=Scripts/adb-ui.sh
source Scripts/adb-ui.sh

readonly pairing_timeout_seconds=60
readonly code_length=6

usage() {
  echo "usage: $0 [--phone <serial>] [--tablet <serial>]" >&2
  exit 2
}

phone=""
tablet=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --phone | --tablet)
      [[ $# -ge 2 && -n "$2" ]] || usage
      if [[ "$1" == "--phone" ]]; then phone="$2"; else tablet="$2"; fi
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done
phone="${phone:-$(ui_wifi_phone)}"
tablet="${tablet:-$(ui_emulator)}"

echo "phone: opening pairing"
ui_open_refineid "${phone}"
ui_tap "${phone}" RappPairingRow
ui_wait "${phone}" cardRemoteAccessSwitch
ui_set_switch "${phone}" cardRemoteAccessSwitch true
ui_wait "${phone}" offeringCodeText
code="$(ui_text "${phone}" offeringCodeText | tr -d ' -')"
if [[ ${#code} -ne ${code_length} ]]; then
  echo "phone: pairing code not readable" >&2
  exit 1
fi

echo "tablet: entering the pairing code"
ui_launch_refineid "${tablet}"
ui_tap "${tablet}" requesterPairingRow
ui_wait "${tablet}" requesterRemoteUseSwitch
# Turning remote use off forgets a held pairing, so the code entry is
# offered again whatever the tablet held before.
ui_set_switch "${tablet}" requesterRemoteUseSwitch false
ui_set_switch "${tablet}" requesterRemoteUseSwitch true
ui_wait "${tablet}" pairingCodeBoxes
# The code entry is a transparent field over the boxes, left out of the
# uiautomator dump; tapping the boxes focuses it.
ui_tap "${tablet}" pairingCodeBoxes
sleep "${ui_poll_seconds}"
ui_type "${tablet}" "${code}"
unset code

echo "tablet: waiting for the pairing to finish"
deadline=$((SECONDS + pairing_timeout_seconds))
tags=""
while ((SECONDS < deadline)); do
  tags="$(ui_tags "${tablet}")"
  if grep -qx pairingFailure <<< "${tags}" || ! grep -qx pairingCodeBoxes <<< "${tags}"; then
    break
  fi
  sleep "${ui_poll_seconds}"
done
if grep -qx pairingFailure <<< "${tags}"; then
  # The reason is one of the app's fixed failure strings, never a value.
  echo "tablet: pairing failed: $(ui_text "${tablet}" pairingFailureReason)" >&2
  exit 1
fi
if grep -qx pairingCodeBoxes <<< "${tags}"; then
  echo "tablet: pairing did not finish within ${pairing_timeout_seconds}s" >&2
  exit 1
fi
echo "paired"
