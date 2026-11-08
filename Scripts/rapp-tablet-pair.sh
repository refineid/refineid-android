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
# never printed. See doc/process/tablet-emulator.md.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=Scripts/adb-ui.sh
source Scripts/adb-ui.sh

readonly pairing_timeout_seconds=60
readonly code_length=6
# The tablet runs in English; these are the app's strings.xml values.
readonly pairing_code_label="Pairing code"

phone=""
tablet=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --phone)
      phone="$2"
      shift 2
      ;;
    --tablet)
      tablet="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done
phone="${phone:-$(ui_wifi_phone)}"
tablet="${tablet:-$(ui_emulator)}"
if [[ -z "${phone}" || -z "${tablet}" ]]; then
  echo "need a phone on Wi-Fi debugging and a running tablet emulator" >&2
  exit 1
fi

echo "phone: opening pairing"
ui_launch_refineid "${phone}"
ui_tap "${phone}" RappPairingRow
ui_wait "${phone}" cardRemoteAccessSwitch
if [[ "$(ui_checked "${phone}" cardRemoteAccessSwitch)" != "true" ]]; then
  ui_tap "${phone}" cardRemoteAccessSwitch
fi
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
if [[ "$(ui_checked "${tablet}" requesterRemoteUseSwitch)" != "true" ]]; then
  ui_tap "${tablet}" requesterRemoteUseSwitch
fi
ui_wait "${tablet}" requesterPairingScreen
sleep "${ui_poll_seconds}"
# The code entry is a transparent field over six boxes; the boxes follow
# the field's label and focus the field when tapped.
ui_tap_next_after "${tablet}" text "${pairing_code_label}"
sleep "${ui_poll_seconds}"
adb -s "${tablet}" shell input text "${code}"
unset code

echo "tablet: waiting for the pairing to finish"
deadline=$((SECONDS + pairing_timeout_seconds))
finished=""
while ((SECONDS < deadline)); do
  if ! ui_has "${tablet}" requesterPairingScreen \
    || ! ui_node "${tablet}" text "${pairing_code_label}" | grep -q .; then
    finished="yes"
    break
  fi
  sleep "${ui_poll_seconds}"
done
if [[ -z "${finished}" ]]; then
  echo "tablet: pairing did not finish within ${pairing_timeout_seconds}s" >&2
  exit 1
fi

failure="$(ui_dump "${tablet}" | grep -oE 'text="(The pairing code was not accepted\.|No phone in pairing mode was found\.|Pairing ended before it was completed\.)"' || true)"
if [[ -n "${failure}" ]]; then
  echo "tablet: pairing failed: ${failure}" >&2
  exit 1
fi
echo "paired"
