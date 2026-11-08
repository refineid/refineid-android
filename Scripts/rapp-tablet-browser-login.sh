#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Log in from the tablet emulator's in-app browser with the card on the
# paired custodian phone, over RAPP, and judge the TLS client-certificate
# handshake from the debug build's browser traces.
#
# Usage:
#
#   Scripts/rapp-tablet-browser-login.sh [--url <https url>] [--tablet <serial>] [--phone <serial>]
#
# The tablet must be paired (Scripts/rapp-tablet-pair.sh) and run a debug
# build. When the phone asks for PIN 1, the script says so and waits: the
# PIN is entered on the phone by its holder, never by a script. A PIN field
# on the tablet fails the run. Page content is never printed; it can hold
# the certificate subject. See doc/process/tablet-emulator.md.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=Scripts/adb-ui.sh
source Scripts/adb-ui.sh

# A public test service that requests a client certificate from any issuer.
readonly default_url="https://certauth.cryptomix.com/json/"
readonly login_timeout_seconds=120
readonly trace_tag=" RefineID: "
readonly tablet_pin_tags="browserPin1Field browserUnlockPin1Field browserUnlockCanField"
readonly phone_pin_tag="rappPinField"

usage() {
  echo "usage: $0 [--url <https url>] [--tablet <serial>] [--phone <serial>]" >&2
  exit 2
}

url="${default_url}"
tablet=""
phone=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url | --tablet | --phone)
      [[ $# -ge 2 && -n "$2" ]] || usage
      case "$1" in
        --url) url="$2" ;;
        --tablet) tablet="$2" ;;
        --phone) phone="$2" ;;
      esac
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done
[[ "${url}" == https://* ]] || usage
tablet="${tablet:-$(ui_emulator)}"
phone="${phone:-$(ui_wifi_phone)}"

browser_traces() {
  "${ui_adb}" -s "${tablet}" logcat -d | grep -F "${trace_tag}" | grep -oE 'browser:[a-z-]+( [a-z-]+=[A-Z_a-z0-9-]+)*' || true
}

echo "tablet: opening the browser"
"${ui_adb}" -s "${tablet}" logcat -c
ui_launch_refineid "${tablet}"
if ! ui_wait "${tablet}" browserAction; then
  echo "tablet: no browser action; is the tablet paired and the phone's card presented?" >&2
  exit 1
fi
ui_tap "${tablet}" browserAction
ui_wait "${tablet}" browserUrlField
ui_tap "${tablet}" browserUrlField
sleep "${ui_poll_seconds}"
"${ui_adb}" -s "${tablet}" shell input keycombination KEYCODE_CTRL_LEFT KEYCODE_A
"${ui_adb}" -s "${tablet}" shell input keyevent KEYCODE_DEL
ui_type "${tablet}" "${url}"
"${ui_adb}" -s "${tablet}" shell input keyevent KEYCODE_ENTER

echo "tablet: waiting for the client-certificate handshake"
deadline=$((SECONDS + login_timeout_seconds))
asked_for_pin=""
outcome=""
while ((SECONDS < deadline)); do
  tablet_tags="$(ui_tags "${tablet}")"
  for tag in ${tablet_pin_tags}; do
    if grep -qx "${tag}" <<< "${tablet_tags}"; then
      echo "tablet: shows ${tag}; a remote login must never ask for a secret on the requester" >&2
      exit 1
    fi
  done
  if [[ -z "${asked_for_pin}" ]] && ui_has "${phone}" "${phone_pin_tag}"; then
    echo "phone: enter PIN 1 on the phone"
    asked_for_pin="yes"
  fi
  traces="$(browser_traces)"
  if grep -q '^browser:tls-error' <<< "${traces}"; then
    outcome="tls-error"
    break
  fi
  if grep -qE '^browser:signature status=(WRONG_PIN|PIN_LOCKED|REFUSED|CANCELLED|TIMED_OUT|INTERRUPTED|ERROR)' <<< "${traces}"; then
    outcome="signature-failed"
    break
  fi
  if grep -q '^browser:signature status=SUCCEEDED' <<< "${traces}"; then
    outcome="signed"
    break
  fi
  sleep "${ui_poll_seconds}"
done

echo "traces:"
browser_traces | sed 's/^/  /'
case "${outcome}" in
  signed)
    echo "logged in"
    ;;
  "")
    echo "no handshake outcome within ${login_timeout_seconds}s" >&2
    exit 1
    ;;
  *)
    echo "login failed: ${outcome}" >&2
    exit 1
    ;;
esac
