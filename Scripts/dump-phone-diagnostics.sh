#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Trigger and print plaintext diagnostics from a connected Android device running debug build.
#
# Usage:
#   scripts/dump-phone-diagnostics.sh [--clear] [<adb device serial or IP:port>]

set -euo pipefail

clear_logs=false
device=""

for arg in "$@"; do
  if [[ "$arg" == "--clear" ]]; then
    clear_logs=true
  elif [[ -z "$device" ]]; then
    device="$arg"
  fi
done

if [[ -z "$device" && -n "${ANDROID_SERIAL:-}" ]]; then
  device="${ANDROID_SERIAL}"
elif [[ -z "$device" ]]; then
  device=$(adb devices | grep -v "List of devices" | grep -w "device" | awk '{print $1}' | head -n 1 || true)
fi

adb_cmd=("adb")
if [[ -n "$device" ]]; then
  adb_cmd+=("-s" "$device")
fi

if [[ "$clear_logs" == true ]]; then
  echo "Clearing diagnostics and trace logs on ${device:-default device}..." >&2
  "${adb_cmd[@]}" shell am broadcast -a fi.refineid.android.CLEAR_LOGS -p fi.refineid.android > /dev/null
  echo "Logs cleared." >&2
  exit 0
fi

# Request diagnostic dump
"${adb_cmd[@]}" shell am broadcast -a fi.refineid.android.DUMP_DIAGNOSTICS -p fi.refineid.android > /dev/null

# Small pause to allow file writing to finish
sleep 0.2

# Read back from internal storage using run-as (supported on debug builds)
"${adb_cmd[@]}" shell run-as fi.refineid.android cat files/diagnostics.txt
