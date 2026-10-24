#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Build, install, and launch the latest diagnostic debug build on one connected Android device.
#
# The calendar version and HHMM build number are dynamically passed as command-line
# Gradle overrides, matching RefineID-Apple's install-ios-development.sh.
#
# Usage:
#
#   Scripts/install-device.sh [<adb device serial or IP:port>]
#
# If no device argument is provided, the first connected device is detected automatically via adb.

set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

# Without an argument, a device reached over Wi-Fi (an address:port serial)
# is preferred to one on the cable: the phone's one USB-C port carries the
# card reader whenever a reader is under test, so the cable comes and goes.
device="${1:-}"
if [[ -z "$device" ]]; then
  connected=$(adb devices | grep -v "List of devices" | grep -w "device" | awk '{print $1}' || true)
  device=$(printf '%s\n' "$connected" | grep -E '^[0-9.]+:[0-9]+$' | head -n 1 || true)
  if [[ -z "$device" ]]; then
    device=$(printf '%s\n' "$connected" | head -n 1 || true)
  fi
fi

read -r yy mm dd hh mn <<<"$(date -u '+%y %m %d %H %M')"
version="${yy}.$((10#$mm)).$((10#$dd))"
build=$((10#$hh * 100 + 10#$mn))

target_msg="connected device"
if [[ -n "$device" ]]; then
  target_msg="$device"
  export ANDROID_SERIAL="$device"
fi

echo "building RefineID ${version} (${build}) for ${target_msg}..."
./gradlew installDebug -PversionName="${version}" -PbuildNumber="${build}"

if [[ -n "$device" ]]; then
  adb -s "$device" shell am start -n fi.refineid.android/.MainActivity
else
  adb shell am start -n fi.refineid.android/.MainActivity
fi

echo "installed and launched RefineID ${version} (${build})"
