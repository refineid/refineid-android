#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Build, install, and launch the latest diagnostic debug build on one connected Android device.
#
# The calendar version and ten-minute build number are dynamically passed as command-line
# Gradle overrides, matching RefineID-Apple's install-ios-development.sh.
#
# Usage:
#
#   Scripts/install-device.sh [<adb device serial or IP:port>]
#
# If no device argument is provided, the first connected device is detected automatically via adb.

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  if [[ -d "${studio_jdk}" ]]; then
    export JAVA_HOME="${studio_jdk}"
    export PATH="${JAVA_HOME}/bin:${PATH}"
  fi
fi

device="${1:-}"
if [[ -z "$device" ]]; then
  device=$(adb devices | grep -v "List of devices" | grep -w "device" | awk '{print $1}' | head -n 1 || true)
fi

read -r yy mm dd hh mn <<<"$(date -u '+%y %m %d %H %M')"
version="${yy}.$((10#$mm)).$((10#$dd))"
build=$((10#$hh * 10 + 10#$mn / 10))

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
