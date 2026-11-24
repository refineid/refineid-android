#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# Build, install, and launch the latest diagnostic debug build on one connected Android device.
#
# The calendar version and HHMM build number are dynamically passed as command-line
# Gradle overrides, matching RefineID-Apple's install-ios-development.sh.
#
# Builds the debug APK with Gradle (`:app:assembleDebug`) and installs it ONLY
# to the single selected device via `adb -s`, avoiding `./gradlew installDebug`
# (whose Gradle daemon can ignore `ANDROID_SERIAL` and install onto every
# connected device).
#
# Usage:
#
#   Scripts/install-device.sh [--serial <serial> | <adb device serial or IP:port>]
#
# If no device argument is provided and `ANDROID_SERIAL` is unset, prefers a
# single online device reached over Wi-Fi debugging (`ip:port`, `[ipv6]:port`,
# or mDNS wireless debugging) when no emulator ambiguity exists, or falls back
# to a single attached online device, refusing to guess if ambiguous.

set -euo pipefail
cd "$(dirname "$0")/.."

readonly app_apk="app/build/outputs/apk/debug/app-debug.apk"
readonly launch_activity="fi.refineid.android/.MainActivity"
readonly wifi_serial_pattern='^([0-9.]+:[0-9]+|\[[0-9a-fA-F:]+\]:[0-9]+|adb-[A-Za-z0-9_-]+\._adb-tls-connect\._tcp\.?)$'

usage() {
  echo "usage: Scripts/install-device.sh [--serial <serial> | <adb device serial or IP:port>]" >&2
  exit 2
}

resolve_adb() {
  if [[ -n "${REFINEID_ADB:-}" ]]; then
    printf '%s\n' "${REFINEID_ADB}"
    return 0
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
  if [[ -x "${sdk}/platform-tools/adb" ]]; then
    printf '%s\n' "${sdk}/platform-tools/adb"
  else
    printf '%s\n' "adb"
  fi
}

install_apk() {
  local adb_bin="$1" serial="$2" apk="$3"
  local output clean rc reason
  if [[ ! -f "${apk}" ]]; then
    echo "APK not found: ${apk}" >&2
    return 1
  fi
  if output="$("${adb_bin}" -s "${serial}" install -r "${apk}" 2>&1)"; then
    rc=0
  else
    rc=$?
  fi
  clean="$(printf '%s\n' "${output}" | tr -d '\r')"
  if [[ "${rc}" -ne 0 ]] \
    || grep -Eq '(^|[[:space:]])Failure([[:space:]]|\[|$)' <<< "${clean}" \
    || ! grep -Eq '^Success$' <<< "${clean}"; then
    reason="$(printf '%s\n' "${clean}" | sed -nE 's/.*Failure[[:space:]]+\[([A-Z0-9_]+)\].*/\1/p' | head -n 1 || true)"
    if [[ -n "${reason}" ]]; then
      echo "failed to install ${apk} on target device (${reason})" >&2
    else
      echo "failed to install ${apk} on target device" >&2
    fi
    return 1
  fi
}

device=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial | -s)
      [[ $# -ge 2 && -n "$2" && -z "${device}" ]] || usage
      device="$2"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    -*)
      echo "unknown argument: $1" >&2
      usage
      ;;
    *)
      [[ -n "$1" && -z "${device}" ]] || usage
      device="$1"
      shift
      ;;
  esac
done

adb_bin="$(resolve_adb)"
adb_devices_out="$("${adb_bin}" devices)"
attached="$(printf '%s\n' "${adb_devices_out}" | awk 'NR > 1 && NF >= 2 { print $1 }' || true)"
connected="$(printf '%s\n' "${adb_devices_out}" | awk 'NR > 1 && $2 == "device" { print $1 }' || true)"

if [[ -z "${device}" && -n "${ANDROID_SERIAL:-}" ]]; then
  device="${ANDROID_SERIAL}"
fi

# Without an explicit serial, a device reached over Wi-Fi is preferred to one
# on the cable (doc/process/test-devices.md): the phone's USB-C port carries the
# card reader whenever a reader is under test, so the cable comes and goes.
# Refuses when multiple Wi-Fi devices are online, or when fallback sees more
# than one attached entry (including offline/unauthorized devices).
if [[ -z "${device}" ]]; then
  wifi_devices="$(printf '%s\n' "${connected}" | grep -E "${wifi_serial_pattern}" || true)"
  wifi_count="$(printf '%s' "${wifi_devices}" | grep -c . || true)"
  if [[ "${wifi_count}" -eq 1 ]]; then
    device="${wifi_devices}"
  elif [[ "${wifi_count}" -gt 1 ]]; then
    echo "multiple Wi-Fi Android devices connected (${wifi_count}); pass --serial <serial>" >&2
    exit 1
  else
    attached_count="$(printf '%s' "${attached}" | grep -c . || true)"
    online_count="$(printf '%s' "${connected}" | grep -c . || true)"
    if [[ "${attached_count}" -eq 0 ]]; then
      echo "no connected Android device found" >&2
      exit 1
    fi
    if [[ "${attached_count}" -gt 1 ]]; then
      echo "multiple Android devices attached (${attached_count}); pass --serial <serial>" >&2
      exit 1
    fi
    if [[ "${online_count}" -ne 1 ]]; then
      echo "target device is not online in 'adb devices'" >&2
      exit 1
    fi
    device="${connected}"
  fi
elif ! printf '%s\n' "${connected}" | grep -Fxq "${device}"; then
  echo "target device is not online in 'adb devices'" >&2
  exit 1
fi

read -r yy mm dd hh mn <<< "$(date -u '+%y %m %d %H %M')"
version="${yy}.$((10#$mm)).$((10#$dd))"
build=$((10#$hh * 100 + 10#$mn))

echo "building RefineID ${version} (${build})..."
if [[ -n "${REFINEID_INSTALL_GRADLE:-}" ]]; then
  "${REFINEID_INSTALL_GRADLE}" :app:assembleDebug -PversionName="${version}" -PbuildNumber="${build}"
else
  # shellcheck source=Scripts/gradle-environment.sh
  source Scripts/gradle-environment.sh
  ./gradlew :app:assembleDebug -PversionName="${version}" -PbuildNumber="${build}"
fi

install_apk "${adb_bin}" "${device}" "${app_apk}"
if am_start_out="$("${adb_bin}" -s "${device}" shell am start -n "${launch_activity}" 2>&1)"; then
  am_start_rc=0
else
  am_start_rc=$?
fi
if [[ "${am_start_rc}" -ne 0 ]] || grep -Eq '(^|[[:space:]])Error:' <<< "${am_start_out}"; then
  echo "failed to launch RefineID on target device" >&2
  exit 1
fi

echo "installed and launched RefineID ${version} (${build})"
