# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# UI automation helpers over adb and uiautomator, sourced by device test
# scripts. Nodes are found by Compose test tags, which the app exposes as
# resource ids (testTagsAsResourceId). Helpers never print node text: a
# screen can hold a pairing code, a holder name or other values that stay
# out of logs. Read a value with ui_text into a variable and use it there.
# Never run a caller under xtrace (bash -x): it would print those values.

ui_poll_seconds=1
ui_default_timeout_seconds=20
# A cold start right after the emulator boots loads the native library and
# compiles; it has taken longer than the default wait.
ui_launch_timeout_seconds=90
# The deepest screen stack the scripts back out of to reach home.
ui_back_limit=4
ui_device_dump="/sdcard/refineid-ui.xml"

# One adb for every script: the SDK's platform-tools when present, so the
# adb server and its clients stay one version.
ui_sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
if [[ -x "${ui_sdk}/platform-tools/adb" ]]; then
  ui_adb="${ui_sdk}/platform-tools/adb"
else
  ui_adb="adb"
fi

# The serials of connected devices matching extended regex $1; fails unless
# exactly one matches, naming what it looked for ($2).
ui_one_device() {
  local pattern="$1" description="$2" matches count
  matches="$("${ui_adb}" devices | awk '$2 == "device" { print $1 }' | grep -E "${pattern}" || true)"
  count="$(printf '%s' "${matches}" | grep -c . || true)"
  if [[ "${count}" -ne 1 ]]; then
    echo "expected exactly one ${description}, found ${count}" >&2
    return 1
  fi
  printf '%s\n' "${matches}"
}

# The serial of the one physical phone reached over Wi-Fi debugging (an
# address:port serial).
ui_wifi_phone() {
  ui_one_device '^[0-9.]+:[0-9]+$' "phone on Wi-Fi debugging"
}

# The serial of the one running emulator.
ui_emulator() {
  ui_one_device '^emulator-[0-9]+$' "running emulator"
}

# The current window hierarchy of device $1, one node per line. The dump
# file is removed from the device after reading.
ui_dump() {
  local serial="$1"
  "${ui_adb}" -s "${serial}" shell uiautomator dump "${ui_device_dump}" > /dev/null 2>&1 || return 1
  "${ui_adb}" -s "${serial}" exec-out cat "${ui_device_dump}" | awk '{ gsub(/<node /, "\n<node "); print }'
  "${ui_adb}" -s "${serial}" shell rm -f "${ui_device_dump}"
}

# The node line on device $1 whose attribute $2 equals $3.
ui_node() {
  local serial="$1" attribute="$2" value="$3"
  ui_dump "${serial}" | grep -F "${attribute}=\"${value}\"" | head -n 1
}

# Attribute $2 of node line $1.
ui_attribute() {
  local node="$1" attribute="$2"
  printf '%s\n' "${node}" | grep -oE " ${attribute}=\"[^\"]*\"" | head -n 1 | sed -E "s/^ ${attribute}=\"([^\"]*)\"$/\1/"
}

# Whether device $1 shows a node tagged $2.
ui_has() {
  [[ -n "$(ui_node "$1" resource-id "$2")" ]]
}

# Waits up to $3 seconds (default ui_default_timeout_seconds) for device $1
# to show a node tagged $2.
ui_wait() {
  local serial="$1" tag="$2" timeout="${3:-${ui_default_timeout_seconds}}" deadline
  deadline=$((SECONDS + timeout))
  until ui_has "${serial}" "${tag}"; do
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${tag}" >&2
      return 1
    fi
    sleep "${ui_poll_seconds}"
  done
}

# Taps on device $1 the centre of node line $2.
ui_tap_node() {
  local serial="$1" node="$2" bounds left top right bottom
  bounds="$(ui_attribute "${node}" bounds)"
  if [[ ! "${bounds}" =~ ^\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]$ ]]; then
    echo "node has no usable bounds" >&2
    return 1
  fi
  left="${BASH_REMATCH[1]}"
  top="${BASH_REMATCH[2]}"
  right="${BASH_REMATCH[3]}"
  bottom="${BASH_REMATCH[4]}"
  "${ui_adb}" -s "${serial}" shell input tap $(((left + right) / 2)) $(((top + bottom) / 2))
}

# Taps the node on device $1 tagged $2.
ui_tap() {
  local node
  node="$(ui_node "$1" resource-id "$2")"
  if [[ -z "${node}" ]]; then
    echo "no node tagged $2" >&2
    return 1
  fi
  ui_tap_node "$1" "${node}"
}

# Types text $2 on device $1 into the focused field. Callers pass secrets
# here from a variable; nothing is printed.
ui_type() {
  "${ui_adb}" -s "$1" shell input text "$2"
}

# The text of the node on device $1 tagged $2. Keep it in a variable; never
# echo it.
ui_text() {
  ui_attribute "$(ui_node "$1" resource-id "$2")" text
}

# The checked state ("true" or "false") of the node on device $1 tagged $2.
ui_checked() {
  ui_attribute "$(ui_node "$1" resource-id "$2")" checked
}

# The test tags device $1 shows, without any node text. A screen without
# tags, or a dump that fails, gives none rather than an error.
ui_tags() {
  { ui_dump "$1" || true; } | grep -oE ' resource-id="[^"]+"' | sed -E 's/^ resource-id="([^"]*)"$/\1/' | grep -v '^android:id/' || true
}

# Brings RefineID to the front on device $1 at its home screen.
ui_launch_refineid() {
  local serial="$1"
  "${ui_adb}" -s "${serial}" shell am force-stop fi.refineid.android
  "${ui_adb}" -s "${serial}" shell am start -n fi.refineid.android/.MainActivity > /dev/null
  ui_wait "${serial}" mainScreen "${ui_launch_timeout_seconds}"
}

# Brings RefineID to the front on device $1 without restarting it, and
# backs out to its home screen. A custodian keeps its RAPP listener and
# port: a restart registers a new port under the same mDNS name, and a
# requester's mDNS cache keeps dialling the old one until it expires.
ui_open_refineid() {
  local serial="$1" attempt
  "${ui_adb}" -s "${serial}" shell am start -n fi.refineid.android/.MainActivity > /dev/null 2>&1
  for ((attempt = 0; attempt < ui_back_limit; attempt++)); do
    if ui_has "${serial}" mainScreen; then
      return 0
    fi
    "${ui_adb}" -s "${serial}" shell input keyevent KEYCODE_BACK
    sleep "${ui_poll_seconds}"
  done
  ui_wait "${serial}" mainScreen "${ui_launch_timeout_seconds}"
}

# Sets the switch on device $1 tagged $2 to state $3 ("true" or "false")
# and waits until it shows that state.
ui_set_switch() {
  local serial="$1" tag="$2" wanted="$3" deadline
  if [[ "$(ui_checked "${serial}" "${tag}")" != "${wanted}" ]]; then
    ui_tap "${serial}" "${tag}"
  fi
  deadline=$((SECONDS + ui_default_timeout_seconds))
  until [[ "$(ui_checked "${serial}" "${tag}")" == "${wanted}" ]]; do
    if ((SECONDS >= deadline)); then
      echo "${tag} did not turn ${wanted}" >&2
      return 1
    fi
    sleep "${ui_poll_seconds}"
  done
}
