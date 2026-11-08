# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# UI automation helpers over adb and uiautomator, sourced by device test
# scripts. Nodes are found by Compose test tags, which the app exposes as
# resource ids (testTagsAsResourceId). Helpers never print node text: a
# screen can hold a pairing code, a holder name or other values that stay
# out of logs. Read a value with ui_text into a variable and use it there.

ui_poll_seconds=1
ui_default_timeout_seconds=20

# The serial of the one connected physical phone reached over Wi-Fi
# debugging (an address:port serial).
ui_wifi_phone() {
  adb devices | awk '$2 == "device" { print $1 }' | grep -E '^[0-9.]+:[0-9]+$' | head -n 1
}

# The serial of the one running emulator.
ui_emulator() {
  adb devices | awk '$2 == "device" { print $1 }' | grep -E '^emulator-[0-9]+$' | head -n 1
}

# The current window hierarchy of device $1, one node per line.
ui_dump() {
  local serial="$1"
  adb -s "${serial}" shell uiautomator dump /sdcard/refineid-ui.xml > /dev/null 2>&1 || return 1
  adb -s "${serial}" exec-out cat /sdcard/refineid-ui.xml | awk '{ gsub(/<node /, "\n<node "); print }'
}

# The node line on device $1 whose attribute $2 equals $3.
ui_node() {
  local serial="$1" attribute="$2" value="$3"
  ui_dump "${serial}" | grep -F "${attribute}=\"${value}\"" | head -n 1
}

# Attribute $2 of node line $1.
ui_attribute() {
  local node="$1" attribute="$2"
  printf '%s\n' "${node}" | grep -oE " ${attribute}=\"[^\"]*\"" | head -n 1 | sed -E "s/^ ${attribute}=\"(.*)\"$/\1/"
}

# Whether device $1 shows a node tagged $2.
ui_has() {
  [[ -n "$(ui_node "$1" resource-id "$2")" ]]
}

# Waits up to $3 seconds (default ui_default_timeout_seconds) for device $1
# to show a node tagged $2.
ui_wait() {
  local serial="$1" tag="$2" timeout="${3:-${ui_default_timeout_seconds}}" waited=0
  until ui_has "${serial}" "${tag}"; do
    if ((waited >= timeout)); then
      echo "timed out waiting for ${tag}" >&2
      return 1
    fi
    sleep "${ui_poll_seconds}"
    waited=$((waited + ui_poll_seconds))
  done
}

# Taps the centre of the node on device $1 whose attribute $2 equals $3.
ui_tap_by() {
  local serial="$1" attribute="$2" value="$3" node bounds
  node="$(ui_node "${serial}" "${attribute}" "${value}")"
  bounds="$(ui_attribute "${node}" bounds)"
  if [[ -z "${bounds}" ]]; then
    echo "no node with ${attribute} ${value}" >&2
    return 1
  fi
  read -r left top right bottom <<< "$(printf '%s\n' "${bounds}" | tr '[],' '   ')"
  adb -s "${serial}" shell input tap $(((left + right) / 2)) $(((top + bottom) / 2))
}

# Taps the node that follows, in document order, the node on device $1 whose
# attribute $2 equals $3: the visible stand-in for an input that uiautomator
# leaves out of its dump, such as a fully transparent field under its label.
ui_tap_next_after() {
  local serial="$1" attribute="$2" value="$3" node bounds
  node="$(ui_dump "${serial}" | grep -F -A 1 "${attribute}=\"${value}\"" | sed -n 2p)"
  bounds="$(ui_attribute "${node}" bounds)"
  if [[ -z "${bounds}" ]]; then
    echo "no node after ${attribute} ${value}" >&2
    return 1
  fi
  read -r left top right bottom <<< "$(printf '%s\n' "${bounds}" | tr '[],' '   ')"
  adb -s "${serial}" shell input tap $(((left + right) / 2)) $(((top + bottom) / 2))
}

# Taps the node on device $1 tagged $2.
ui_tap() {
  ui_tap_by "$1" resource-id "$2"
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

# The test tags device $1 shows, without any node text.
ui_tags() {
  ui_dump "$1" | grep -oE ' resource-id="[^"]+"' | sed -E 's/^ resource-id="(.*)"$/\1/' | grep -v '^android:id/'
}

# Brings RefineID to the front on device $1 at its home screen.
ui_launch_refineid() {
  local serial="$1"
  adb -s "${serial}" shell am force-stop fi.refineid.android
  adb -s "${serial}" shell am start -n fi.refineid.android/.MainActivity > /dev/null
  ui_wait "${serial}" mainScreen
}
