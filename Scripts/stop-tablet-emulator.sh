#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Stop the bridged tablet emulator started by Scripts/start-tablet-emulator.sh
# and return the files it wrote as root under ~/.android to the user.
#
# Usage:
#
#   Scripts/stop-tablet-emulator.sh
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=Scripts/adb-ui.sh
source Scripts/adb-ui.sh

readonly exit_wait_seconds=30

android_home="${ANDROID_EMULATOR_HOME:-${HOME}/.android}"

if serial="$(ui_emulator 2> /dev/null)"; then
  "${ui_adb}" -s "${serial}" emu kill > /dev/null
  deadline=$((SECONDS + exit_wait_seconds))
  while pgrep -q qemu-system && ((SECONDS < deadline)); do
    sleep "${ui_poll_seconds}"
  done
fi

sudo chown -R "$(id -un):$(id -gn)" "${android_home}"
echo "tablet emulator stopped; ${android_home} owned by $(id -un)"
