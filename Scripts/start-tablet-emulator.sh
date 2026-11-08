#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Start an Android tablet emulator bridged onto the Mac's local network, so it
# takes the RAPP requester role and discovers a physical custodian phone over mDNS.
#
# Usage:
#
#   Scripts/start-tablet-emulator.sh [<host network interface>]
#
# The interface defaults to the one carrying the Mac's default route. The
# emulator runs under sudo: vmnet bridged mode needs root because the emulator
# binary does not carry the com.apple.vm.networking entitlement.
# See doc/process/tablet-emulator.md.
set -euo pipefail

readonly avd_name="refineid_tablet"
readonly api_level="android-35"
readonly image_tag="google_apis_playstore_tablet"
readonly image_abi="arm64-v8a"
readonly boot_poll_seconds=5
readonly boot_poll_limit=120

sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}}"
avd_home="${ANDROID_AVD_HOME:-${HOME}/.android/avd}"
emulator="${sdk}/emulator/emulator"
adb="${sdk}/platform-tools/adb"
image_dir="system-images/${api_level}/${image_tag}/${image_abi}"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "vmnet bridging is macOS only" >&2
  exit 1
fi
if [[ ! -x "${emulator}" ]]; then
  echo "Android emulator not found under ${sdk}" >&2
  exit 1
fi
if [[ ! -d "${sdk}/${image_dir}" ]]; then
  echo "System image missing: install ${image_dir//\//;} with sdkmanager" >&2
  exit 1
fi

interface="${1:-$(route get default | awk '/interface:/ { print $2 }')}"
if [[ -z "${interface}" ]]; then
  echo "No host network interface given and no default route found" >&2
  exit 1
fi

if [[ ! -f "${avd_home}/${avd_name}.ini" ]]; then
  mkdir -p "${avd_home}/${avd_name}.avd"
  cat > "${avd_home}/${avd_name}.ini" << EOF
avd.ini.encoding=UTF-8
path=${avd_home}/${avd_name}.avd
target=${api_level}
EOF
  cat > "${avd_home}/${avd_name}.avd/config.ini" << EOF
AvdId=${avd_name}
avd.ini.displayname=RefineID Tablet
abi.type=${image_abi}
hw.cpu.arch=arm64
hw.cpu.ncore=4
hw.ramSize=4096
disk.dataPartition.size=8G
image.sysdir.1=${image_dir}/
tag.id=google_apis_playstore
tag.ids=google_apis_playstore,tablet
PlayStore.enabled=true
hw.device.name=pixel_tablet
hw.device.manufacturer=Google
hw.lcd.width=2560
hw.lcd.height=1600
hw.lcd.density=320
hw.initialOrientation=landscape
hw.keyboard=yes
hw.gpu.enabled=yes
hw.gpu.mode=auto
showDeviceFrame=no
EOF
  echo "created AVD ${avd_name}"
fi

log_dir="${TMPDIR:-/tmp}"
log="${log_dir%/}/${avd_name}-emulator.log"

# Netsim's packet-streamed Wi-Fi otherwise owns the virtio Wi-Fi device and
# keeps wlan0 behind user-mode NAT; with it disabled, vmnet backs wlan0.
sudo env \
  HOME="${HOME}" \
  ANDROID_SDK_ROOT="${sdk}" \
  ANDROID_AVD_HOME="${avd_home}" \
  ANDROID_EMULATOR_HOME="${HOME}/.android" \
  "${emulator}" -avd "${avd_name}" \
  -feature -WiFiPacketStream \
  -vmnet-bridged "${interface}" \
  -no-snapshot -no-boot-anim > "${log}" 2>&1 &
emulator_pid=$!

echo "starting ${avd_name} bridged on ${interface}; log: ${log}"
booted=""
for ((attempt = 0; attempt < boot_poll_limit; attempt++)); do
  if ! kill -0 "${emulator_pid}" 2> /dev/null; then
    echo "emulator exited during boot; see ${log}" >&2
    exit 1
  fi
  booted="$("${adb}" -e shell getprop sys.boot_completed 2> /dev/null | tr -d '\r' || true)"
  if [[ "${booted}" == "1" ]]; then
    break
  fi
  sleep "${boot_poll_seconds}"
done
if [[ "${booted}" != "1" ]]; then
  echo "emulator did not finish booting; see ${log}" >&2
  exit 1
fi

# Emulated touches count as stylus input on the tablet image, and the
# keyboard's stylus onboarding would take text that adb types.
"${adb}" -e shell settings put secure stylus_handwriting_enabled 0

host_address="$(ipconfig getifaddr "${interface}" || true)"
guest_address="$("${adb}" -e shell ip -4 -o addr show wlan0 | awk '{ split($4, a, "/"); print a[1] }' | tr -d '\r')"
if [[ -n "${host_address}" && "${guest_address%.*}" == "${host_address%.*}" ]]; then
  echo "${avd_name} booted; wlan0 is on the host's local subnet"
else
  echo "${avd_name} booted, but wlan0 is not on the host's local subnet; see ${log}" >&2
  exit 1
fi
