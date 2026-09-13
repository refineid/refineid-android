#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

# End-to-end automated pairing test between RefineID Mac and connected Android device.
#
# Drives the complete pairing ceremony:
# 1. Resets stale pairing state on both Mac and Android.
# 2. Starts RefineID on Mac in pairing offer mode (--offer-remote-reader).
# 3. Extracts the 6-digit numeric pairing code from Mac.
# 4. Injects the pairing code into Android via ADB intent (REFINEID_PAIR_OFFER).
# 5. Monitors the mutual Noise handshake, Hello exchange, and Confirmation over mDNS.
# 6. Asserts successful pairing completion on both Mac and Android.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAC_APP="/Applications/RefineID.app/Contents/MacOS/RefineID"
MAC_LOG="$(mktemp /tmp/refineid_e2e_mac_XXXXXX.log)"
SERIAL="${ANDROID_SERIAL:-}"

if [[ -z "$SERIAL" ]]; then
  SERIAL=$(adb devices | grep -v "List of devices" | grep -w "device" | awk '{print $1}' | head -n 1 || true)
fi

if [[ -z "$SERIAL" ]]; then
  echo "Error: No connected Android device found." >&2
  exit 1
fi

if [[ ! -x "$MAC_APP" ]]; then
  echo "Error: RefineID not found at $MAC_APP. Run Scripts/install-macos.sh first." >&2
  exit 1
fi

cleanup() {
  if [[ -n "${MAC_PID:-}" ]] && kill -0 "$MAC_PID" 2>/dev/null; then
    kill "$MAC_PID" 2>/dev/null || true
  fi
  rm -f "$MAC_LOG"
}
trap cleanup EXIT

echo "============================================================"
echo " Starting Automated RAPP Pairing Test: Mac <-> Android ($SERIAL)"
echo "============================================================"

# Step 1: Clean slate
echo "==> Step 1: Clearing stale pairing state on Mac and Android..."
"$MAC_APP" --reset-card-state >/dev/null 2>&1 || true

adb -s "$SERIAL" shell run-as fi.refineid.android rm -f \
  /data/data/fi.refineid.android/shared_prefs/fi.refineid.rapp.pairs.xml \
  /data/data/fi.refineid.android/shared_prefs/fi.refineid.rapp.vault.pairs.xml \
  /data/data/fi.refineid.android/shared_prefs/fi.refineid.rapp.vault.revoked.xml || true

adb -s "$SERIAL" shell am force-stop fi.refineid.android
adb -s "$SERIAL" shell am start -n fi.refineid.android/.MainActivity >/dev/null 2>&1
sleep 1

# Step 2: Start Mac in offer mode
echo "==> Step 2: Generating pairing offer on Mac..."
"$MAC_APP" --offer-remote-reader > "$MAC_LOG" 2>&1 &
MAC_PID=$!

CODE=""
for i in $(seq 1 30); do
  if grep -q "offer-remote-reader: offer " "$MAC_LOG" 2>/dev/null; then
    CODE=$(grep "offer-remote-reader: offer " "$MAC_LOG" | head -n 1 | awk '{print $3}')
    break
  fi
  sleep 0.3
done

if [[ -z "$CODE" ]]; then
  echo "Error: Failed to obtain pairing code from Mac." >&2
  cat "$MAC_LOG"
  exit 1
fi

echo "==> Step 3: Pairing code generated on Mac: $CODE"
RENDEZVOUS=$(grep "host browsing for name:" "$MAC_LOG" | head -n 1 | awk '{print $NF}' || true)
echo "    Mac mDNS rendezvous name: ${RENDEZVOUS:-unknown}"

# Step 4: Submit pairing code to Android
echo "==> Step 4: Injecting pairing code into Android via ADB..."
adb -s "$SERIAL" shell am start -n fi.refineid.android/.MainActivity --es REFINEID_PAIR_OFFER "$CODE" >/dev/null 2>&1

# Step 5: Wait for pairing completion on Mac
echo "==> Step 5: Waiting for mutual Noise handshake and confirmation..."
PAIRED="no"
for i in $(seq 1 40); do
  if grep -qE "offer-remote-reader: paired" "$MAC_LOG" 2>/dev/null; then
    PAIRED="yes"
    break
  fi
  if grep -q "offer-remote-reader: no peer took the offer" "$MAC_LOG" 2>/dev/null; then
    break
  fi
  sleep 0.5
done

if [[ "$PAIRED" != "yes" ]]; then
  echo "Error: Pairing failed or timed out on Mac." >&2
  echo "--- Mac Log ---"
  cat "$MAC_LOG"
  echo "--- Android logcat ---"
  adb -s "$SERIAL" logcat -d | grep -iE "rapp|stream" | tail -n 40
  exit 1
fi

echo "==> Step 6: Pairing reported SUCCESS by Mac!"
grep -E "offer-remote-reader: paired" "$MAC_LOG" || true
grep -E "offer-remote-reader: pairings held:" "$MAC_LOG" || true

# Step 7: Verify pairing on Android
echo "==> Step 7: Verifying pair persistence on Android..."
sleep 1
PAIRS_XML=$(adb -s "$SERIAL" shell run-as fi.refineid.android cat /data/data/fi.refineid.android/shared_prefs/fi.refineid.rapp.pairs.xml || true)

if echo "$PAIRS_XML" | grep -q "pairIdHex"; then
  echo "    Android successfully saved paired peer record:"
  echo "$PAIRS_XML"
else
  echo "Error: Android pair record not found in shared_prefs." >&2
  exit 1
fi

echo "============================================================"
echo " SUCCESS: End-to-end pairing test PASSED!"
echo "============================================================"
exit 0
