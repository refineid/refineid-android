#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
export LC_ALL=C

readonly EXIT_FAILURE=1
readonly EXIT_USAGE=2
readonly MODE_PREFLIGHT="preflight"
readonly MODE_REPLAY="replay"
readonly REPLAY_ARGUMENT="--replay"
readonly AOSP_TAG="android-13.0.0_r31"
readonly FRAMEWORKS_BASE_UPSTREAM="https://android.googlesource.com/platform/frameworks/base"
readonly KEYCHAIN_UPSTREAM="https://android.googlesource.com/platform/packages/apps/KeyChain"
readonly PIXEL_DEVICE_UPSTREAM="https://android.googlesource.com/device/google/coral"
readonly REFINEID_RELATIVE_PATH="packages/apps/RefineID"
readonly FRAMEWORKS_BASE_RELATIVE_PATH="frameworks/base"
readonly KEYCHAIN_RELATIVE_PATH="packages/apps/KeyChain"
readonly PIXEL_DEVICE_RELATIVE_PATH="device/google/coral"
readonly AUDIT_DIRECTORY_PREFIX="refineid-aosp-audit."

SCRIPT_DIRECTORY="$(cd "$(dirname "$0")" && pwd -P)"
readonly SCRIPT_DIRECTORY
REPOSITORY_ROOT="$(cd "$SCRIPT_DIRECTORY/.." && pwd -P)"
readonly REPOSITORY_ROOT
AUDIT_PARENT="$(cd /tmp && pwd -P)"
readonly AUDIT_PARENT
audit_root=""

fail() {
  echo "$1" >&2
  exit "$EXIT_FAILURE"
}

usage() {
  echo "usage: $0 [$REPLAY_ARGUMENT]" >&2
}

cleanup() {
  local audit_basename
  local audit_parent

  [[ -n "$audit_root" && -d "$audit_root" ]] || return
  audit_parent="$(cd "$(dirname "$audit_root")" && pwd -P)"
  audit_basename="$(basename "$audit_root")"
  if [[ "$audit_parent" == "$AUDIT_PARENT" && "$audit_basename" == "$AUDIT_DIRECTORY_PREFIX"* ]]; then
    rm -rf -- "$audit_root"
  fi
}

clone_sparse_project() {
  local upstream="$1"
  local destination="$2"
  local patch_directory="$3"

  git init --quiet "$destination"
  git -C "$destination" remote add origin "$upstream"
  git -C "$destination" -c protocol.version=2 fetch --quiet --depth=1 \
    --filter=blob:none origin "refs/tags/$AOSP_TAG:refs/tags/$AOSP_TAG"
  git -C "$destination" sparse-checkout init --no-cone
  awk '
    /^\+\+\+ b\// {
      sub(/^\+\+\+ b\//, "")
      print
    }
  ' "$patch_directory"/*.patch |
    sort -u |
    git -C "$destination" sparse-checkout set --stdin
  git -C "$destination" checkout --quiet --detach "refs/tags/$AOSP_TAG^{}"
}

mode="$MODE_PREFLIGHT"
if [[ "$#" -eq 1 && "$1" == "$REPLAY_ARGUMENT" ]]; then
  mode="$MODE_REPLAY"
elif [[ "$#" -ne 0 ]]; then
  usage
  exit "$EXIT_USAGE"
fi

repository_status="$(git -C "$REPOSITORY_ROOT" status --porcelain --untracked-files=normal)"
[[ -z "$repository_status" ]] ||
  fail "AOSP patch audit requires a clean committed RefineID checkout"

audit_root="$(mktemp -d "$AUDIT_PARENT/$AUDIT_DIRECTORY_PREFIX"XXXXXX)"
trap cleanup EXIT

mkdir -p "$audit_root/packages/apps" "$audit_root/frameworks" "$audit_root/device/google"
git clone --quiet --local -- "$REPOSITORY_ROOT" "$audit_root/$REFINEID_RELATIVE_PATH"

audit_platform="$audit_root/$REFINEID_RELATIVE_PATH/platform/aosp/android-13.0.0_r31"
clone_sparse_project "$FRAMEWORKS_BASE_UPSTREAM" "$audit_root/$FRAMEWORKS_BASE_RELATIVE_PATH" \
  "$audit_platform/patches/frameworks-base"
clone_sparse_project "$KEYCHAIN_UPSTREAM" "$audit_root/$KEYCHAIN_RELATIVE_PATH" \
  "$audit_platform/patches/packages-apps-KeyChain"
clone_sparse_project "$PIXEL_DEVICE_UPSTREAM" "$audit_root/$PIXEL_DEVICE_RELATIVE_PATH" \
  "$audit_platform/patches/device-google-coral"

"$audit_root/$REFINEID_RELATIVE_PATH/Scripts/apply-aosp-patches.sh" --check-base "$audit_root"

if [[ "$mode" == "$MODE_REPLAY" ]]; then
  "$audit_root/$REFINEID_RELATIVE_PATH/Scripts/apply-aosp-patches.sh" "$audit_root"
  "$audit_root/$REFINEID_RELATIVE_PATH/Scripts/apply-aosp-patches.sh" \
    --check-applied "$audit_root"
fi

printf 'aosp_patch_audit=%s\n' "$mode"
