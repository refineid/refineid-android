#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Bootstrap a macOS development environment for refineid-android using
# Homebrew: JDK, Android SDK command-line tools, the SDK platform and NDK
# pinned by the Gradle build, rustup with the Android cross-compilation
# targets, cargo-ndk, and ShellCheck. Idempotent; safe to re-run.

set -euo pipefail
cd "$(dirname "$0")/.."

sdk_root="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}"
rust_android_targets=(aarch64-linux-android x86_64-linux-android)
brew_formulas=(openjdk rustup shellcheck)
brew_casks=(android-commandlinetools android-platform-tools)

if [[ "$(uname)" != "Darwin" ]]; then
  echo "Error: this script bootstraps macOS only." >&2
  exit 1
fi

if ! command -v brew >/dev/null; then
  echo "Error: Homebrew is required; see https://brew.sh" >&2
  exit 1
fi

# The Homebrew rust formula cannot install Android cross-compilation targets
# and shadows the rustup-managed toolchain on PATH.
if brew list --formula rust >/dev/null 2>&1; then
  echo "Error: the Homebrew 'rust' formula conflicts with rustup." >&2
  echo "Remove it first: brew uninstall rust" >&2
  exit 1
fi

# The Gradle build is the single source of truth for the pinned versions.
ndk_version=$(sed -n 's/^ *ndkVersion = "\(.*\)"$/\1/p' app/build.gradle.kts)
platform_api=$(sed -n 's/^val currentAndroidApi = \([0-9]*\)$/\1/p' app/build.gradle.kts)
if [[ -z "${ndk_version}" || -z "${platform_api}" ]]; then
  echo "Error: could not read ndkVersion or currentAndroidApi from app/build.gradle.kts." >&2
  exit 1
fi

for formula in "${brew_formulas[@]}"; do
  brew list --formula "${formula}" >/dev/null 2>&1 || brew install "${formula}"
done
for cask in "${brew_casks[@]}"; do
  brew list --cask "${cask}" >/dev/null 2>&1 || brew install --cask "${cask}"
done

java_home="$(brew --prefix openjdk)/libexec/openjdk.jdk/Contents/Home"
export JAVA_HOME="${java_home}"

if command -v sdkmanager >/dev/null; then
  sdkmanager=$(command -v sdkmanager)
else
  sdkmanager="$(brew --prefix)/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager"
fi

echo "Accepting Android SDK licenses..."
"${sdkmanager}" --sdk_root="${sdk_root}" --licenses < <(yes) >/dev/null

echo "Installing SDK platform ${platform_api} and NDK ${ndk_version}..."
# Since the Android 16 minor-release scheme the platform package may carry an
# explicit minor version, so fall back to the ".0" name for the same API level.
"${sdkmanager}" --sdk_root="${sdk_root}" "platforms;android-${platform_api}" ||
  "${sdkmanager}" --sdk_root="${sdk_root}" "platforms;android-${platform_api}.0"
"${sdkmanager}" --sdk_root="${sdk_root}" "ndk;${ndk_version}"

if [[ ! -f local.properties ]]; then
  printf 'sdk.dir=%s\n' "${sdk_root}" > local.properties
  echo "Wrote local.properties with sdk.dir=${sdk_root}"
fi

# Homebrew's rustup is keg-only; neither it nor its cargo and rustc
# proxies are linked into the default Homebrew bin directory, so the
# PATH must carry the keg before the first rustup invocation.
rustup_bin="$(brew --prefix rustup)/bin"
export PATH="${rustup_bin}:${HOME}/.cargo/bin:${PATH}"

if ! rustup show active-toolchain >/dev/null 2>&1; then
  rustup toolchain install stable
  rustup default stable
fi
rustup target add "${rust_android_targets[@]}"

command -v cargo-ndk >/dev/null || cargo install cargo-ndk

Scripts/install-hooks.sh

cat <<EOF

Bootstrap complete. Ensure your shell profile exports:

  export JAVA_HOME="${java_home}"
  export ANDROID_SDK_ROOT="${sdk_root}"
  export PATH="${rustup_bin}:\${HOME}/.cargo/bin:\${PATH}"

Then build with: ./gradlew assembleDebug
EOF
