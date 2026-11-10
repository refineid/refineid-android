#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# The full quality floor for the pre-push hook: `./gradlew check` treats
# Kotlin compiler and Android Lint warnings as errors, runs Detekt and
# ktlint, tests and lints the Rust bridge, runs ShellCheck, proves the
# AOSP provider wire contract, and verifies the minimized release APK.

set -euo pipefail
cd "$(dirname "$0")/.."

python3 -B Scripts/TestDocumentationGate.py

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

./gradlew check

if command -v cargo-audit > /dev/null || cargo audit --version > /dev/null 2>&1; then
  (cd native/refineid-android-core && cargo audit)
  (cd native/refineid-rapp-android && cargo audit)
fi

echo "pre-push gates passed"
