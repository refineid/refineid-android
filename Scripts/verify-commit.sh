#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Fast quality gates for the pre-commit hook: Kotlin formatting and static
# analysis, Rust formatting, shell lint, and Android Lint. The full floor --
# warnings-as-errors compilation, tests, Clippy, and release-artifact checks --
# runs in the pre-push gate via `./gradlew check`.

set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

whatsup_files=$(git ls-files | grep -i -E '(^|/)WHATSUP\.md$' || true)
if [[ -n "$whatsup_files" ]]; then
  echo "WHATSUP.md files are forbidden:"
  printf '%s\n' "$whatsup_files"
  exit 1
fi

./gradlew --quiet spotlessCheck detekt :app:detekt rustFormatCheck shellCheck lintDebug
echo "pre-commit gates passed"
