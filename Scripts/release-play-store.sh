#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

# Ensure the current branch is main.
branch=$(git rev-parse --abbrev-ref HEAD)
if [[ "${branch}" != "main" ]]; then
  echo "Error: Release must be performed from the 'main' branch." >&2
  exit 1
fi

# Prevent uncommitted changes from being released accidentally.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: Working directory is not clean. Commit or stash changes first." >&2
  exit 1
fi

echo "Stamping version..."
./Scripts/stamp-version.sh

echo "Running compliance checks..."
./gradlew check

echo "Publishing release bundle to Play Store internal track..."
./gradlew publishReleaseBundle --track internal

echo "Release process completed successfully."
