#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
# Runs the Gradle wrapper from the repository root on the JDK and Rust
# toolchain the hooks use (Scripts/gradle-environment.sh).

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh
exec ./gradlew "$@"
