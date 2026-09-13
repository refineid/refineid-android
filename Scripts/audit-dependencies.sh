#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
#
# Deep dependency vulnerability audit script for RefineID Android.
# Audits Rust native crates (cargo-audit and osv-scanner) and Android / Gradle
# release artifacts (OWASP dependency-check).

set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck source=Scripts/gradle-environment.sh
source Scripts/gradle-environment.sh

echo "==> Auditing Rust crates with cargo audit..."
(cd native/refineid-android-core && cargo audit)
(cd native/refineid-rapp-android && cargo audit)

if command -v osv-scanner > /dev/null; then
  echo "==> Auditing lockfiles with osv-scanner..."
  osv-scanner -r native/
fi

if command -v dependency-check > /dev/null; then
  echo "==> Running OWASP Dependency-Check..."
  mkdir -p build/reports/dependency-check
  nvd_args=()
  if [[ -n "${NVD_API_KEY:-}" ]]; then
    nvd_args+=(--nvdApiKey "${NVD_API_KEY}")
  fi
  dependency-check \
    --project "refineid-android" \
    --scan app/build/outputs/apk/release \
    --format HTML --format JSON \
    --out build/reports/dependency-check \
    --failOnCVSS 7 \
    "${nvd_args[@]}" || true
  if [[ -f build/reports/dependency-check/dependency-check-report.html ]]; then
    echo "OWASP report generated at build/reports/dependency-check/dependency-check-report.html"
  else
    echo "Notice: OWASP Dependency-Check requires an NVD API key (export NVD_API_KEY=...) to download NVD data without rate limits."
  fi
else
  echo "Notice: dependency-check not found (install via Homebrew: brew install dependency-check)."
fi
