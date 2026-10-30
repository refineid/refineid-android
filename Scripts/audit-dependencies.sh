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

# OWASP Dependency-Check ends in one of these results, printed as the last
# line "dependency-check: <result>":
#   complete            fresh report, no finding at or above the threshold (exit 0)
#   threshold-exceeded  fresh report with a finding at or above the threshold (exit 1)
#   incomplete          no fresh report, or the scanner failed for another reason,
#                       e.g. the vulnerability database could not be updated or
#                       loaded (exit 1)
#   not-installed       the scanner is absent; nothing was analysed (exit 0)
owasp_failing_cvss=7
# The dependency-check CLI exits with 15 when a finding meets --failOnCVSS.
owasp_threshold_exit_status=15
owasp_report_directory=build/reports/dependency-check
owasp_reports=(
  "${owasp_report_directory}/dependency-check-report.html"
  "${owasp_report_directory}/dependency-check-report.json"
)

if ! command -v dependency-check > /dev/null; then
  echo "Notice: dependency-check not found (install via Homebrew: brew install dependency-check)."
  echo "dependency-check: not-installed"
  exit 0
fi

echo "==> Running OWASP Dependency-Check..."
mkdir -p "${owasp_report_directory}"
rm -f "${owasp_reports[@]}"
nvd_args=()
if [[ -n "${NVD_API_KEY:-}" ]]; then
  nvd_args+=(--nvdApiKey "${NVD_API_KEY}")
fi
owasp_status=0
dependency-check \
  --project "refineid-android" \
  --scan app/build/outputs/apk/release \
  --format HTML --format JSON \
  --out "${owasp_report_directory}" \
  --failOnCVSS "${owasp_failing_cvss}" \
  ${nvd_args[@]:+"${nvd_args[@]}"} || owasp_status=$?

owasp_report_fresh=true
for report in "${owasp_reports[@]}"; do
  [[ -s "${report}" ]] || owasp_report_fresh=false
done

if [[ "${owasp_report_fresh}" != true ]] ||
  [[ "${owasp_status}" -ne 0 && "${owasp_status}" -ne "${owasp_threshold_exit_status}" ]]; then
  echo "OWASP Dependency-Check did not complete (exit status ${owasp_status})."
  if [[ -z "${NVD_API_KEY:-}" ]]; then
    echo "Notice: OWASP Dependency-Check requires an NVD API key (export NVD_API_KEY=...) to download NVD data without rate limits."
  fi
  echo "dependency-check: incomplete"
  exit 1
fi

echo "OWASP report generated at ${owasp_reports[0]}"
if [[ "${owasp_status}" -eq "${owasp_threshold_exit_status}" ]]; then
  echo "dependency-check: threshold-exceeded"
  exit 1
fi
echo "dependency-check: complete"
