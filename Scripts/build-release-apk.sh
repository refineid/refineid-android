#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
cd "$(dirname "$0")/.."

# Set JAVA_HOME if not already set, preferring the Android Studio bundled JDK on macOS.
if [[ -z "${JAVA_HOME:-}" ]] && [[ "$(uname)" == "Darwin" ]]; then
  studio_jdk="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
  if [[ -d "${studio_jdk}" ]]; then
    export JAVA_HOME="${studio_jdk}"
  fi
fi

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

version_name=$(grep '^versionName=' version.properties | cut -d= -f2 | tr -d '[:space:]')
build_number=$(grep '^buildNumber=' version.properties | cut -d= -f2 | tr -d '[:space:]')
release_apk="app/build/outputs/apk/release/refineid-${version_name}.${build_number}.apk"

echo "Building production APK for website distribution..."
./gradlew app:assembleRelease

if [[ -f "app/build/outputs/apk/release/app-release-unsigned.apk" ]] && [[ ! -f "app/build/outputs/apk/release/app-release.apk" ]]; then
  echo "Signing release APK with hardware identity card (PIN 2)..."
  pkcs11_lib="/usr/local/lib/librefineid_pkcs11_sign.dylib"
  if [[ ! -f "${pkcs11_lib}" ]]; then
    echo "Error: Required PKCS#11 bridge not found at ${pkcs11_lib}" >&2
    exit 1
  fi

  sdk_dir="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
  apksigner_jar=$(find "${sdk_dir}/build-tools" -name apksigner.jar 2>/dev/null | sort -V | tail -n 1)
  if [[ -z "${apksigner_jar}" || ! -f "${apksigner_jar}" ]]; then
    echo "Error: apksigner.jar not found in Android SDK" >&2
    exit 1
  fi

  pkcs11_cfg=$(mktemp)
  trap 'rm -f "${pkcs11_cfg}"' EXIT
  cat << EOF > "${pkcs11_cfg}"
name = RefineIDSign
library = ${pkcs11_lib}
slotListIndex = 0
EOF

  "${JAVA_HOME}/bin/java" \
    --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
    --add-opens=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED \
    -jar "${apksigner_jar}" sign \
    --provider-class sun.security.pkcs11.SunPKCS11 \
    --provider-arg "${pkcs11_cfg}" \
    --ks NONE \
    --ks-type PKCS11 \
    --ks-pass pass: \
    --in app/build/outputs/apk/release/app-release-unsigned.apk \
    --out "${release_apk}"

  echo "Verifying signed release APK..."
  "${JAVA_HOME}/bin/java" \
    -jar "${apksigner_jar}" verify \
    "${release_apk}"
elif [[ -f "app/build/outputs/apk/release/app-release.apk" ]]; then
  mv -f "app/build/outputs/apk/release/app-release.apk" "${release_apk}"
fi

echo "Release APK generated successfully."
echo "Location: ${release_apk}"
