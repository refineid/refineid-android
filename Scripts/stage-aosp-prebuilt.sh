#!/usr/bin/env bash
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.

set -euo pipefail
cd "$(dirname "$0")/.."

readonly RELEASE_APK="app/build/outputs/apk/release/app-release-unsigned.apk"
readonly RELEASE_MERGED_MANIFEST="app/build/intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml"
readonly AOSP_PREBUILT_DIRECTORY="aosp-prebuilt"
readonly AOSP_PREBUILT_APK="${AOSP_PREBUILT_DIRECTORY}/RefineID.apk"
readonly APK_SIGNATURE_ENTRY_PATTERN='^META-INF/[^/]+\.(RSA|DSA|EC|SF)$'
readonly PREBUILT_FILE_MODE="0644"
readonly RELEASE_PACKAGE='package="fi.refineid.android"'
readonly PROVIDER_SERVICE='android:name="fi.refineid.android.keychain.ExternalKeyProviderService"'
readonly KEYCHAIN_BIND_PERMISSION='android:permission="com.android.keychain.permission.BIND_EXTERNAL_KEY_PROVIDER"'
readonly PROVIDER_INTERFACE_ACTION='android:name="com.android.keychain.external.IExternalKeyProviderService"'
readonly BACKGROUND_ACTIVITY_PERMISSION='android:name="android.permission.START_ACTIVITIES_FROM_BACKGROUND"'
readonly INTERNET_PERMISSION="android.permission.INTERNET"
readonly CLEARTEXT_DISABLED='android:usesCleartextTraffic="false"'

./gradlew check

[[ -f "$RELEASE_APK" ]] || {
  echo "release APK was not produced" >&2
  exit 1
}
[[ -f "$RELEASE_MERGED_MANIFEST" ]] || {
  echo "release merged manifest was not produced" >&2
  exit 1
}

for required_manifest_entry in \
  "$RELEASE_PACKAGE" \
  "$PROVIDER_SERVICE" \
  "$KEYCHAIN_BIND_PERMISSION" \
  "$PROVIDER_INTERFACE_ACTION" \
  "$BACKGROUND_ACTIVITY_PERMISSION"; do
  grep -Fq "$required_manifest_entry" "$RELEASE_MERGED_MANIFEST" || {
    echo "release manifest is missing a required provider declaration" >&2
    exit 1
  }
done

if grep -Fq "$INTERNET_PERMISSION" "$RELEASE_MERGED_MANIFEST"; then
  echo "release manifest must not request Internet access" >&2
  exit 1
fi
if ! grep -Fq "$CLEARTEXT_DISABLED" "$RELEASE_MERGED_MANIFEST"; then
  echo "release manifest must explicitly disable cleartext traffic" >&2
  exit 1
fi

if unzip -Z1 "$RELEASE_APK" | grep -Eq "$APK_SIGNATURE_ENTRY_PATTERN"; then
  echo "release APK must remain unsigned for AOSP platform signing" >&2
  exit 1
fi

mkdir -p "$AOSP_PREBUILT_DIRECTORY"
install -m "$PREBUILT_FILE_MODE" "$RELEASE_APK" "$AOSP_PREBUILT_APK"
echo "staged unsigned AOSP prebuilt at ${AOSP_PREBUILT_APK}"
