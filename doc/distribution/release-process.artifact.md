# Release Process

Status: Active

Date: 2026-08-22

## Context

The RefineID Android app is distributed through the Google Play Store and as a
direct download (APK) from the official website. This document outlines the
automated workflows for both paths.

## Automation

### Play Store Distribution
The `com.github.triplet.play` plugin manages the communication with the Google
Play Developer API. It is configured in the `:app` module to:

1. Use a service account for authentication, loaded from `play.properties`.
2. Default to the `internal` test track for new uploads.
3. Build and upload Android App Bundles (AAB).

Run the release script:
```bash
./Scripts/release-play-store.sh
```

### Direct Website Distribution
For users who prefer not to use the Play Store or to bypass verification waits,
a Universal APK is provided. This APK contains native libraries for all
supported architectures (`arm64-v8a` and `x86_64`) and is signed with the
developer's hardware identity card (PIN 2). The build script produces
`app/build/outputs/apk/release/refineid-${versionName}.${buildNumber}.apk`
(e.g., `refineid-26.8.22.165.apk`).

Run the APK build script:
```bash
./Scripts/build-release-apk.sh
```

## Security and Compliance

Both distribution paths share a mandatory verification sequence:

- **Branch Validation**: Requires the `main` branch.
- **State Validation**: Requires a clean git working directory.
- **Versioning**: Calls `Scripts/stamp-version.sh` to update `versionName` and
  `versionCode` based on the current UTC time.
- **Compliance**: Runs `./gradlew check` to verify:
    - Lint and Detekt style/correctness.
    - Rust Clippy for native core logic.
    - Security constraints (no logging, no cleartext traffic, restricted internet).

## Configuration

Credentials and local paths are kept in properties files at the repository root,
which are excluded from version control:

- `keystore.properties`: Signing keys for production builds.
- `play.properties`: Google Play service account credentials.

Templates are provided as `*.properties.example`.
