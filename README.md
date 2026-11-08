# RefineID for Android

Native Android support for Finnish identity cards: in-app and system browser
authentication, qualified PDF signing, and contactless NFC operation.

## Requirements

- Android 13+
- USB CCID smart-card reader or NFC
- JDK of the version in `gradle/gradle-daemon-jvm.properties`, Rust
  (aarch64-linux-android and x86_64-linux-android targets), cargo-ndk,
  Android SDK/NDK

## Quick start

```sh
Scripts/bootstrap-macos.sh       # installs toolchains, installs git hooks
Scripts/gradle.sh check          # full quality gates
Scripts/gradle.sh assembleDebug  # debug APK
Scripts/install-device.sh        # build, install and launch on the test phone
```

`Scripts/gradle.sh` runs the Gradle wrapper on the JDK and Rust toolchain the
hooks use, whatever the calling shell exports; see
[`doc/process/build-environment.md`](doc/process/build-environment.md).

Release APK (signed with hardware identity card, PIN 2):

```sh
Scripts/build-release-apk.sh
```

### Windows host

The gates and the hooks run in the bash of Git for Windows; the build starts
the repository's shell scripts under it. Set up by hand what the macOS
bootstrap installs: a JDK of the version `gradle/gradle-daemon-jvm.properties`
names, with `JAVA_HOME` pointing at it, the SDK platform
and the NDK pinned in `app/build.gradle.kts` through `sdkmanager`, the Rust
Android targets with `rustup target add`, `cargo install cargo-ndk`, and
ShellCheck (`winget install koalaman.shellcheck`). Every text file checks out
with LF on every host whatever `core.autocrlf` says, except `gradlew.bat`,
which `cmd.exe` needs in CRLF (`.gitattributes`).

### Managing build cache

During development, Cargo build artifacts (under `native/*/target`) and `rustc` incremental compilation caches can grow significantly.

```sh
# Sweep unused native build artifacts older than 14 days
cargo sweep -t 14 -r native

# Clean native incremental compilation caches if disk space is needed
find native -type d -name "incremental" -prune -exec rm -rf {} +
```

## Wireless debugging

```sh
adb tcpip 5555
adb shell ip -f inet addr show wlan0   # note the phone address
adb connect <phone-address>:5555
```

The TCP listener survives until reboot or a USB-debugging toggle.

## Source hierarchy

| Repository | Role |
|---|---|
| fineid-spec | Protocol behavior specification |
| refineid-core | Reusable Rust implementation |
| refineid-mono-internal | Compatibility and coverage oracle |
| RefineID-Apple | Product-behavior and UX reference |

## AOSP integration

For system-browser support via platform KeyChain, see
[`doc/architecture/0011-browser-authentication-boundary.md`](doc/architecture/0011-browser-authentication-boundary.md)
and the AOSP design in
[`doc/architecture/0012-platform-keychain-external-key.md`](doc/architecture/0012-platform-keychain-external-key.md).

The AOSP patch series, its Pixel 4 build scripts and runbooks, and the
app-side provider the patched KeyChain binds to are parked in
[refineid-hack's `aosp-keychain-external-key/`](https://github.com/refineid/refineid-hack/tree/main/aosp-keychain-external-key).

## Quality gates

`./gradlew check` enforces: Kotlin compiler warnings-as-errors, Android Lint,
Detekt, ktlint, rustfmt, Clippy, ShellCheck, release
bytecode logging prohibition, and no Internet permission in the release manifest.

## Versioning

Calendar versioning `YY.M.D` matching the Apple release. See
[`doc/architecture/0006-calendar-versioning.md`](doc/architecture/0006-calendar-versioning.md)
and the [release process](doc/distribution/release-process.artifact.md).

## Security

Never place a real PIN, CAN, PUK, certificate, card dump, APDU trace, personal
identifier, or device/network identifier in source control, tests, screenshots,
issues, or CI logs.

## License

Apache License, Version 2.0.
