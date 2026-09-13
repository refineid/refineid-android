# RefineID for Android

Native Android support for Finnish identity cards: in-app and system browser
authentication, qualified PDF signing, and contactless NFC operation.

## Requirements

- Android 13+
- USB CCID smart-card reader or NFC
- JDK, Rust (aarch64-linux-android target), cargo-ndk, Android SDK/NDK

## Quick start

```sh
Scripts/bootstrap-macos.sh   # installs toolchains, sets env, installs git hooks
./gradlew check              # full quality gates
./gradlew assembleDebug      # debug APK
./gradlew installDebug       # deploy to connected device
```

Release APK (signed with hardware identity card, PIN 2):

```sh
Scripts/build-release-apk.sh
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

Build the AOSP image with the pinned Pixel 4
[`BUILD.md`](platform/aosp/android-13.0.0_r31/BUILD.md). To stage the
minimized unsigned release artifact:

```sh
Scripts/stage-aosp-prebuilt.sh
```

## Quality gates

`./gradlew check` enforces: Kotlin compiler warnings-as-errors, Android Lint,
Detekt, ktlint, rustfmt, Clippy, ShellCheck, wire-contract matching, release
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
