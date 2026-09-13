# ADR 0006: Calendar versioning

Status: Accepted

Date: 2026-08-15

## Context

RefineID is one product on Apple and Android. Its releases should carry the
same human-readable version and build pair on both platforms. The Apple policy
uses a `YY.M.D` UTC date and a ten-minute UTC build bucket. Apple build numbers
may restart when the marketing version changes, while Android `versionCode`
must increase across published versions regardless of `versionName`.

## Decision

Android uses the same logical pair as Apple:

- `versionName` is `YY.M.D`, with no zero padding.
- `buildNumber` is `H * 10 + M / 10` in UTC.

The manifest's integer `versionCode` is `YYMMDD000 + buildNumber`. Thus
`26.8.15 (84)` becomes `260815084`. The date prefix makes release ordering
global and the final three digits preserve the shared Apple build number. The
encoding remains below Google Play's `2,100,000,000` limit through 2099.

`version.properties` stores the stamped pair. `Scripts/stamp-version.sh`
updates it explicitly. Builds never derive a version from the live clock, so
rebuilding one source revision is reproducible and ordinary development builds
do not churn tracked files. Only one publishable artifact may be cut in a UTC
ten-minute bucket.

## Consequences

Release records and support reports can use one cross-platform pair. Android
still receives a globally increasing upgrade code. A release cut after a UTC
date or bucket rollover must capture the new pair once and use it for every
artifact from that candidate.

The Android version-code requirements are documented at
<https://developer.android.com/studio/publish/versioning>.
