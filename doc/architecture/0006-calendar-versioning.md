# ADR 0006: Calendar versioning

Status: Accepted

Date: 2026-08-15

## Context

RefineID is one product on Apple and Android. Its releases should carry the
same human-readable version and build pair on both platforms. The Apple policy
uses a `YY.M.D` UTC date and the UTC time of day as an `HHMM` build number.
Apple build numbers may restart when the marketing version changes, while
Android `versionCode` must increase across published versions regardless of
`versionName`, and Google Play caps it at `2,100,000,000`.

## Decision

Android uses the same logical pair as Apple:

- `versionName` is `YY.M.D`, with no zero padding.
- `buildNumber` is the UTC time of day as `HHMM`.

The manifest's integer `versionCode` is `YYMMDD000 + H * 10 + M / 10`: the
date, then the build's UTC ten-minute bucket. Thus `26.8.15 (845)` becomes
`260815084`. The date prefix makes release ordering global, and the encoding
remains below Google Play's limit through 2099. `YYMMDD` followed by the full
`HHMM` would not fit, so the shown build number and the `versionCode` differ
in their last digits.

`version.properties` stores the stamped pair. `Scripts/stamp-version.sh`
updates it explicitly. Builds never derive a version from the live clock, so
rebuilding one source revision is reproducible and ordinary development builds
do not churn tracked files. Only one publishable artifact may be cut in a UTC
ten-minute bucket, since two builds in one bucket share a `versionCode`.

## Consequences

Release records and support reports can use one cross-platform pair. Android
still receives a globally increasing upgrade code. A release cut after a UTC
date or bucket rollover must capture the new pair once and use it for every
artifact from that candidate.

The Android version-code requirements are documented at
<https://developer.android.com/studio/publish/versioning>.
