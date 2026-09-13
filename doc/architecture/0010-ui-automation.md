# ADR 0010: Native Android UI automation

Status: Accepted

Date: 2026-08-15

## Context

The Android port needs the same kind of user-journey automation that the Apple
application obtains from XCUITest. RefineID also has two distinct UI scopes:
its own Compose hierarchy and flows that cross into Android system UI or a
browser. A single Android framework is not the best tool for both scopes.

Authentication tests must never embed or retrieve a real PIN. An automated
hardware test must not submit a guessed credential or consume a retry. Screen
captures and hierarchy dumps are also unsuitable wherever holder information
or credential input could be visible.

## Decision

Instrumented UI tests run from `app/src/androidTest` under
`AndroidJUnitRunner` and use two Google-provided layers:

- Compose UI Test v2 drives and asserts the app-owned Compose hierarchy. Its
  synchronization with recomposition makes it the default for screen behavior.
- UI Automator 2.4 drives opaque-box, cross-process journeys involving system
  permission UI, browser applications, and other Android-owned windows. It is
  the direct counterpart to the cross-application part of XCUITest.

Product controls carry stable, locale-independent test tags. The root enables
`testTagsAsResourceId`, making the same contract visible through Compose
semantics and the accessibility tree used by UI Automator. Tests do not select
product controls by translated labels.

The suite verifies the secure field semantics, input bounds, one-shot synthetic
submission, field clearing, disabled signing state, permission action,
card-absence behavior, terse browser-action visibility, real application
launch, and accessibility-tree visibility. Device-side tests also exercise the
eight browser JCA algorithms and the fingerprint-pinned issuer set through the
Android runtime. An opt-in hardware journey takes a live card through public
certificate discovery and the diagnostic TLS client-certificate request. It
handles Android's USB permission window when a fresh test installation needs
it, then cancels at the PIN prompt without submitting a credential. The UI
Automator launcher uses a normal explicit Android intent; the app is not
granted network access merely to support a test-only shell launcher.

## Credential and evidence policy

UI tests may use named synthetic PIN-shaped values only with fake callbacks.
They must never read a credential from an environment variable, Gradle
property, file, command line, device clipboard, screenshot, or accessibility
dump. A physical signing run remains holder-driven: automation may bring the
app to the secure field and observe a coarse result, but it does not enter or
submit the credential.

Test artifacts must not contain page text from an authenticated browser,
certificate contents, card or reader identifiers, device identifiers, network
addresses, status words, retry counts, or signature bytes. Release builds keep
the manual authentication surface absent.

## Execution

Run local and instrumented UI checks with:

    ./gradlew check connectedDebugAndroidTest

`connectedDebugAndroidTest` is a physical-device or emulator gate. Browser
integration will extend the UI Automator layer rather than introducing a
third-party driver.

With a supported card and reader already present, run the non-credential live
browser handshake separately:

    ./gradlew connectedDebugAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=fi.refineid.android.ui.LiveBrowserHandshakeUiAutomatorTest \
      -Pandroid.testInstrumentationRunnerArguments.refineidLiveBrowserHandshake=true

The test stops at the secure PIN1 field and dismisses it. It never enters or
submits a credential and therefore must not consume a retry.

To verify the complete leaf-plus-pinned-intermediate identity published to the
platform provider without reaching a PIN prompt, run:

    ./gradlew connectedDebugAndroidTest \
      -Pandroid.testInstrumentationRunnerArguments.class=fi.refineid.android.keychain.LiveExternalKeyIdentityUiAutomatorTest \
      -Pandroid.testInstrumentationRunnerArguments.refineidLiveExternalKeyIdentity=true

This test verifies the public certificate relationship in memory and never
prints or persists either certificate.

The debug-only document harness follows the file-commit ordering used by the
Apple application: select a PDF, select its distinct output destination, and
only then expose PIN2. Compose tests verify those three UI states, secure PIN2
semantics, decimal and length bounds, one synthetic one-shot submission,
immediate field clearing, disabled working state, and terse status text. A
separate device test verifies bounded PDF input ownership and zeroization. No
automated test enters PIN2 into the real card service.
