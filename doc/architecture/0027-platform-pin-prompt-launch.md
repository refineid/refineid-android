# ADR 0027: Platform PIN prompt launch

## Status

Accepted.

## Context

The framework JCA signature call is synchronous and originates in a browser
crypto worker. KeyChain proxies it to RefineID's bound provider service, which
must ask the holder for a fresh PIN1 before touching the card. At that point
RefineID can have no visible activity. Android 10 and newer restrict activity
launches from background processes, so a plain `startActivity` may suppress
the prompt and leave the TLS operation waiting until timeout.

The pinned Android 13 framework provides the hidden
`android.permission.START_ACTIVITIES_FROM_BACKGROUND` permission for this
class of privileged system integration. The AOSP product signs RefineID with
the same platform certificate that signs the framework and KeyChain.

## Decision

The platform application declares
`android.permission.START_ACTIVITIES_FROM_BACKGROUND`. The ordinary debug APK
does not acquire that signature permission; it becomes effective only when the
AOSP image signs the product APK with its build-local platform key.

The permission is used only by `ExternalKeyPinPromptBroker` to start
`ExternalKeyPinActivity` for one already authenticated KeyChain request. The
activity is an exact in-package component, is not exported, is excluded from
recents, hides overlays, rejects obscured touches, disables screenshots,
autofill, and content capture, and closes on cancellation, timeout, caller
death, or loss of foreground. The prompt shows the KeyChain-derived caller
label and never accepts a browser-supplied origin or identity claim.

No generic activity-launch Binder method is exposed. The external provider
service remains protected by the dedicated signature permission and static
component, privilege, UID, and signing-certificate checks in KeyChain.

## Verification

The manifest instrumentation test proves the provider permission, private
prompt activity, recents exclusion, overlay protection permission, and
background-launch declaration. The AOSP staging script rejects a release APK
whose merged manifest omits the declaration. Existing broker, cancellation,
Binder-death, secure-field, and UI tests exercise prompt ownership without a
real credential.

The final platform image test must additionally prove that an independent
browser signature request raises the prompt while RefineID has no foreground
activity. That observation cannot be made on the stock image because the debug
APK is not platform-signed.

## Consequences

The Android 13 image has an explicit, auditable route for the holder prompt
instead of relying on a background-launch exemption that may not propagate
through browser, KeyChain, and provider processes. The permission is broad at
the framework level, so its narrow in-app use and unexported target remain
security invariants.
