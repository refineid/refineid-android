# ADR 0011: Browser authentication boundary

Status: Accepted

Date: 2026-08-15

## Context

RefineID ultimately needs Finnish identity-card authentication from the user's
normal Android browser, including services reached through Suomi.fi. An
embedded browser is a useful first consumer of the card stack, but it is not
equivalent to system-wide browser support.

Android exposes two materially different client-certificate seams:

- An app-owned `WebViewClient` receives `ClientCertRequest` and may call
  `proceed` with a `PrivateKey` and certificate chain. The choice is scoped to
  that WebView process and cached for its host and port.
- Independent browser processes normally obtain user-selected aliases through
  Android `KeyChain`. The public API lets an app choose and consume an existing
  alias; it does not let an ordinary app publish a process-external virtual
  private key whose operations are delegated to a USB smart card.

A Java security provider is also process-local. Installing the RefineID
provider in the application therefore cannot change the providers seen by
Chrome, Firefox, or another separately installed browser.

## Decision

The current `WebView` integration is a debug-only diagnostic boundary. It is
allowed to prove the browser-facing key contract while the production release
continues to expose no embedded browser, Internet permission, or diagnostic
logging.

The diagnostic path:

1. accepts navigation and client-certificate requests only for the pinned
   diagnostic HTTPS origin;
2. clears WebView's in-memory client-certificate decision before each run;
3. reads the public authentication certificate from the retained card session;
4. builds only a cryptographically verified leaf-plus-pinned-intermediate
   chain that matches the card key profile and the server's key and issuer
   hints;
5. passes a non-exportable `CardBackedPrivateKey` to `ClientCertRequest`;
6. lets Chromium select one of the exact supported JCA names:
   `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, their three `/PSS`
   counterparts, `SHA256withECDSA`, or `SHA384withECDSA`;
7. prompts for one holder-entered PIN1 submission only when Chromium actually
   requests a signature; and
8. serializes card use, bounds and zeroizes the message, and consumes the PIN
   and signer exactly once.

The system-browser target remains a separate platform integration. The
preferred route is an AOSP/OEM implementation that presents the card identity
as a normal grantable `KeyChain` alias and routes its private-key operations to
an authenticated RefineID card service. That work requires a privileged system
component plus Keystore/KeyChain integration and corresponding Binder, SELinux,
lifecycle, consent, and browser-compatibility tests. A cooperating browser fork
could use the same card service sooner, but would not satisfy the all-browsers
goal.

Copying or importing a private key is not an alternative: the card key is
non-exportable. A credential-management policy can influence alias selection,
but it does not create the missing external-key implementation behind the
alias.

## Verification

- Local provider tests exercise all eight Chromium algorithm names, one-shot
  use, DER conversion, bounded input, and fall-through for ordinary software
  keys.
- Connected Android tests exercise the same eight names through the device's
  real `java.security.Signature` implementation and load all four
  fingerprint-pinned intermediate certificates as currently valid CAs.
- A live USB-card run reached the diagnostic server's client-certificate
  request, supplied the matching identity, and reached the holder PIN prompt.
  The opt-in UI Automator hardware journey repeats this boundary and dismisses
  the prompt without credential entry.

Completion of a holder-driven WebView signature proves the app-owned seam; it
does not prove system-browser integration. Completion of the ultimate goal
requires browser tests from independent processes using the platform-published
identity.

## References

- [Android `ClientCertRequest`](https://developer.android.com/reference/android/webkit/ClientCertRequest)
- [Android `KeyChain`](https://developer.android.com/reference/android/security/KeyChain)
- [Android hardware-backed Keystore architecture](https://source.android.com/docs/security/features/keystore)
- [Chromium Android TLS signature mapping](https://chromium.googlesource.com/chromium/src/+/HEAD/net/ssl/ssl_platform_key_android.cc)
- [Chromium Java private-key bridge](https://chromium.googlesource.com/chromium/src/+/HEAD/net/android/java/src/org/chromium/net/AndroidKeyStore.java)
- [AOSP `KeyChainService`](https://android.googlesource.com/platform/packages/apps/KeyChain/+/master/src/com/android/keychain/KeyChainService.java)
