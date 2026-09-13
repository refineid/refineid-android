# Android smart-card support across versions

Date: 2026-08-17

What Android offers smart-card work today, what Android 14 through 16
changed, and what that means for this repository. Claims cite what the
source proves; absences were searched for, not assumed.

## What an application can reach

An ordinary application gets raw transports and nothing above them:

- USB host I/O for CCID readers. There is no platform PC/SC service;
  every reader stack on Android is application-private, as this
  repository's `usb.ccid` boundary is.
- NFC reader mode with ISO-DEP (`IsoDep`) APDU exchange, also
  application-private, as the `nfc` boundary is.
- OMAPI (`android.se.omapi`, API 28+) reaches secure elements whose
  readers are named `SIM`, `eSE`, or `SD`. Android 13 added a
  vendor-stable OMAPI service for HAL modules. OMAPI never covers USB
  or NFC card readers and never feeds any TLS stack.
  <https://source.android.com/docs/security/features/open-mobile-api>

## Where browsers get client-certificate keys

Both major Android browsers terminate client-certificate authentication
in the platform KeyChain:

- Chromium prompts through `KeyChain.choosePrivateKeyAlias`.
- Firefox (GeckoView) exposes a client-certificate event whose
  resolution is an alias from the same KeyChain API.
  <https://bugzilla.mozilla.org/show_bug.cgi?id=1813930>

KeyChain serves keys that exist in Android Keystore (KeyMint): either
hardware-bound or imported as raw key material. A smart-card private
key can be neither, and stock KeyChain has no service-provider
interface an application could implement. That absence is the entire
reason for this repository's AOSP patch series.

Google has shipped the missing hook twice on its other platforms:

- macOS/iOS CryptoTokenKit: third-party persistent token extensions
  serve certificates and signing system-wide, Safari included; iOS 26
  added a built-in NFC smart-card slot. RefineID-Apple ships on it.
- ChromeOS `chrome.certificateProvider`: middleware extensions inject
  certificates and proxy TLS-handshake signing to a smart card over a
  PC/SC connector application.
  <https://developer.chrome.com/docs/extensions/reference/api/certificateProvider>

No equivalent exists on Android, and no upstream AOSP change or public
proposal adding one was found. The external-key-provider patch series
here occupies genuinely unclaimed ground. For an in-depth analysis of
why `.p12` fast-swapping, Web NFC, and browser extensions cannot circumvent
this, see `client-certificate-delegation-and-web-limitations.md`.

## Android 14, 15, and 16

Nothing in these releases changes the picture for reader-side smart
cards:

- Android 16 added `KeyStoreManager.grantKeyAccess`, which grants
  another application's UID access to a key the caller owns *inside
  Android Keystore*. It shares KeyMint-resident keys; it is not a
  delegated-signing hook and cannot represent an on-card key.
  <https://developer.android.com/reference/android/security/keystore/KeyStoreManager>
- Android 15's NFC additions — observe mode, polling-loop frames and
  filters — serve card *emulation* (payments), not reading.
  <https://android-developers.googleblog.com/2024/03/the-second-developer-preview-of-android-15.html>
- Android 16 routes NDEF web URIs through `ACTION_VIEW`, adds a
  first-scan allowlist prompt, and has field reports of
  `setReaderMode` lifecycle regressions. None of this affects
  foreground reader mode as used here, but the regression reports are
  a watch item before targeting 16.
  <https://github.com/nfcim/flutter_nfc_kit/issues/222>

Porting this repository's platform work forward therefore means
rebasing the KeyChain patch series onto a newer release and moving to
hardware that release supports; the concept carries, the hook still
has to be added by us.

## The wallet horizon

The web-facing successor to certificate login is arriving as wallet
presentation, not smart-card TLS:

- Chrome 141 shipped the W3C Digital Credentials API as stable
  (OpenID4VP and ISO 18013-7), backed on Android by Credential
  Manager — which *does* have a third-party provider service model.
  <https://developer.chrome.com/blog/digital-credentials-api-shipped>
- eIDAS 2 obliges every member state to offer an EUDI wallet; DVV
  builds Finland's. The wallet was due by the end of 2026, and DVV
  now states certification and release slip to 2027.
  <https://dvv.fi/en/european-digital-identity-wallet>
- The Citizen Certificate card remains a live mechanism: EU countries
  must accept identification with it in early 2026, and DVV continues
  shipping desktop card-reader software.
  <https://dvv.fi/en/citizen-certificate-on-id-card>

## Consequences for this repository

1. Stock Android cannot serve an on-card key to any browser on any
   current or announced version; the patched KeyChain remains the only
   route, and both Chrome and Firefox sit behind the same choke point
   it opens.
2. The demonstrator stays pinned to Android 13 on flame — the last
   release with official device support for the verification Pixel.
   Later Android needs a patch rebase and newer hardware, not a
   different design.
3. The provider concept is upstream-worthy: Google shipped the same
   shape on ChromeOS and Apple ships it in CryptoTokenKit, while AOSP
   has nothing and nobody was found proposing it.
4. Card login stays relevant through at least 2026-2027 while the
   Finnish EUDI wallet slips; wallet presentation is a complementary
   future track with its own provider APIs, not a replacement for
   certificate authentication on the sites that require it today.
