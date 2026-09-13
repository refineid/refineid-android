# ADR 0012: Platform KeyChain external-key integration

Status: Accepted

Date: 2026-08-15

## Context

ADR 0011 establishes that an app-owned WebView and a process-local JCA
provider are diagnostic tools, not the system-browser result. Chrome,
Firefox, and other independent applications obtain client-certificate
identities through Android `KeyChain`.

Current AOSP assumes that every selectable client private key is an
AndroidKeyStore entry:

- `IKeyChainService.requestPrivateKey` returns a Keystore2 grant string;
- `KeyChain.getKeyPair` reconstructs an AndroidKeyStore key from that grant;
- `KeyChainService` reads certificates and grants from AndroidKeyStore; and
- `KeyChainActivity` enumerates `AndroidKeyStore.aliases()` and retains only
  key entries.

The administrative install path does not provide an escape hatch.
`DevicePolicyManager.installKeyPair` converts the supplied `PrivateKey` to an
encoded `PKCS8EncodedKeySpec`, and the KeyChain AIDL accepts those encoded
private-key bytes. A FINEID authentication key cannot use this path because
the private key is non-exportable and remains on the card.

A credential-management policy can choose an alias for an exact package and
URI, but the current grant path still requires the alias to identify an
AndroidKeyStore key. Policy can remove a chooser interaction; it cannot create
an external key.

The current RefineID application now has both complete-message and
exact-digest signing boundaries. Both routes use one holder-entered PIN1,
serialize USB use, validate the card key profile, and locally verify the card
signature before returning it.

## Decision

The Pixel/AOSP work will add an external-key branch to `KeyChain`. It will not
model the card as an AndroidKeyStore or KeyMint key and will not patch
Keystore2 for the first implementation.

The platform branch consists of four boundaries:

1. `KeyChainService` owns aliases, grants, certificate access, and the
   connection to a statically trusted external-key provider.
2. `KeyChain.getPrivateKey` returns a framework-owned, non-exportable
   `PrivateKey` for an external alias.
3. A framework JCA provider recognizes only that private-key class, hashes or
   validates its input, and asks `KeyChainService` to sign an exact digest.
4. A privileged RefineID service obtains a fresh PIN1 through its secure UI,
   signs through the retained USB session, locally verifies the result, and
   returns only the verified signature or a coarse failure.

This keeps ordinary browser code on the normal `KeyChain` and JCA paths. No
Chrome or Firefox fork is required for the supported rows in the matrix below.

## Platform shape

### Alias and certificate discovery

External providers are declared in the system image, not registered by an
arbitrary installed application. A provider is identified by a component
protected with a signature-level bind permission and a matching priv-app and
SELinux policy.

The provider exposes active public identities. KeyChain assigns a stable,
non-personal alias in its own namespace; the alias must not contain a card
serial, certificate subject, identity code, reader model, or device detail.
The leaf certificate is read dynamically from the active card. Its issuing
certificate comes from the fingerprint-pinned public FINEID set only after an
exact direct-issuer check; ADR 0026 defines that fail-closed boundary.

`KeyChainActivity` unions active external aliases with AndroidKeyStore aliases
before applying the existing key-type, issuer, user-selectable, and policy
filters. Its adapter obtains the external certificate through
`KeyChainService`; it does not pretend that the alias is a KeyStore key entry.

`containsKeyPair`, `setGrant`, certificate retrieval, alias removal, and grant
cleanup gain an explicit external-alias branch. Existing AndroidKeyStore
behavior remains unchanged.

### Private-key descriptor

A new hidden parcelable response replaces the assumption that
`requestPrivateKey` can return only a Keystore2 grant:

- `KEYSTORE_GRANT` carries the existing grant string;
- `EXTERNAL_KEY` carries the KeyChain-owned alias, key algorithm, public-key
  parameters, and an active provider generation; and
- no response means absent, inactive, or unauthorized, as today.

The existing AIDL method remains during migration. A new method returns the
typed response so platform components can be updated without overloading the
grant-string syntax.

For an external response, the framework constructs an RSA or EC
`KeyChainExternalPrivateKey`. It returns `null` from `getEncoded`, reports no
export format, carries only public parameters and an opaque alias, and cannot
be serialized into private-key material.

### Framework JCA provider

The platform installs a JCA provider visible in every application process.
Its services declare `KeyChainExternalPrivateKey` as the supported key class,
so ordinary software and AndroidKeyStore keys continue to fall through to
their existing providers.

For hashed JCA algorithms, the provider hashes incrementally in the calling
browser process and sends only the final digest across Binder. It never sends
the TLS transcript or buffers a Binder-sized message. The external service
accepts only named algorithms and exact digest lengths.

The provider implements:

- `SHA256withRSA`;
- `SHA256withRSA/PSS`;
- `SHA384withRSA`;
- `SHA384withRSA/PSS`;
- `SHA512withRSA`;
- `SHA512withRSA/PSS`;
- `SHA256withECDSA`;
- `SHA384withECDSA`;
- `NONEwithRSA`, with strict parsing of a supported RSA DigestInfo; and
- `NONEwithECDSA`, accepting only a supported digest length.

It deliberately does not expose raw RSA private-key encryption. The card API
accepts a digest and performs RSA-PSS encoding internally; it cannot apply an
arbitrary modulus-wide private operation.

### Sign call

The hidden KeyChain sign call is synchronous because JCA `Signature.sign()` is
synchronous. The framework provider invokes it only from the browser's crypto
worker, never a main thread.

The request carries:

- the KeyChain-owned external alias;
- one closed algorithm identifier;
- an exact-length digest; and
- the provider generation observed when the key was obtained; and
- an opaque Binder token created in the calling browser process solely to
  observe that process's liveness.

It does not carry a caller UID or package as a trusted field.
`KeyChainService` derives the Binder caller UID, verifies the alias grant and
active generation, resolves the installed package for holder-facing consent,
and only then proxies to the trusted RefineID service.

The private provider call includes that KeyChain-derived UID and its resolved
package names. The provider accepts such fields only from the statically bound
KeyChain service after independently enforcing the binding permission and
KeyChain's system UID; an ordinary process cannot submit caller attribution.

The private AIDL interface owns the provider algorithm vocabulary. KeyChain
maps each framework signature algorithm to its named provider counterpart
instead of forwarding an assumed integer value. Release staging also compares
the independently compiled AIDL and parcelable wire implementations, allowing
only the Android platform versus AndroidX annotation dialect required by their
two build environments.

The liveness token is not caller identity and grants no authority. The
RefineID service links to its death while an operation or secure prompt is
pending, allowing browser-process death to cancel and clear that work without
trusting any browser-supplied identity claim.

The result is either a signature of the algorithm's fixed shape or a coarse
typed failure. Transport details, card status words, certificate contents,
PIN shape, and retry-counter values do not cross into the browser process.

## Browser algorithm matrix

| Caller path | Input received by platform provider | Card operation | Status |
| --- | --- | --- | --- |
| Chromium `SHA256withRSA` | Complete message | SHA-256 digest, RSA PKCS#1 v1.5 | Supported |
| Chromium `SHA256withRSA/PSS` | Complete message | SHA-256 digest, native RSA-PSS | Supported; direct JCA support prevents Chromium's raw-RSA fallback |
| Chromium `SHA384withRSA` | Complete message | SHA-384 digest, RSA PKCS#1 v1.5 | Supported |
| Chromium `SHA384withRSA/PSS` | Complete message | SHA-384 digest, native RSA-PSS | Supported; direct JCA support prevents Chromium's raw-RSA fallback |
| Chromium `SHA512withRSA` | Complete message | SHA-512 digest, RSA PKCS#1 v1.5 | Supported |
| Chromium `SHA512withRSA/PSS` | Complete message | SHA-512 digest, native RSA-PSS | Supported; direct JCA support prevents Chromium's raw-RSA fallback |
| Chromium `SHA256withECDSA` | Complete message | SHA-256 digest, P-384 ECDSA | Supported |
| Chromium `SHA384withECDSA` | Complete message | SHA-384 digest, P-384 ECDSA | Supported |
| Gecko `NoneWithECDSA` | Precomputed digest | P-384 ECDSA selected by exact digest length | Supported for SHA-256 and SHA-384 |
| Gecko `NoneWithRSA` | DER SHA-2 DigestInfo prepared by NSS | Strictly extract a SHA-256, SHA-384, or SHA-512 digest, then native RSA PKCS#1 v1.5 | Supported at the provider boundary; an on-device Firefox handshake remains pending |
| Gecko `raw` for RSA-PSS | Modulus-wide EMSA-PSS encoded block | No matching card operation | Unsupported in unmodified Firefox for RSA-PSS |

Gecko currently implements its RSA-PSS path by performing EMSA-PSS encoding
itself and asking Java for `RSA/None/NoPadding`. The original digest cannot be
recovered from that randomized encoded block. Supporting this row requires a
Gecko change that passes the digest and PSS parameters, or a different card
interface; weakening the card boundary to emulate raw RSA is not an option.

The primary ECDSA card path does not have this limitation.

### Pinned browser source audit

The browser contract was checked on 2026-08-15 against immutable upstream
revisions, independently of the provider implementation:

- Chromium revision
  [`d8a3ba218dabe95a746bd44f4d5747b2f3d72725`](https://chromium.googlesource.com/chromium/src/+/d8a3ba218dabe95a746bd44f4d5747b2f3d72725/net/ssl/ssl_platform_key_android.cc)
  probes each named JCA `Signature` with the selected private key and signs the
  complete TLS input with that same algorithm. Its raw-RSA PSS fallback is used
  only when the named PSS signature is unavailable. The corresponding
  [`AndroidKeyStore.java`](https://chromium.googlesource.com/chromium/src/+/d8a3ba218dabe95a746bd44f4d5747b2f3d72725/net/android/java/src/org/chromium/net/AndroidKeyStore.java)
  performs `getInstance`, `initSign`, `update`, and `sign` directly.
- Firefox revision
  [`98f1235b79c19a808e3101160efb7810b71a75d7`](https://github.com/mozilla-firefox/firefox/blob/98f1235b79c19a808e3101160efb7810b71a75d7/mobile/android/geckoview/src/main/java/org/mozilla/gecko/ClientAuthCertificateManager.java)
  uses `NoneWithRSA` and `NoneWithECDSA` through JCA, but uses
  `RSA/None/NoPadding` for its `raw` RSA-PSS route. Its
  [`backend_android.rs`](https://github.com/mozilla-firefox/firefox/blob/98f1235b79c19a808e3101160efb7810b71a75d7/security/manager/ssl/osclientcerts/src/backend_android.rs)
  performs one real signature to obtain the length and another to return the
  result. NSS
  [`SGN_Digest`](https://github.com/mozilla-firefox/firefox/blob/98f1235b79c19a808e3101160efb7810b71a75d7/security/nss/lib/cryptohi/secsign.c)
  constructs and DER-encodes `DigestInfo` before its RSA PKCS#1 signing call.

These source checks prove the JCA input shapes and the need for replay. They do
not replace the independent Chrome and Firefox handshakes on the final patched
system image.

The source result was also checked against the exact independently installed
[official Firefox 151.0.4 arm64 APK](https://ftp.mozilla.org/pub/fenix/releases/151.0.4/android/fenix-151.0.4-android-arm64-v8a/fenix-151.0.4.multi.android-arm64-v8a.apk)
on 2026-08-16. The artifact has SHA-256
`bc75c0496b04eff55121ff08f974ad2f7f9c603ec7d3f376f4e2f3d3e158d11b`.
Its shipped `ClientAuthCertificateManager` accepts `NoneWithRSA` and
`NoneWithECDSA` through `Signature.getInstance`, and retains
`RSA/None/NoPadding` for the raw route. Installation and launch on the stock
Pixel passed. This artifact audit still does not count as a client-certificate
handshake on the patched system.

## One-result replay lease

Gecko's PKCS #11 adapter currently calls its signing function once to learn
the output length and again to obtain the signature. Performing two card
operations would prompt twice and spend two PIN-protected operations for one
TLS signature.

After one locally verified result, the RefineID service therefore retains a
one-result replay lease keyed by:

- the browser UID derived and forwarded by KeyChain;
- alias and provider generation;
- algorithm; and
- exact digest.

The lease permits one retrieval, expires after a short named timeout, and
zeroizes its signature bytes on retrieval, replacement, provider-generation
change, detach, service shutdown, or expiry. It stores no PIN. A third request
requires a new holder-approved operation.

This works for Gecko's deterministic RSA PKCS#1 and ECDSA inputs. It cannot
repair Gecko RSA-PSS because independently generated EMSA-PSS inputs may use
different salts and therefore do not match the lease key.

## Consent and security invariants

- Alias selection uses the existing KeyChain chooser or an explicit
  credential-management policy. The stable external alias remains provider
  owned and is never deleted as policy-managed key material. A browser never
  self-grants an alias.
- Every new card operation requires fresh holder PIN1 entry. PIN values are
  neither cached nor sent through KeyChain or the browser process.
- The platform-signed provider holds the Android 13 background-activity launch
  permission solely to show its own unexported secure PIN activity for an
  authenticated KeyChain request; ADR 0027 defines the restriction.
- The secure prompt identifies the requesting application. The JCA boundary
  does not carry a trustworthy web origin, so the design does not claim
  origin-level consent beyond Android's existing UID grant model.
- The browser controls the data it asks its granted key to sign, as it already
  does for ordinary KeyChain keys. RefineID accepts only the narrow
  authentication algorithms and still requires holder action.
- Every signature is verified against the currently selected authentication
  certificate before it crosses the provider boundary.
- Card operations remain serialized and credential APDUs remain at-most-once.
- Browser-token death, provider Binder death, detach, generation mismatch,
  prompt cancellation, timeout, and caller interruption fail closed and clear
  pending state.
- Debug builds record only sanitized type, length, caller, timing, and outcome
  metadata. RefineID release builds emit no logs.
- Platform signing keys, priv-app allowlists for a particular build, and any
  real card or identity material are never committed.

## Patch series

The first Pixel patch series is ordered so each boundary can be tested before
the next one depends on it:

1. Add hidden typed descriptors, algorithm/failure constants, and AIDL tests.
2. Add `KeyChainExternalPrivateKey` and the external JCA provider with
   synthetic Binder tests.
3. Extend the RSA vocabulary to SHA-384 and SHA-512 PKCS#1/PSS without
   renumbering existing framework or provider codes.
4. Add KeyChainService external aliases, grants, certificates, provider
   generation checks, and proxy signing.
5. Extend KeyChainActivity discovery and filtering for external identities.
6. Carry browser-process liveness through the request and add the
   signature-protected, exact-component KeyChain binding with static package,
   privilege, UID, and signing-certificate trust checks.
7. Add the RefineID privileged service, system-image declarations, SELinux
   policy, secure prompt coordinator, and one-result replay lease over the
   existing digest-signing boundary. These sources are implemented; their
   first full Soong image build remains pending on the Linux builder.
8. Run independent Chrome and Firefox client-authentication tests, including
   cancellation, detach, wrong-card generation, process death, and the matrix
   limitations above.

The initial implementation targets the connected Pixel 4 build
`TP1A.221005.002.B2`, based on AOSP tag `android-13.0.0_r31`. Reproducible
patches live under `platform/aosp/android-13.0.0_r31`.

A full Android 13 platform build requires a 64-bit Linux builder. AOSP builds
for Android 11 and newer are unsupported on macOS, and Google's current
[workstation guidance](https://source.android.com/docs/setup/start/requirements)
budgets at least 400 GB of free space. The Mac remains useful for isolated
source, AIDL, Java, application, and physical-device validation, but it is not
the platform image builder.

## Rejected alternatives

- Importing or copying the private key: impossible for a non-exportable card
  key and contrary to the security model.
- Installing only an application JCA provider: providers are process-local and
  do not appear in independent browsers.
- Treating the key as a synthetic Keystore2/KeyMint key immediately: this
  expands the trusted and vendor-facing patch surface without being necessary
  for KeyChain browser callers.
- Credential-management policy alone: it selects existing aliases but does
  not implement an external key.
- Raw RSA emulation: the card deliberately exposes only named signature
  operations and cannot safely implement arbitrary private-key exponentiation.
- Keeping the WebView as production authentication: it does not satisfy the
  independent system-browser requirement.

## Verification required for completion

- AOSP unit tests prove typed descriptor parsing, UID-bound grants, provider
  generation invalidation, certificate filtering, and fail-closed Binder
  behavior.
- Framework provider tests prove exact algorithm/input mapping and ordinary-key
  provider fall-through.
- RefineID tests prove one fresh PIN per card operation, mandatory local
  verification, one-result replay, zeroization, detach, timeout, and process
  death behavior.
- Physical Pixel tests prove that Chrome and Firefox independently receive the
  alias through `KeyChain`, complete a supported TLS client-authentication
  handshake, and cannot use the alias without a grant and holder action.
- Release artifact inspection continues to prove that RefineID contains no
  logging calls or trace literals.

## Upstream references

- [AOSP `KeyChain`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/KeyChain.java)
- [AOSP `IKeyChainService`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/keystore/java/android/security/IKeyChainService.aidl)
- [AOSP `KeyChainService`](https://android.googlesource.com/platform/packages/apps/KeyChain/+/refs/heads/main/src/com/android/keychain/KeyChainService.java)
- [AOSP `KeyChainActivity`](https://android.googlesource.com/platform/packages/apps/KeyChain/+/refs/heads/main/src/com/android/keychain/KeyChainActivity.java)
- [AOSP `DevicePolicyManager.installKeyPair`](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/admin/DevicePolicyManager.java)
- [Chromium Android TLS signature mapping](https://chromium.googlesource.com/chromium/src/+/HEAD/net/ssl/ssl_platform_key_android.cc)
- [Chromium Android JCA bridge](https://chromium.googlesource.com/chromium/src/+/HEAD/net/android/java/src/org/chromium/net/AndroidKeyStore.java)
- [Gecko Android KeyChain bridge](https://hg.mozilla.org/mozilla-central/raw-file/tip/mobile/android/geckoview/src/main/java/org/mozilla/gecko/ClientAuthCertificateManager.java)
- [Gecko Android PKCS #11 backend](https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/osclientcerts/src/backend_android.rs)
