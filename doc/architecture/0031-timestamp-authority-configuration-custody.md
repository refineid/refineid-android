# ADR 0031: Timestamp-authority configuration custody

## Status

Accepted.

## Context

The Apple product keeps an ordered holder-configured timestamp-authority list.
Addresses and usernames are preferences, passwords are Keychain entries keyed
by address, and an empty authority list restores the shipped configuration.
Android needs the same product behavior without placing reusable credentials in
plain SharedPreferences, backups, logs, immutable password strings, tests, or
source control.

Authority configuration selects the service endpoint. Tokens authenticate to
independent runtime EU trusted-list timestamp anchors, never certificates
promoted from the response itself. See [ADR 0050](0050-trusted-list-timestamps.md).

Android Keystore operations may block. Its keys are non-exportable, but
hardware backing is device-dependent. Requiring StrongBox would unnecessarily
exclude otherwise supported devices. Binding this configuration key to an
unlock event would also conflict with intentionally lock-free development
devices; the Android documentation flags `setUnlockedDeviceRequired` behavior
problems on Android 12 through 14.

## Decision

`TimestampAuthorityStore` owns the ordered configuration boundary. Its methods
are synchronous and must run away from the main thread. A dedicated private
SharedPreferences file holds only the authority count, addresses, and optional
usernames. Application backup and device-transfer extraction remain disabled
for every app-private domain in the manifest rules.

The shipped set contains the single HTTPS endpoint
`https://timestamp.sectigo.com/qualified` without credentials. Saving that exact
set removes the override so a future shipped default is not shadowed. Saving an
empty list has the explicit meaning Restore Defaults. Duplicate addresses are
rejected so address-keyed password ownership cannot be ambiguous.

A username and password are either both absent or both present. A present
password may be empty because that is a complete HTTP Basic credential. Basic
credentials are accepted only for HTTPS authority addresses; the credential-
free shipped HTTP endpoint remains valid. Merely loading or saving a setting
does not probe the endpoint or make a network request.

`AndroidKeystoreTimestampAuthorityPasswordVault` protects password values with
one AES-256-GCM key generated directly through `KeyGenParameterSpec` in the
`AndroidKeyStore` provider. The key permits only encryption and decryption,
uses no padding, and requires provider-generated randomized encryption. It is
not exportable, does not require StrongBox, and is not bound to a lock-screen
authentication event.

Each write receives a fresh 96-bit GCM IV and uses the exact authority address
as additional authenticated data. The preference key is a Base64url-encoded
SHA-256 digest of that address. Only Base64-encoded IV and ciphertext are
persisted. Stored shapes are bounded by the network credential limits before
decryption output is accepted.

Passwords enter and leave the boundary as owned `CharArray` values. The vault
serializes UTF-16 code units directly into mutable byte arrays; plaintext
characters, plaintext bytes, address bytes, digests, IVs, and decoded
ciphertext are cleared at their ownership boundaries. Configuration and vault
`toString` or exception values contain no address, username, password, storage
key, or platform exception. Persisted corruption becomes the coarse
`MALFORMED` result; Keystore or persistence failure becomes `UNAVAILABLE`.

The implementation deliberately uses the platform API rather than deprecated
Jetpack `MasterKeys` helpers. Relevant platform contracts are documented by
[Android Keystore](https://developer.android.com/privacy-and-security/keystore)
and
[`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder).

## Verification

Host tests cover the HTTPS default, owned password copies, clearing,
redacted descriptions, trusted-list authority selection, empty Basic passwords, and
refusal of credentials over plaintext HTTP.

Instrumentation uses isolated synthetic preference names and a dedicated test
key alias. On the Android 13 Pixel 4 it proves ordered encrypted round trips,
absence of plaintext in stored values, a non-exportable Keystore key, randomized
ciphertext for repeated writes, authenticated failure after ciphertext
mutation, and complete credential removal on Restore Defaults. The test does
not access the reader, card, network, or production preference files.

## Consequences

The Android app now has a production-compatible custody boundary for the same
holder settings as Apple. The non-exportability guarantee is supplied by
Android Keystore; this decision does not claim hardware backing on every
supported device. Clearing mutable JVM and platform buffers is best effort,
while plaintext persistence, backup, diagnostic output, and source fixtures
remain prohibited.

The next slice can expose a terse settings surface and pass owned configured
authorities into the debug signing source. Release browser authentication and
production document-signing network policy remain separate milestones.
