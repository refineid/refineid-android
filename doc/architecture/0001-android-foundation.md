# ADR 0001: Android foundation and first hardware slice

Status: Accepted

Date: 2026-08-15

## Context

RefineID needs to use a Finnish identity card for authentication and signing
without exporting its private keys. Android provides USB Host and NFC APIs, but
its public KeyChain API does not let an application register a non-exportable
private key residing on an external smart card as a system client-certificate
identity.

The reference Apple application can expose such an identity through
CryptoTokenKit. Android has no equivalent public application API. Therefore an
in-app browser can prove TLS and card behavior, but it cannot by itself satisfy
the normal-browser product goal.

## Decision

The implementation is split into four boundaries:

1. Transport adapters provide ISO 7816 exchanges over USB CCID and, later, NFC.
2. A narrow native bridge exposes the reusable refineid-core operations needed
   by Android.
3. Application services own consent, PIN lifecycle, certificate selection, and
   sanitized state.
4. Browser integrations consume those services. A diagnostic browser is built
   first; system-browser support remains an explicit platform-integration
   workstream.

The first physical vertical slice uses USB:

    Pixel USB Host
        -> CCID reader
        -> identity card
        -> PIN-authorized RSA signature
        -> local certificate verification

Reader discovery and USB permission land before any APDU is sent. CCID framing
then gains pure JVM tests, followed by the Rust bridge and the legacy RSA-card
flow.

The Android application initially targets API 37, supports API 33 and newer,
and builds with JDK 26 and a pinned Gradle wrapper. Generated JVM bytecode
targets version 17 independently of the build runtime. API 33 is the initial
minimum because it matches the physical development device; lowering it is a
separate compatibility decision.

## Source relationship

Protocol decisions come from fineid-spec. Shipped reusable Rust should come
from a pinned public refineid-core revision. The broader internal monorepo is
an oracle for coverage and compatibility, and RefineID-Apple is the UI and
behavior reference. All of these sources are licensed under Apache-2.0.

## Security consequences

- USB permission does not authorize a card command; user intent is still
  required for PIN-protected operations.
- Real credentials, card data, certificates, APDU captures, and device
  identifiers never enter Git or ordinary logs.
- PIN memory must be short lived and zeroized.
- The revoked development card can prove transport, signing, and local
  verification. It cannot prove successful relying-party authentication.
- Successful end-to-end browser testing ultimately requires a valid test
  credential and an authorized relying party.

## Browser consequence

The browser goal is intentionally unresolved by the first slice. Candidate
paths to investigate are an Android/Open Source Project credential-provider
integration, cooperation with a browser that exposes an external-key hook, or
a browser-neutral service protocol supported by the relying party. A WebView
or GeckoView result is diagnostic evidence, not completion of system-browser
support.
