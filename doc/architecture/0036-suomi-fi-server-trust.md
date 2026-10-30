# ADR 0036: Suomi.fi identification server trust

Status: Accepted

Date: 2026-08-17

## Context

The debug browser must complete a Suomi.fi e-Identification login with the
card. Choosing the certificate-card method (Varmennekortti) navigates from the
discovery page at `tunnistautuminen.suomi.fi` to the Digital and Population Data
Services Agency (DVV) authentication host `kortti.tunnistautuminen.suomi.fi`.

The two hosts use different certificate authorities. The discovery host chains
to a public Amazon root and validates normally. The certificate-card host
presents a server certificate that chains leaf -> `Telia Server CA v3` ->
`Telia Root CA v2`. The bundled WebView's root store omits `Telia Root CA v2`,
an otherwise-public Finnish root in the Mozilla program, so its server
handshake fails before the card is ever consulted.

Observed on a physical device (recorded exchange, not documentation): the
platform certificate verifier reports `Trust anchor for certification path not
found`, the socket reports `net_error -202` (`ERR_CERT_AUTHORITY_INVALID`), and
the certificate-card page never loads. Answering the single
`onReceivedSslError` callback with `proceed()` is not sufficient: the WebView
invokes the handler once, but the network stack keeps rejecting the certificate
on the connections that follow, so the page still fails. Server trust has to be
repaired at the network-stack layer, not the per-error callback.

## Decision

A debug-only network security config
(`app/src/debug/res/xml/network_security_config.xml`, referenced from the debug
manifest) sets the application trust anchors to the platform system store plus
`Telia Root CA v2`:

```xml
<trust-anchors>
    <certificates src="system" />
    <certificates src="@raw/telia_root_ca_v2" />
</trust-anchors>
```

The root is committed as `app/src/main/res/raw/telia_root_ca_v2.pem` and
identified by its SHA-256 fingerprint `242B6974...B82C`. `src="system"` is the
full platform trust set, not the legacy system directory: hosts under the public
ISRG and Amazon roots keep validating, verified against their vendor test hosts
after the change. `Telia Root CA v2` is public CA material and contains no
cardholder or private-key bytes; adding it fills a gap in the WebView store
rather than lowering trust.

`cleartextTrafficPermitted` stays `true` because a network security config
overrides the manifest `usesCleartextTraffic` flag, and certificate AIA, OCSP,
and CRL fetches over plain HTTP must keep working. The `InsecureBaseConfiguration`
lint warning is suppressed on that element rather than project-wide.

The config lives in the debug source set because release ships no embedded
browser (see ADR 0011). When a release consumer needs card authentication
against Telia-issued Suomi.fi hosts, move the anchor to the `main` source set.

## Consequences

- The certificate-card handshake completes, the card client-certificate
  authentication runs, and Suomi.fi returns the identified holder to the
  service. Verified end to end on a physical device with an EC card.
- `AppTrace.browserTlsError` records the `SslError` primary error code only,
  which tells an untrusted-authority rejection apart from the other TLS
  failures; the host and the certificate names are not traced.
- The trust addition is scoped to a single pinned public root; any other
  untrusted certificate is still refused.
