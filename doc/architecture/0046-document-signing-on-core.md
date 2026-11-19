# ADR 0046: Document signing and verification on refineid-core

## Status

Accepted. Supersedes ADRs 0015 to 0025 and 0028 to 0030.

## Context

The app carried its own Kotlin document stack: CMS, incremental PDF
signing, PAdES validation, RFC 3161 timestamps, OCSP and CRL evidence,
ASiC-E with XAdES, and a bounded signing network. The same work lives in
the shared `refineid-doc-sign` crate of refineid-core, which every
first-party client signs and verifies with.

## Decision

The Sign and Verify screens drive `native/refineid-doc-sign-android`, a
UniFFI surface over `refineid-doc-sign`. The app's own document stack is
deleted.

- Signing: the core builds each document, asks the card in this phone to
  sign the digests through `CardDigestSigner`, timestamps them with the
  holder's configured authorities (the core's default when none is
  stored), collects the long-term material against the card's CA
  certificates the app passes in, and writes each signed file under its
  signed-document name. PDFs are PAdES at LTA with the core's
  verification seal in the app's language; several files are one ASiC-E
  container with an XAdES signature at LTA. The app offers the written
  file in the platform save panel.
- Verifying: the core judges every signature of the chosen file against
  the EU trusted lists' anchors (the list of the lists and the Finnish
  list, fetched over the app's transport and cached on disk) and asks
  the responders about a signer the file leaves unchecked. The screen
  shows the core's verdict.
- Network: `CoreHttpClient` is the core's transport. A
  certificate-published host is vetted by the core (`vet_destination`);
  the request connects to exactly the vetted addresses and never resolves
  the name again. HTTPS goes through the platform's `HttpsURLConnection`
  to the address literal, with the host named in TLS (SNI) by
  `NamedHostSocketFactory` and the certificate checked against the host
  name. HTTP goes over a socket to the address (`PlainHttpExchange`),
  because the platform's HTTP stack refuses cleartext to an address
  literal. A redirect is vetted again. The configured timestamp authority
  is trusted as configured and connects by name.
- Release builds reach the network for these fetches only, beside RAPP
  and the in-app browser (AGENTS.md).

## Consequences

Signing and verification behave as on the other first-party clients. The
core decides the signed file name, the levels, the timestamp policy (all
configured authorities are asked; a login is accepted for a sole HTTPS
authority only) and the verdict.
