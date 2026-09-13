# Client-Certificate Delegation, Fast Key Swapping, and Web Limitations on Android

Date: 2026-09-09

A technical examination of why smart-card authentication cannot be proxied or
injected on stock Android without operating-system hooks, what modern identity
verification sites actually inspect, and why Android should follow the path
blazed by CryptoTokenKit on iOS 26.

---

## 1. The Core Paradox: Key Possession vs. Signing Oracle

In public-key digital signatures, an entity does not strictly need to possess
the private key as a raw byte array in memory. Mathematically, a private key is
simply an answering oracle:

$$\text{Sign}(K_{\text{priv}}, \text{message}) \longrightarrow \text{signature}$$

Any agent that possesses the *capability* to evaluate this function (by
dispatching APDUs to an on-card chip or HSM) produces cryptographic results
indistinguishable from an agent possessing the raw private key in memory.

On desktop platforms and modern mobile operating systems, this principle is
the foundation of smart-card architecture:
- **Windows (CAPI / CNG)**: Chrome and Edge never see key bytes. Windows
  provides an `NCRYPT_KEY_HANDLE`. When the browser calls `NCryptSignHash()`,
  Windows invokes the registered Smart Card Minidriver (e.g.
  `refineid_minidriver.dll`), which exchanges APDUs with the card.
- **macOS & iOS 26 (CryptoTokenKit)**: The OS exposes opaque `SecKeyRef`
  handles. `SecKeyCreateSignature()` invokes `TKTokenSmartCardPINAuthOperation`
  inside a third-party token extension, providing system-wide card authentication
  for Safari.
- **Linux (PKCS#11 / NSS)**: Browsers talk through `p11-kit` or NSS to
  `librefineid_pkcs11.so`, dispatching `C_Sign` to the token.

Yet on stock Android, attempting to perform this exact operation in standalone
Google Chrome fails completely.

---

## 2. Why ".p12 Fast-Swapping" Fails

It is tempting to ask: *Why not generate software keys or swap `.p12`
(PKCS#12) packages on the fly as we communicate with the card?*

This approach runs into two impassable barriers: one mathematical, one
architectural.

### The Cryptographic Barrier
A `.p12` archive requires both the X.509 certificate (containing the card's
public key $K_{\text{card\_pub}}$) and the corresponding private key
($K_{\text{card\_priv}}$).
1. **The card's private key cannot be exported**: The Finnish citizen card
   enforces `CKA_EXTRACTABLE = false`. The silicon refuses to export private
   key material under any circumstance.
2. **Software key substitution breaks the TLS handshake**: If one generates a
   temporary software key pair ($K_{\text{soft\_pub}}, K_{\text{soft\_priv}}$)
   and bundles $K_{\text{soft\_priv}}$ with the card's real certificate:
   - The browser sends the card certificate ($K_{\text{card\_pub}}$) to the
     server.
   - The server issues a challenge over the handshake transcript.
   - Android signs the challenge with $K_{\text{soft\_priv}}$.
   - The server verifies: $\text{Verify}(K_{\text{card\_pub}}, \text{hash}, \text{sig}) \stackrel{?}{=} \text{True}$.
   - **Verification fails instantly.** The TLS connection is aborted with a fatal
     `handshake_failure` or `decrypt_error`.

One cannot forge or substitute a private key for an existing certificate without
breaking the underlying RSA-3072 or ECC P-256 discrete logarithm mathematics.

### The Android OS Barrier
Even if an exportable key existed:
- `KeyChain.createInstallIntent()` requires interactive user confirmation:
  unlocking the lock screen, naming the certificate, and accepting persistent
  system warnings ("Network may be monitored by an authority").
- Stock Android provides no public background API for non-system apps to
  silently install, update, or delete keys in the system `KeyChain`.
- Writing key pairs to the hardware KeyMint / Trusty TEE silicon incurs
  hundreds of milliseconds of latency per write.

---

## 3. Case Study: What `https://card.refineid.fi` Actually Verifies

The reference FINEID authentication site documented at
`https://www.refineid.fi/demo` illustrates what a relying party demands during
card login. Verification spans two distinct architectural boundaries:

```
[ Card / Chip ]
      │  (PIN1 + APDU: PSO CDS)
      ▼
[ Browser TLS Client ]
      │  mTLS Handshake (CertificateVerify)
      ▼
┌────────────────────────────────────────────────────────┐
│ Apache mod_ssl (TLS Boundary)                          │
│  - SSLCACertificateFile (DPDSA trust bundle)           │
│  - SSLOCSPEnable leaf (Live revocation check)          │
│  - SSLVerifyClient optional (Cryptographic verification)│
│  - Extended Key Usage: id-kp-clientAuth                │
└──────────────────────────┬─────────────────────────────┘
                           │ Sets SSL_CLIENT_VERIFY=SUCCESS
                           │ Exports Subject DN & Cert to CGI
                           ▼
┌────────────────────────────────────────────────────────┐
│ guestbook.py (Application Boundary)                    │
│  - Checks SSL_CLIENT_VERIFY == "SUCCESS"               │
│  - Extracts serialNumber (PEUIN / SATU identifier)     │
│  - Extracts & decodes eMRTD holder name (AA/AE/OE)     │
│  - Binds HMAC-SHA256 CSRF token to holder's PEUIN      │
└────────────────────────────────────────────────────────┘
```

1. **The TLS Boundary (Apache `mod_ssl`)**:
   - **Handshake Signature**: Verifies that the client possesses the private
     key matching the certificate via `CertificateVerify`.
   - **Certificate Authority Anchor**: Verifies that the certificate chains up
     to the official Finnish Digital and Population Data Services Agency
     (DPDSA / DVV / VRK) root bundle (`dpdsa-trust-bundle.pem`). Self-signed or
     untrusted CA certificates are rejected during the TLS handshake.
   - **Live Revocation**: Queries the DVV OCSP responder to verify that the
     certificate has not been suspended or revoked.
   - **Key Purpose**: Enforces `id-kp-clientAuth` (Client Authentication),
     ensuring the user selected the authentication certificate (PIN1), not the
     Qualified Electronic Signature certificate (PIN2).
2. **The Application Boundary (`guestbook.py` CGI)**:
   - Enforces `SSL_CLIENT_VERIFY == "SUCCESS"`.
   - Extracts the **PEUIN** (Personal Electronic Unique Identification Number /
     *sähköinen asiointitunnus* / SATU) from the Subject DN `serialNumber`.
   - Reconstructs native Finnish names from uppercase eMRTD spelling
     (`AA` $\to$ `Å`, `AE` $\to$ `Ä`, `OE` $\to$ `Ö`).
   - Issues short-lived CSRF tokens cryptographically keyed to the verified
     PEUIN.

Because the server-side gate is rooted in **TLS-level client certificate
validation**, the client must participate in the TLS handshake itself.

---

## 4. The "Adversary with Good Intentions"

Why can't an intermediary proxy sit between the browser and the server, or
between the browser and the card, answering challenges on the user's behalf?

In security engineering, **cryptography cannot measure intent**:
- To a mathematical verifier, an "intermediary with good intentions" is
  indistinguishable from a **Relay Attacker (Man-in-the-Middle / Mafia Fraud)**.
- If a protocol allowed an arbitrary third-party proxy to relay challenges
  without strict channel binding, a phishing site could trick a user into
  authenticating a high-value bank transaction while showing an innocent login
  screen.
- **TLS 1.3 Channel Binding**: TLS 1.3 explicitly defeats intermediaries by
  having the client sign the **`transcript_hash`**. The transcript hash includes
  the ephemeral Diffie-Hellman keys negotiated directly between the client's
  network socket and the server. An external proxy cannot insert itself into the
  handshake without breaking the transcript.
- **Android Sandbox Model**: Android enforces mutual suspicion. The kernel and
  SELinux treat any third-party app attempting to intercept or inject keys into
  Chrome as an attacker. There is no concept of a "friendly" app helper in the
  OS Keystore architecture.

---

## 5. Web Technologies and Extensions: Why They Cannot Help

### Chrome Extensions (`chrome.certificateProvider`)
Google actually designed an API that matches the "authorized signing oracle"
model: [`chrome.certificateProvider`](https://developer.chrome.com/docs/extensions/reference/api/certificateProvider/).
It allows extensions to receive `onCertificatesRequested` and
`onSignatureRequested` events, routing TLS handshake signing to external smart
cards.

However:
1. Google intentionally restricted `chrome.certificateProvider` to **ChromeOS**.
2. **Chrome for Android does not support extensions at all.** The entire
   extension runtime is disabled in the mobile Chrome build.

### Web NFC (Chrome Status feature `6261030015467520`)
Shipped in Chrome 89 on Android, Web NFC introduces `NDEFReader` and
`NDEFWriter`. It cannot be used for card authentication for two fundamental
reasons:
1. **Protocol Restriction**: Web NFC is strictly limited to NDEF tags (simple
   records like URLs and text). Google and the W3C deliberately barred raw
   ISO 7816-4 APDU commands (`IsoDep.transceive`) to protect contactless payment
   and ID cards from malicious scripts. FINEID authentication requires raw
   `SELECT`, `VERIFY`, and `PSO:CDS` APDUs.
2. **The Timing Catch-22**: Web NFC is a JavaScript DOM API that runs inside an
   already-loaded webpage. Mutual TLS client-certificate authentication occurs
   during the initial TCP/TLS handshake, *before* any HTTP traffic or JavaScript
   can be delivered. JavaScript cannot satisfy a TLS handshake required to fetch
   that JavaScript.

---

## 6. Conclusion: Android Should Do Better (Just Like iOS 26)

Every other major operating system provides an extensible provider model for
smart-card authentication:
* **Windows**: Smart Card Minidrivers plug into CAPI / CNG.
* **macOS**: CryptoTokenKit persistent extensions plug into Security.framework.
* **iOS 26**: Apple expanded **CryptoTokenKit** with built-in NFC smart-card
  slots, allowing apps like RefineID-Apple to expose card certificates and
  on-chip signing system-wide, including Safari.
* **Linux**: NSS and `p11-kit` allow userspace PKCS#11 module registration.
* **ChromeOS**: `chrome.certificateProvider` allows extension-backed card
  middleware.

**Android stands alone as the only major operating system that locks out
third-party smart-card cryptographic service providers.**

Android KeyChain remains designed purely as a passive storage vault for raw
keys rather than an extensible cryptographic dispatch router. Until Android
introduces a public Service Provider Interface (SPI) for delegated signing in
KeyChain — matching what Apple accomplished with CryptoTokenKit — mobile users
remain divided between custom AOSP platform images (`IExternalKeyProviderService`)
and dedicated in-app browsers (`ReFineIdWebViewClient`).
