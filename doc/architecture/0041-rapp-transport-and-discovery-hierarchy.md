# Architecture Record 0041: RAPP Transport & Discovery Hierarchy (Android Platform)

- **Document Version**: `26.10.3`
- **Normative Status**: Active Project Standard
- **Applies To**: `RefineID-Android` (Phone Custodian role)
- **Supersedes**: Prior architecture drafts assuming desktop listeners or static port advertising

---

## 1. Executive Summary & Security Model

The RefineID Remote Card Proxy protocol (RAPP) bridges physical identity cards (e.g. Finnish Citizen Certificate on FINEID cards) held at an Android phone's NFC radio to requester workstations (macOS, Windows, Linux/BSD).

### 1.1 Sovereign Phone Custodian vs. Requester Workstation

1. **Android Phone is the Sovereign Custodian**:
   - The smartphone possesses the physical NFC antenna, reads contactless PACE/CAN tokens, prompts user PINs securely on screen, and controls card custody.
   - Mobile operating systems (Android, iOS) provide isolated sandboxes and biometric security hardware, whereas desktop workstations have large attack surfaces, open daemon ports, and shared multi-user privileges.
   - **Zero Unprompted Exposure**: The Android phone **never** announces itself or opens any listening socket by default. It activates its listener and discovery advertisements **if and only if** the user explicitly toggles `[x] Allow Remote Reader` in the RefineID Android settings.
   - When "Allow Remote Reader" is disabled, all radio advertising (BLE Peripheral) and network listeners (mDNS/DNS-SD via `NsdManager`, TCP `ServerSocket`) are strictly quiescent, conserving battery and complying with RFC 8882 (zero trackable beacons).

2. **Workstation is Strictly an Outbound Client (Requester)**:
   - Workstations (macOS, Windows, Linux, FreeBSD, NetBSD) **never** bind listening ports (no port 47110) and never require firewall exemptions.
   - Workstations connect strictly via **outbound client TCP sockets** dialed toward the announced phone custodian.

3. **Workstation UX Hygiene**:
   - Desktop software operates as a **pure local card reader by default** (PC/SC contact readers via `pcscd` or Windows Smart Card Resource Manager).
   - Desktops only begin discovering/sniffing remote phone readers if the user explicitly turns on `[x] Enable Remote Phone Reader` in the workstation GUI.

---

## 2. Normative 3-Tier Discovery & Transport Hierarchy

When remote reader proxying is enabled, RefineID implements a strict fallback hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier 1: Apple Direct P2P (AWDL / MultipeerConnectivity)                 │
│         - Native Apple-to-Apple high-speed ad-hoc channel               │
│         - (Applicable only to Apple devices)                            │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ fallback (Android or non-Apple)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier 2: Bluetooth Low Energy Proximity (BLE GATT)                       │
│         - Cross-platform proximity-gated link (Android, Linux, Win, Mac)│
│         - Android BluetoothGattServer (API 21+) / SAR Framing           │
│         - Advisory RSSI discovery gate (>= -55 dBm)                     │
│         - Profile: fi.refineid.rapp.ble.v1                              │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ fallback (BLE unavailable or out-of-range)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Local IP Stream Discovery (mDNS / DNS-SD + Outbound TCP)        │
│         - IETF RFC 6762 (mDNS) & RFC 6763 (DNS-SD)                      │
│         - Android NsdManager registration: _refineid-stream._tcp.       │
│         - Phone acts as mDNS responder & TCP listener (ephemeral port)  │
│         - Workstation acts strictly as mDNS browser & outbound client   │
│         - Profile: fi.refineid.stream.v1                                │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Tier 2: Bluetooth Low Energy Proximity (`fi.refineid.rapp.ble.v1`)
- **Android Underlay**: `BluetoothLeAdvertiser.startAdvertising` + `BluetoothGattServer` opened via `BluetoothManager.openGattServer`.
  - Service UUID: `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
  - Channel Characteristic: `7E39FD02-A6B5-4D78-9E11-37E28E9545F1` (`PROPERTY_WRITE | PROPERTY_INDICATE`)
  - Bootstrap Characteristic: `7E39FD03-A6B5-4D78-9E11-37E28E9545F1` (`PROPERTY_READ`)
  - Framing: Mandates ATT MTU Exchange ($\ge 512$ bytes) and RAPP BLE SAR framing (6-byte header: Total Frame Length, Chunk Sequence, Flags, Reserved).
- **Advisory Proximity Gating**: Requester monitors RSSI and enforces an advisory discovery gate ($\ge -55\text{ dBm}$ filtered median over at least 3 packets, configurable to $-85\text{ dBm}$ in isolated developer testing).
  - *Threat Model Note*: Per RAPP v26.10.1 §4.4, RSSI is strictly an advisory filter and defense-in-depth heuristic; it does NOT prove physical proximity or defeat transparent RF relays or wormholes. Protection against unauthorized execution is provided at Layer 7 by explicit per-operation user consent on the phone display and PIN verification.
- **Clarification on L2CAP CoC**:
  - `BluetoothGattServer` does not manage L2CAP channels. On Android 10+ (API 29+), Bluetooth Low Energy Connection-Oriented Channels (CoC) are managed via `BluetoothAdapter.listenUsingInsecureL2capChannel` / `listenUsingL2capChannel` (returning `BluetoothServerSocket`), with dynamic PSMs discovered via `serverSocket.getPsm()`.
  - Because public user-space APIs for BLE L2CAP CoC are not supported on all client platforms (such as Windows user-space), GATT-based `fi.refineid.rapp.ble.v1` is the canonical cross-platform Tier 2 profile. Any future credit-based CoC profile would be a separate, distinct adaptation (`fi.refineid.rapp.ble-coc.v1`).
- **Zero OS Bonding**: No Android Bluetooth pairing dialogs or OS PIN passkeys. Security is entirely provided by application-layer Noise cryptography (`Noise_XXpsk3` for pairing, `Noise_KK` for sessions).

### 2.2 Tier 3: Local IP Stream Discovery (`fi.refineid.stream.v1`)
- **Discovery Service**: `_refineid-stream._tcp.` via Android `NsdManager.registerService`.
- **Ephemeral Port**: An ephemeral TCP `ServerSocket(0)` is bound on the local Wi-Fi interface.
- **Privacy (RFC 8882)**:
  - The service instance name MUST be a fresh, ephemeral random string generated on each registration: `refineid-[random_8_hex]._refineid-stream._tcp.local.`, preventing long-term device tracking across networks.
  - The SRV record target MUST use an anonymized, ephemeral host label: `refineid-[random_8_hex].local.`, avoiding leakage of Android device or user names.
  - The persistent 16-byte `rendezvous_token` (RAPP v26.10.1 §4.3) is **NEVER** published in mDNS records or instance names; it is transmitted strictly over the established point-to-point TCP stream during `Phase::Routing`.
  - TXT records publish `mode=pairing` (with the 16-byte ephemeral `offer_id`) during pairing, and `mode=session` (with optional 15-minute rotating HMAC discovery hints) during operational reconnection.
- **Stream Lifecycle**:
  1. User toggles `Allow Remote Reader` on Android.
  2. Android app binds ephemeral `ServerSocket(0)` and registers `NsdServiceInfo` with `NsdManager`.
  3. Desktop resolves phone's IP and port via mDNS.
  4. Desktop opens outbound TCP connection to phone.
  5. Workstation and phone execute authenticated RAPP handshake.

---

## 3. Privacy, Battery & Forensic Constraints

1. **Explicit Toggle Control**:
   - The phone does not broadcast BLE beacons or advertise mDNS services in background without user intent.
   - When the user leaves or disables "Allow Remote Reader", the `NsdManager` service is unregistered and `BluetoothLeAdvertiser.stopAdvertising` is invoked immediately.
2. **Auditability & Zero Secret Leakage**:
   - Strictly zero PIN data, candidate lengths, CAN values, or card authentication tokens are ever logged in Logcat, file dumps, or network traces.
