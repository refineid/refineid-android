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
│ Tier 2: Bluetooth Low Energy Proximity (BLE L2CAP CoC)                  │
│         - Cross-platform proximity-gated link (Android, Linux, Win, Mac)│
│         - Android BluetoothGattServer / L2CAP Channel (API 29+)         │
│         - RSSI threshold gating (>= -70 dBm) to defeat relay attacks    │
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
- **Android Underlay**: `BluetoothLeAdvertiser` + `BluetoothGattServer` opened via `BluetoothManager.openGattServer`.
- **L2CAP CoC**: Uses `BluetoothGattServer.openL2capChannel` (introduced in Android 10 / API 29) to assign a dynamic Protocol/Service Multiplexer (PSM) and receive binary streams.
- **Physical Proximity Gating**: Requester monitors RSSI and enforces a threshold of at least $-70\text{ dBm}$, guaranteeing that the phone is immediately adjacent to the laptop.
- **Zero OS Bonding**: No Android Bluetooth pairing dialogs or OS PIN passkeys. Security is entirely provided by application-layer Noise cryptography (`Noise_XXpsk3` for pairing, `Noise_KK` for sessions).

### 2.2 Tier 3: Local IP Stream Discovery (`fi.refineid.stream.v1`)
- **Discovery Service**: `_refineid-stream._tcp.` via Android `NsdManager.registerService`.
- **Ephemeral Port**: An ephemeral TCP `ServerSocket(0)` is bound on Wi-Fi interface.
- **Privacy (RFC 8882)**: The service instance name does not publish IMEI, Android build serials, MAC addresses, or personal usernames. The instance name is derived deterministically from the pairing rendezvous token.
- **Stream Lifecycle**:
  1. User toggles `Allow Remote Reader` on Android.
  2. Android app binds ephemeral `ServerSocket` and registers `NsdServiceInfo` with `NsdManager`.
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
