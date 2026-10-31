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
│         - Profile: fi.refineid.rapp.ble                                 │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ fallback (BLE unavailable or out-of-range)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Tier 3: Local IP Stream Discovery (mDNS / DNS-SD + Outbound TCP)        │
│         - IETF RFC 6762 (mDNS) & RFC 6763 (DNS-SD)                      │
│         - Android NsdManager registration: _refineid-stream._tcp.       │
│         - Phone acts as mDNS responder & TCP listener (ephemeral port)  │
│         - Workstation acts strictly as mDNS browser & outbound client   │
│         - Profile: fi.refineid.stream                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Tier 2: Bluetooth Low Energy Proximity (`fi.refineid.rapp.ble`)
- **Android Underlay**: `BluetoothManager.openGattServer` + `BluetoothLeAdvertiser.startAdvertising`, served beside the stream listener under the same gates (ADR 0043).
  - Service UUID: `7E39FD01-A6B5-4D78-9E11-37E28E9545F1`
  - Channel Characteristic: `7E39FD02-A6B5-4D78-9E11-37E28E9545F1` (`PROPERTY_WRITE | PROPERTY_INDICATE`, with its Client Characteristic Configuration descriptor)
  - Bootstrap Characteristic: `7E39FD03-A6B5-4D78-9E11-37E28E9545F1` (`PROPERTY_READ`; refuses reads, since pairing runs over the stream)
  - Framing: ATT MTU of at least 512 and the RAPP BLE SAR framing of RAPP v26.10.29 §5.3, segmented and reassembled by the shared engine.
- **No signal analysis**: Per RAPP v26.10.29 §4.4 no endpoint gates on RSSI; signal strength proves nothing against a transparent relay. Protection against unauthorized execution is provided at Layer 7 by the PINs the holder enters on the phone and the card verifies: PIN 1 once, then held in the phone's memory until the card leaves, and PIN 2 for every signature or batch.
- **Clarification on L2CAP CoC**:
  - `BluetoothGattServer` does not manage L2CAP channels. On Android 10+ (API 29+), Bluetooth Low Energy Connection-Oriented Channels (CoC) are managed via `BluetoothAdapter.listenUsingInsecureL2capChannel` / `listenUsingL2capChannel` (returning `BluetoothServerSocket`), with dynamic PSMs discovered via `serverSocket.getPsm()`.
  - Because public user-space APIs for BLE L2CAP CoC are not supported on all client platforms (such as Windows user-space), GATT-based `fi.refineid.rapp.ble` is the canonical cross-platform Tier 2 profile. Any future credit-based CoC profile would be a separate, distinct adaptation (`fi.refineid.rapp.ble-coc.v1`).
- **Zero OS Bonding**: No Android Bluetooth pairing dialogs or OS PIN passkeys; no characteristic asks for link-layer encryption, and a refusal is always `writeNotPermitted` (STPA CC-54, CC-73). Security is entirely provided by application-layer Noise cryptography (`Noise_XXpsk3` for pairing, `Noise_KK` for sessions).

### 2.2 Tier 3: Local IP Stream Discovery (`fi.refineid.stream`)
- **Discovery Service**: `_refineid-stream._tcp.` via Android `NsdManager.registerService`.
- **Ephemeral Port**: An ephemeral TCP `ServerSocket(0)` is bound on the local Wi-Fi interface.
- **Privacy (RFC 8882)**:
  - The service instance name MUST be a fresh, ephemeral random string generated on each registration: `refineid-[random_8_hex]._refineid-stream._tcp.local.`, preventing long-term device tracking across networks.
  - The SRV record target MUST use an anonymized, ephemeral host label: `refineid-[random_8_hex].local.`, avoiding leakage of Android device or user names.
  - No value that stays the same across connections is published or sent. Each session dial opens with a fresh 16-byte nonce and a routing tag keyed from the pairing's static agreement (RAPP v26.10.29 §2.2.1); the phone routes it with one `RappSessionRouter` per listener and refuses unknown or replayed tags without answering.
  - TXT records publish `mode=pairing` during pairing, `mode=session` with the rotating 15-minute discovery hints of the four most recently used pairings (built by `rappSessionRecord`) during operational reconnection, and `mode=withdrawn` when the user switches the service off.
- **Revocation** (RAPP v26.10.29 §4.6): forgetting a pairing with its session open closes the session as `pairing_revoked` and destroys the record. Without an open session the core marks the record forgotten: it leaves the list of paired devices but keeps its key, its discovery hint stays in the `mode=session` record and its routing tag still routes, and the next session carries only the `pairing_revoked` close, after which the key is destroyed. A forgotten record that kept its key for 30 days is destroyed untold at start.
- **Storage confirmation** (RAPP v26.10.29 §4.3 item 4): the custodian stores the unconfirmed pair record, sends `pairing.stored`, and stores the confirmed record over it only after the requester's `pairing.stored`; a record found unconfirmed at start, or left unconfirmed when the ceremony ends, is destroyed and nobody is told.
- **Card presence** (RAPP v26.10.29 §8.4): on every established session the custodian sends `card.status` once before any operation runs and again whenever the card it holds changes. A card in the USB reader from insertion until removal, and an NFC card from the holder adding it to the phone until the holder removes it there, is present and named by the SHA-256 fingerprint of its authentication certificate; an operation the card did not answer ends with `card_error` and leaves presence unchanged.
- **Withdrawal** (RAPP v26.10.29 §4.5): switching Remote Access off closes the open session with `service_withdrawn`, stops accepting connections, re-registers the same instance with the `rappWithdrawnRecord` TXT for three seconds, and then unregisters. The system suspending the app is not a withdrawal.
- **Stream Lifecycle**:
  1. User toggles `Allow Remote Reader` on Android.
  2. Android app binds ephemeral `ServerSocket(0)` and registers `NsdServiceInfo` with `NsdManager`.
  3. Desktop resolves phone's IP and port via mDNS.
  4. Desktop opens outbound TCP connection to phone.
  5. Workstation and phone execute authenticated RAPP handshake.

---

### 2.3 Android 17 Local Network Permission (`ACCESS_LOCAL_NETWORK`)
- Android 17 (API 37) gates the local network behind the runtime `ACCESS_LOCAL_NETWORK` permission for apps that target it. The gate sits in the networking stack: without the permission the system refuses the `NsdManager` registration of `_refineid-stream._tcp.` and blocks the stream's inbound connections, so the phone can neither be found nor reached over Wi-Fi. Earlier Androids grant the local network with `INTERNET` and know no such permission; the app asks for it only on Android 17 and later (`LocalNetworkPermission`).
- The permission belongs to the `NEARBY_DEVICES` group with `BLUETOOTH_ADVERTISE` and `BLUETOOTH_CONNECT`, so a holder who granted nearby devices is not prompted again.
- **When it is asked** (`RemoteAccessAction`): only when the holder turns Remote Access on, beside notifications and nearby devices. Opening the page, the app's start and the paired computers' sessions never ask.
- **Declined**: the phone serves over Bluetooth alone. The Remote Access page shows *Allow local network access* where the pairing code would be, with a retry that asks again; the debug trace records `rapp:offer-failed error=local_network_permission_missing`. A registration the system refuses while a listener starts is reported like a socket failure (`rapp:listener-failed error=registration_refused_<exception>`), never thrown at the caller.
- **Granted later**: the answer restarts the session listener and the pairing offer that waited for it.

## 3. Privacy, Battery & Forensic Constraints

1. **Explicit Toggle Control**:
   - The phone does not broadcast BLE beacons or advertise mDNS services in background without user intent.
   - When the user disables "Allow Remote Reader", the `NsdManager` service announces the withdrawal for three seconds and is then unregistered, and `BluetoothLeAdvertiser.stopAdvertising` is invoked immediately.
2. **Auditability & Zero Secret Leakage**:
   - Strictly zero PIN data, candidate lengths, CAN values, or card authentication tokens are ever logged in Logcat, file dumps, or network traces.
