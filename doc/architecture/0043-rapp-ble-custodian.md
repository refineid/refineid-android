# ADR 0043: RAPP custodian over Bluetooth LE

## Status

Accepted.

## Context

A paired computer reaches the phone over the local network (`fi.refineid.stream`,
ADR 0041) while it sees the phone's DNS-SD record. With the screen off or in
power saving, the record can stay out of sight, and a Mac requester then dials
Bluetooth (`fi.refineid.rapp.ble`, RAPP v26.10.29 section 5). The phone must
answer there too, also with RefineID in the background. A stored pairing serves
any registered transport (section 2.1, phase 4), so Bluetooth needs no pairing
of its own and no link-layer bond.

## Decision

- **GATT server.** `RappBleGattServer` opens one `BluetoothGattServer` and adds
  the RAPP service once: the channel characteristic (write, indicate, with its
  Client Characteristic Configuration descriptor) and the bootstrap
  characteristic (read). Every permission is a plain read or write: no
  characteristic asks for encryption or authentication, so no computer's
  system ever asks to bond (STPA CC-54). The bootstrap characteristic refuses
  reads: pairing happens over the stream.
- **Advertising.** While the phone serves, it advertises the service UUID
  alone: connectable, no device name, no power level, nothing derived from a
  pairing (section 4.1). The platform picks the advertising address; with LE
  privacy on, Android's default, it is a resolvable private address that
  rotates, as section 4.1 asks (not yet observed). A failure for want of
  advertising sets, or an internal error, is retried after 30 seconds.
- **Links.** `RappBleGattLinks` keeps one link per central from the moment it
  enables indications. The link reads the ATT MTU negotiated by then and starts
  closed below 512 (section 5.2 step 1). Its first frame is the routing
  preamble; later frames go to the session. Fragments are reassembled and
  segmented by the engine (`RappBleSarReassembler`, `rappBleSarSegment`), with
  one indication in flight per central. A refused preamble, a refused
  fragment, a write before the subscription and a write on a closed link are
  answered `writeNotPermitted`, never an authentication or encryption error
  (CC-73). A closed link refuses writes until its central unsubscribes or
  disconnects. A link the phone closes first indicates the frames it already
  queued, for at most two seconds, so a closing message such as
  `pairing_revoked` or `service_withdrawn` still reaches the computer.
- **Routing.** One `RappSessionRouting` serves both transports: a preamble
  routes only on the transport whose domain it carries (`rapp-ble` or
  `rapp-stream`, section 2.2.1), and a nonce routed on either is refused on
  both. The pre-authentication limiter (section 3.3 item 6) is shared too.
- **One session.** The phone serves one session at a time, whichever transport
  carries it (CC-67). `RappSessionAdmission` admits a routed dial when no
  session is open; never while the open one is coming up or carries an
  operation (UCA-66); at once when the open one is idle and of the same
  pairing, the same computer coming back on the other transport; and for
  another pairing only after the open session idled for five seconds. An
  admitted dial ends the idle session and closes its transport. A routed
  Bluetooth link has ten seconds to complete `Noise_KK`, the stream listener's
  bound. Every open session gets `card.status` with the reader (CC-81).
- **Lifecycle.** The server starts and stops with the stream listener, under
  the same gates: Remote Access on and a custodian pairing to serve. Turning
  Remote Access off stops the advertisement at once, closes the open session
  with `service_withdrawn` on either transport, and closes the server with the
  stream withdrawal (section 4.5; the advertisement carries no withdrawal). The
  server follows the radio: Bluetooth turning off ends every link, turning on
  publishes and advertises again.
- **Background.** The server lives in the process `RappCustodianService` keeps
  in the foreground-service state (ADR 0040). The process is not cached, so the
  freezer leaves it running; Doze defers alarms, jobs and network access, none
  of which the server uses; the advertisement runs in the Bluetooth controller
  and GATT requests reach the process over binder from the Bluetooth service.
  Stream and Bluetooth both keep serving with the screen off.
- **Permissions.** Android 12 and newer require `BLUETOOTH_ADVERTISE` and
  `BLUETOOTH_CONNECT` (one "Nearby devices" prompt). RefineID asks for them,
  together with notifications, only when the holder turns Remote Access on,
  beside the card access number rule (`remoteAccessPermissions`). Opening the
  page and starting the app ask nothing. Declined, the phone serves over the
  stream alone; nothing nags, and a debug build traces it.
- **Diagnostics.** Debug builds trace every server step and link event, and
  write each failure as a `rapp:error` line: the server not published,
  advertising failures with their code, Bluetooth off or unsupported, the
  permission missing or declined, a link closed with its cause (MTU below 512
  with the value, routing refused, reassembly, protocol violation, indication
  failure), and each dial refused with why (no pairing, busy, held, rate
  limited, handshake deadline). Release builds carry none of it.

## Verification

JVM tests drive the link state machine against a fake platform with the
engine's SAR (`RappBleGattLinksTest`), the admission rule
(`RappSessionAdmissionTest`), Bluetooth routing (`RappSessionDiscoveryTest`)
and the permission rule (`RemoteAccessActionTest`).

Not yet observed on hardware: a Mac's scan seeing the advertisement, the
negotiated MTU between a Mac central and an Android peripheral, and a login over
Bluetooth with the phone's screen off.

## Consequences

- An existing installation serves over Bluetooth once the holder turns Remote
  Access off and on again, which asks for the permission.
- One session at a time keeps a second computer waiting while one holds the
  phone, as the stream already did; serving every computer at once (STPA
  section 21) needs the dispatcher's session state split per session.
