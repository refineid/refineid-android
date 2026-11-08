# Tablet emulator on the local network

An Android tablet emulator on the Mac stands in for a computer in RAPP.
`RappDeviceRole` makes a device the custodian only when it has NFC and is
not a tablet (smallest width below sw600dp, or a foldable); the emulator
has neither NFC nor a phone-sized display, so it takes the requester
role. Paired with a physical phone holding a test card, it exercises
pairing, remote card use and in-app browser login over RAPP without a
hand on either device, with every PIN entered on the phone.

## Why bridged networking

The emulator's default networking is user-mode NAT. RAPP requesters find
custodians only through mDNS (`_refineid-stream._tcp`), and multicast
does not cross that NAT, so a NAT-ed emulator never sees the phone.

The Android Emulator on macOS can back its virtio Wi-Fi device with
Apple's `vmnet` framework in bridged mode. The tablet then joins the
Mac's local network as its own host, takes an address from the
network's DHCP server, and sends and receives mDNS like a physical
tablet.

## Start it

```bash
Scripts/start-tablet-emulator.sh [<host network interface>]
```

The script creates the `refineid_tablet` AVD on first use, starts it
bridged on the interface carrying the default route, waits for boot,
turns stylus handwriting off, and checks that `wlan0` landed on the
host interface's network under its subnet mask. It needs:

- The `system-images;android-35;google_apis_playstore_tablet;arm64-v8a`
  image. A Play image carries Google Play services, which passkeys in the
  WebView need.
- `sudo`. vmnet requires root or the `com.apple.vm.networking`
  entitlement, and the emulator binary does not carry the entitlement.
  The script asks for the password in the foreground before it starts
  the emulator in the background. Files the emulator writes as root land
  in `~/.android` (AVD state, metrics) and `/tmp/android-root` (crash
  reports).

Stop it with `Scripts/stop-tablet-emulator.sh`, which shuts the emulator
down and returns `~/.android` to the user.

The emulator command it runs:

```bash
sudo emulator -avd refineid_tablet \
  -feature -WiFiPacketStream \
  -vmnet-bridged <interface> \
  -no-snapshot -no-boot-anim
```

Observed with emulator 37.1.11 on Apple silicon:

- `-vmnet-bridged` alone leaves `wlan0` behind NAT: netsim's packet-streamed
  Wi-Fi (`WiFiPacketStream`) owns the virtio Wi-Fi device. Disabling that
  feature lets vmnet back `wlan0`.
- `-wifi-tap <name>` with `-vmnet-bridged` exits: the emulator opens
  `/dev/<name>` as a TAP device, which macOS does not provide.
- Emulated taps count as stylus input on the tablet image. With stylus
  handwriting on, the keyboard opens its stylus onboarding over the app
  and takes the text `adb shell input text` types.

## Pair it with the phone

```bash
Scripts/rapp-tablet-pair.sh [--phone <serial>] [--tablet <serial>]
```

The phone is the one device on Wi-Fi debugging (see
[test-devices.md](test-devices.md)) and holds a primed card. The script
opens Remote Access on the phone (bringing the running app to the front
rather than restarting it, so the phone keeps PIN 1 and its listener)
and turns Card Remote Access on, reads
the offered code from the screen into a variable, opens Remote Access on
the tablet, turns remote use on, types the code, and waits for the entry
to close. Progress goes to stdout and the last line is `paired`; it
exits non-zero with the tablet's failure reason, or when the pairing
does not finish within a minute. The code is never printed. Never run
it, or any script built on the helpers, under `bash -x`: xtrace prints
variables and arguments, the code among them.

Both scripts drive the UI through `Scripts/adb-ui.sh`, sourced helpers
that find nodes by Compose test tag (exposed as resource ids), tap them,
wait for them and read their state, and never print node text. They use
the SDK's `adb`, refuse to guess when more than one phone or emulator is
connected, and delete the dump file from the device after reading it.
New device scripts reuse them, and a node a script needs gets a test tag
in `UiAutomationIds` rather than a match on localised text. Two limits
of `uiautomator dump` shape the pairing script:

- The pairing code field, a fully transparent `BasicTextField` over six
  boxes, did not appear in the dump. The script taps the boxes
  (`pairingCodeBoxes`) to focus it.
- The boxes clear their semantics, so they cannot confirm what was
  typed; the outcome (`pairingFailure`, or the boxes gone) does.

## Log in from the tablet's browser

```bash
Scripts/rapp-tablet-browser-login.sh [--url <https url>]
```

With the tablet paired, the script opens the in-app browser on the
tablet, loads the URL (by default a public service that requests a
client certificate from any issuer) and judges the TLS handshake from
the debug build's `browser:` traces: the client-certificate request,
its completion and the signature status. It prints the traces, which
carry only enum values and counts, and ends with `logged in`. It never
prints page content, which can carry the certificate subject.

- The card signs on the phone, so it lies on the phone's NFC reader for
  the whole run. When the phone asks for the card (`RappCardTapMessage`)
  or for PIN 1 (`rappPinField`), the script says so and waits for the
  holder. With the card present and PIN 1 held on the phone, the
  signature goes through without a prompt. Without the card the phone
  waits and the tablet's signature ends in `ERROR` after a minute.
- A PIN or CAN field on the tablet fails the run: a remote login never
  asks the requester for a secret (AGENTS.md RULE #1).
- The default service does not trust the Finnish card root, so its page
  reports the chain as unverified while it still receives the card's
  certificate; the script's verdict is the handshake, not the page.

Keep hands off the emulator while a script drives it. Touches on the
emulator window can switch the tablet into desktop windowing and bring
other apps' windows over RefineID, and the scripts' taps then land in
the wrong window. `Scripts/stop-tablet-emulator.sh` and a fresh start
restore a known state.

## Build signing

The main checkout signs debug builds with the key named in its
untracked `keystore.properties`; a worktree without that file signs with
the SDK debug key. A device holding a build from one cannot update to a
build from the other (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`), and
uninstalling clears its pairings and primed CAN. Keep the custodian phone
on builds from one origin; the tablet can be uninstalled freely.

## Instrumented tests

`connectedDebugAndroidTest` installs and runs on every connected device,
including the custodian phone; it did not honour `ANDROID_SERIAL` here.
Run instrumented tests on the tablet alone with adb:

```bash
Scripts/gradle.sh :app:assembleDebug :app:assembleDebugAndroidTest
adb -s emulator-5554 install -r -t app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s emulator-5554 shell am instrument -w -e class <test class> \
  fi.refineid.android.test/androidx.test.runner.AndroidJUnitRunner
```

## Secrets and screenshots

- Pairing codes, CANs and PINs stay on the devices. Scripts read them
  into variables and type them; they never echo them.
- Node dumps of the phone can carry the holder's name. Print test tags,
  not node text.
- Artemis sends screenshots to its model provider. Point it at the tablet
  only (`--serial emulator-5554`), never at the custodian phone while a
  CAN, PIN, pairing code or holder name can be on screen. Pass
  `ARTEMIS_HOME=<checkout>` when Artemis is not cloned beside this
  repository or in `~/src/artemis`.

## What it does not cover

- NFC and USB card transports: the emulator has neither. Card exchanges
  are verified on physical phones.
- Requester discovery through a real tablet's or computer's Wi-Fi stack.
- Android 17 local-network permission: the tablet image is API 35.
