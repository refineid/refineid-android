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
host's local subnet. It needs:

- The `system-images;android-35;google_apis_playstore_tablet;arm64-v8a`
  image. A Play image carries Google Play services, which passkeys in the
  WebView need.
- `sudo`. vmnet requires root or the `com.apple.vm.networking`
  entitlement, and the emulator binary does not carry the entitlement.
  Files the emulator writes as root, such as crash reports under
  `/tmp/android-root`, are owned by root.

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
opens Remote Access on the phone and turns Card Remote Access on, reads
the offered code from the screen into a variable, opens Remote Access on
the tablet, turns remote use on, types the code, and waits for the entry
to close. It exits non-zero with the tablet's failure reason, or when
the pairing does not finish within a minute. The code is never printed.

Both scripts drive the UI through `Scripts/adb-ui.sh`, sourced helpers
that find nodes by Compose test tag (exposed as resource ids), tap them,
wait for them and read their state, and never print node text. New
device scripts reuse them. Two limits of `uiautomator dump` shape them:

- A fully transparent node is left out of the dump. The pairing code
  field is a transparent `BasicTextField` over six boxes, so the script
  taps the boxes, the node after the field's label, to focus it.
- Nodes under `clearAndSetSemantics` expose no text, so the code boxes
  cannot confirm what was typed; the outcome screen does.

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
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
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
