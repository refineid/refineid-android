---
name: android-tablet-testing
description: Test RefineID Android on a bridged tablet emulator paired over RAPP with the physical custodian phone, without a hand on either device. Use when testing RAPP pairing, remote card use, the in-app browser on a tablet or requester, tablet layouts, or when asked to run the app in the emulator or drive it with scripts or Artemis.
---

# Android tablet testing

The full setup, its reasons and its limits are in
`doc/process/tablet-emulator.md`; read it before changing the scripts.
This is the run order.

## 1. Start the tablet

```bash
Scripts/start-tablet-emulator.sh
```

Runs the emulator under `sudo`, bridged onto the Mac's network. It ends
with "wlan0 is on the host's local network"; anything else is a failure
to fix before going on. Stop it with `Scripts/stop-tablet-emulator.sh`.

## 2. Install builds

- Tablet: `Scripts/install-device.sh emulator-5554`.
- Phone: `Scripts/install-device.sh <wifi serial>`, only from the same
  checkout origin as the build already on it (main checkout or worktree);
  a signature mismatch means uninstalling, which clears its pairings and
  primed CAN. Ask the owner before uninstalling on the phone.
- Read the build number at the foot of each home screen before judging
  behaviour.

## 3. Pair

```bash
Scripts/rapp-tablet-pair.sh
```

Needs a primed card on the phone. The last line is `paired`, or it
exits non-zero with the tablet's failure reason. Never run it under
`bash -x`; xtrace would print the pairing code.

## 4. Log in from the browser

```bash
Scripts/rapp-tablet-browser-login.sh [--url <https url>]
```

Ends with `logged in` when the card on the phone signed the tablet's TLS
handshake. If it prints "phone: enter PIN 1 on the phone", ask the owner to do
so; never type a PIN. Ask the owner to keep hands off the emulator while
scripts run.

## 5. Drive and check

- Source the helpers from bash (`bash -c 'source Scripts/adb-ui.sh; ...'`);
  under zsh `BASH_REMATCH` is empty and taps fail.
- Write further flows as scripts that source `Scripts/adb-ui.sh`: find
  nodes by test tag (`ui_tap`, `ui_wait`, `ui_has`, `ui_checked`,
  `ui_tags`), read values into variables with `ui_text`, never print
  node text.
- Add a missing test tag to the app rather than tapping coordinates or
  localised text.
- When a flow breaks, look at the tablet:
  `adb -s emulator-5554 shell screencap -p /sdcard/s.png` then
  `adb -s emulator-5554 pull /sdcard/s.png <local path>`; the tablet
  holds no secrets. Do not capture the phone while a CAN, PIN,
  pairing code or holder name can be on screen.
- Artemis: `ARTEMIS_HOME=<checkout> Scripts/test-artemis.sh custom "<goal>" --serial emulator-5554`.
  Tablet only.
- Instrumented tests: run on the tablet alone with `adb shell am
  instrument` as the doc shows; `connectedDebugAndroidTest` also reaches
  the phone.
- Read the debug error sink and traces with
  `adb -s emulator-5554 logcat -d | grep " RefineID:"`.

## Rules that bind here

- Every PIN is entered on the phone, never typed by a script on the
  tablet or sent anywhere (AGENTS.md RULE #1, RULE #2).
- No addresses, serials, names or codes in commits, docs, issues or
  transcripts; mask them in command output.
- A bug found on the tablet gets a regression test that fails without
  the fix, in its own worktree and pull request.
