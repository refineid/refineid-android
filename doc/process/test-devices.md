# Test devices

The test phone is reached over Wi-Fi debugging, always. Its one USB-C
port carries the card reader whenever a reader is under test, so the
cable to the Mac comes and goes, and a command addressed to the cable's
serial hangs on "waiting for device" the moment a reader is plugged in.

- When the phone is attached over USB, set up Wi-Fi debugging at once:
  `adb tcpip 5555`, then `adb connect <address>:5555`. The address is the
  phone's on the local network and is not written down here.
- Address the phone by its Wi-Fi serial (`<address>:5555`) for installs,
  logs and screenshots from then on. `Scripts/install-device.sh` prefers
  a Wi-Fi device when no serial is given.
- Before judging what the phone shows, read the build number at the foot
  of the home screen; an install that never reached the phone leaves the
  previous build running.
- A debug build can be captured with `adb exec-out screencap`; a release
  build sets the secure window flag and captures black. A black capture
  of a debug build means the screen was off or locked.
