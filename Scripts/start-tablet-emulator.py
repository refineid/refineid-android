#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Start a bridged macOS Android tablet emulator for RAPP requester testing.

Usage:
  Scripts/start-tablet-emulator.py [<host network interface>]

The interface defaults to the one carrying the Mac's default route. The
emulator runs under sudo: vmnet bridged mode needs root because the emulator
binary does not carry the com.apple.vm.networking entitlement.
See doc/process/tablet-emulator.md.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

AVD_NAME = adb_ui.AVD_NAME
API_LEVEL = 'android-35'
IMAGE_TAG = 'google_apis_playstore_tablet'
IMAGE_ABI = 'arm64-v8a'
BOOT_POLL_SECONDS = 5.0
BOOT_POLL_LIMIT = 120


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/start-tablet-emulator.py',
        description='Start the bridged Android tablet emulator on the local network.',
    )
    parser.add_argument(
        'interface',
        nargs='?',
        help='Host network interface to bridge onto (default: default-route interface).',
    )
    return parser.parse_args(argv)


def default_route_interface() -> str:
    result = subprocess.run(
        ['route', 'get', 'default'],
        text=True,
        capture_output=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith('interface:'):
            return stripped.split(':', 1)[1].strip()
    return ''


def ensure_avd_created(avd_home: Path, image_dir: str) -> bool:
    """Create `refineid_tablet` AVD files if absent; write config.ini before the marker .ini."""
    ini_path = avd_home / f'{AVD_NAME}.ini'
    avd_dir = avd_home / f'{AVD_NAME}.avd'
    config_path = avd_dir / 'config.ini'
    if ini_path.is_file() and config_path.is_file():
        return False
    avd_dir.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        f'AvdId={AVD_NAME}\n'
        'avd.ini.displayname=RefineID Tablet\n'
        f'abi.type={IMAGE_ABI}\n'
        'hw.cpu.arch=arm64\n'
        'hw.cpu.ncore=4\n'
        'hw.ramSize=4096\n'
        'disk.dataPartition.size=8G\n'
        f'image.sysdir.1={image_dir}/\n'
        'tag.id=google_apis_playstore\n'
        'tag.ids=google_apis_playstore,tablet\n'
        'PlayStore.enabled=true\n'
        'hw.device.name=pixel_tablet\n'
        'hw.device.manufacturer=Google\n'
        'hw.lcd.width=2560\n'
        'hw.lcd.height=1600\n'
        'hw.lcd.density=320\n'
        'hw.initialOrientation=landscape\n'
        'hw.keyboard=yes\n'
        'hw.gpu.enabled=yes\n'
        'hw.gpu.mode=auto\n'
        'showDeviceFrame=no\n',
        encoding='utf-8',
    )
    ini_path.write_text(
        f'avd.ini.encoding=UTF-8\npath={avd_dir}\ntarget={API_LEVEL}\n',
        encoding='utf-8',
    )
    return True


def same_ipv4_network(host_address: str, host_mask: str, guest_address: str) -> bool:
    """Return True if `guest_address` shares `host_address`'s IPv4 subnet under `host_mask`."""
    try:
        network = ipaddress.IPv4Network(f'{host_address}/{host_mask}', strict=False)
        guest = ipaddress.IPv4Address(guest_address)
    except ValueError:
        return False
    return guest in network


def parse_wlan0_ipv4(ip_addr_output: str) -> str:
    """Extract the IPv4 address from `ip -4 -o addr show wlan0` output."""
    for line in ip_addr_output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == 'inet':
            return parts[3].split('/', 1)[0].strip()
    return ''


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    os.chdir(adb_ui.repo_root())

    if platform.system() != 'Darwin':
        print('vmnet bridging is macOS only', file=sys.stderr)
        return 1

    try:
        emu_home = adb_ui.emulator_home()
        sdk = adb_ui.sdk_root()
        avd_home = adb_ui.avd_home(emu_home)
        emulator_bin = sdk / 'emulator' / 'emulator'
        image_dir = f'system-images/{API_LEVEL}/{IMAGE_TAG}/{IMAGE_ABI}'

        if not (emulator_bin.is_file() and os.access(emulator_bin, os.X_OK)):
            raise adb_ui.AdbError(f'Android emulator not found under {sdk}')
        if not (sdk / image_dir).is_dir():
            package = image_dir.replace('/', ';')
            raise adb_ui.AdbError(f'System image missing: install {package} with sdkmanager')

        interface = args.interface or default_route_interface()
        if not interface:
            raise adb_ui.AdbError('No host network interface given and no default route found')

        adb_bin = adb_ui.resolve_adb()
        if adb_ui.find_avd_emulator(adb_bin, AVD_NAME) is not None:
            raise adb_ui.AdbError(f'{AVD_NAME} is already running; stop it first')

        if ensure_avd_created(avd_home, image_dir):
            print(f'created AVD {AVD_NAME}')

        # Ask for the password now, in the foreground; the emulator then starts in
        # the background in the same session so terminal-scoped sudo credentials
        # remain valid for `sudo -n` while `stdin=DEVNULL` prevents TTY reads.
        sudo_bin = os.environ.get('REFINEID_SUDO', 'sudo')
        if subprocess.run([sudo_bin, '-v'], check=False).returncode != 0:
            return 1

        # Netsim's packet-streamed Wi-Fi otherwise owns the virtio Wi-Fi device and
        # keeps wlan0 behind user-mode NAT; with it disabled, vmnet backs wlan0.
        # Create the log atomically so an existing symlink in the shared temp
        # directory cannot redirect writes to an unrelated file.
        with tempfile.NamedTemporaryFile(
            mode='wb',
            prefix=f'{AVD_NAME}-emulator-',
            suffix='.log',
            delete=False,
        ) as log_file:
            log_path = Path(log_file.name)
            proc = subprocess.Popen(
                [
                    sudo_bin,
                    '-n',
                    'env',
                    f'HOME={Path.home()}',
                    f'ANDROID_SDK_ROOT={sdk}',
                    f'ANDROID_AVD_HOME={avd_home}',
                    f'ANDROID_EMULATOR_HOME={emu_home}',
                    str(emulator_bin),
                    '-avd',
                    AVD_NAME,
                    '-feature',
                    '-WiFiPacketStream',
                    '-vmnet-bridged',
                    interface,
                    '-no-snapshot',
                    '-no-boot-anim',
                ],
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )

        print(f'starting {AVD_NAME} bridged on {interface}; log: {log_path}')
        booted = False
        serial: str | None = None
        for _ in range(BOOT_POLL_LIMIT):
            if proc.poll() is not None:
                raise adb_ui.AdbError(f'emulator exited during boot; see {log_path}')
            try:
                serial = adb_ui.find_avd_emulator(adb_bin, AVD_NAME, timeout=BOOT_POLL_SECONDS)
            except adb_ui.AdbError:
                serial = None
            if serial is not None:
                try:
                    prop = adb_ui.run_adb(
                        adb_bin,
                        ['shell', 'getprop', 'sys.boot_completed'],
                        serial=serial,
                        operation='boot check',
                        timeout=BOOT_POLL_SECONDS,
                        check=False,
                    )
                except adb_ui.AdbError:
                    prop = None
                if prop is not None and prop.stdout.strip().replace('\r', '') == '1':
                    booted = True
                    break
            time.sleep(BOOT_POLL_SECONDS)

        if not booted or serial is None:
            raise adb_ui.AdbError(f'emulator did not finish booting; see {log_path}')

        # Emulated touches count as stylus input on the tablet image, and the
        # keyboard's stylus onboarding would take text that adb types.
        adb_ui.run_adb(
            adb_bin,
            ['shell', 'settings', 'put', 'secure', 'stylus_handwriting_enabled', '0'],
            serial=serial,
            operation='stylus setting',
        )

        host_address = subprocess.run(
            ['ipconfig', 'getifaddr', interface],
            text=True,
            capture_output=True,
            check=False,
        ).stdout.strip()
        host_mask = subprocess.run(
            ['ipconfig', 'getoption', interface, 'subnet_mask'],
            text=True,
            capture_output=True,
            check=False,
        ).stdout.strip()
        guest_output = adb_ui.run_adb(
            adb_bin,
            ['shell', 'ip', '-4', '-o', 'addr', 'show', 'wlan0'],
            serial=serial,
            operation='wlan0 address check',
            check=False,
        ).stdout
        guest_address = parse_wlan0_ipv4(guest_output)

        if same_ipv4_network(host_address, host_mask, guest_address):
            print(f"{AVD_NAME} booted; wlan0 is on the host's local network")
            return 0
        raise adb_ui.AdbError(
            f"{AVD_NAME} booted, but wlan0 is not on the host's local network; see {log_path}"
        )
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
