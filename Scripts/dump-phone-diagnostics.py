#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Trigger and print or clear plaintext diagnostics on one Android debug target.

Uses `adb_ui` for SDK `adb` lookup and strict single-device targeting so
multiple attached devices (such as a bridged tablet emulator and a phone)
never silently target the wrong device, and never prints device serials or
IP addresses to stdout or stderr.

Usage:
  Scripts/dump-phone-diagnostics.py [--clear] [--serial <serial> | --emulator | --wifi-phone | <serial>]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

ACTION_DUMP_DIAGNOSTICS = f'{adb_ui.APP_PACKAGE}.DUMP_DIAGNOSTICS'
ACTION_CLEAR_LOGS = f'{adb_ui.APP_PACKAGE}.CLEAR_LOGS'
DIAGNOSTICS_REL_PATH = 'files/diagnostics.txt'
CLEAR_BROADCAST_OK_RE = re.compile(
    r'^Broadcast completed:\s*result=0,\s*data="LOGS_CLEARED"$',
    re.MULTILINE,
)
DUMP_BROADCAST_OK_RE = re.compile(
    r'^Broadcast completed:\s*result=0,\s*data="DUMP_OK:',
    re.MULTILINE,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/dump-phone-diagnostics.py',
        description='Dump or clear RefineID debug diagnostics on exactly one target Android device.',
    )
    parser.add_argument(
        '--clear',
        action='store_true',
        help='Clear diagnostics and trace logs on the selected device instead of dumping them.',
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument('--serial', '-s', help='Target the named online adb serial.')
    target.add_argument(
        '--emulator',
        action='store_true',
        help='Target the single running emulator (emulator-*).',
    )
    target.add_argument(
        '--wifi-phone',
        action='store_true',
        help='Target the single phone on Wi-Fi debugging.',
    )
    parser.add_argument(
        'device',
        nargs='?',
        default=None,
        help='Optional positional online adb serial (cannot be combined with --serial/--emulator/--wifi-phone).',
    )
    args = parser.parse_args(argv)
    if args.serial is not None:
        args.serial = args.serial.strip()
        if not args.serial:
            parser.error('--serial must be non-empty')
    if args.device is not None:
        args.device = args.device.strip()
        if not args.device:
            parser.error('device serial must be non-empty')
        if args.serial is not None or args.emulator or args.wifi_phone:
            parser.error('pass either a positional device serial or a target flag, not both')
    return args


def resolve_target_serial(adb_bin: str, args: argparse.Namespace) -> str:
    attached = adb_ui.attached_devices(adb_bin)
    online = [serial for serial, state in attached if state == 'device']
    explicit = args.serial if args.serial is not None else args.device
    if explicit is not None:
        return adb_ui.verify_online(online, explicit)
    if args.emulator:
        return adb_ui.select_one_device(online, adb_ui.EMULATOR_SERIAL_RE, 'running emulator')
    if args.wifi_phone:
        return adb_ui.select_one_device(online, adb_ui.WIFI_SERIAL_RE, 'phone on Wi-Fi debugging')
    env_serial = os.environ.get('ANDROID_SERIAL', '').strip()
    if env_serial:
        return adb_ui.verify_online(online, env_serial)
    if not attached:
        raise adb_ui.AdbError('no connected Android device found')
    # Refuse implicit targeting whenever more than one entry is attached
    # (including offline/unauthorized entries) so --clear cannot silently hit
    # the wrong device.
    if len(attached) > 1:
        raise adb_ui.AdbError(
            f'multiple Android devices attached ({len(attached)}); '
            'pass --serial <serial>, --emulator, or --wifi-phone'
        )
    if len(online) != 1:
        raise adb_ui.AdbError("target device is not online in 'adb devices'")
    return online[0]


def send_diagnostics_broadcast(
    adb_bin: str,
    serial: str,
    action: str,
    expected_pattern: re.Pattern[str],
    *,
    operation: str,
) -> None:
    """Send an ordered broadcast and require `result=0` plus the receiver ack.

    `DiagnosticsDumpReceiver.onReceive` writes `files/diagnostics.txt`
    synchronously before returning `resultData`, so observing the matched
    completion line guarantees the file write has finished before `run-as cat`.
    """
    result = adb_ui.run_adb(
        adb_bin,
        ['shell', 'am', 'broadcast', '-a', action, '-p', adb_ui.APP_PACKAGE],
        serial=serial,
        operation=operation,
    )
    clean = result.stdout.replace('\r', '')
    if not expected_pattern.search(clean):
        raise adb_ui.AdbError(
            f'{operation} broadcast was not handled (is the debug build installed?)'
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    try:
        adb_bin = adb_ui.resolve_adb()
        serial = resolve_target_serial(adb_bin, args)

        if args.clear:
            print('Clearing diagnostics and trace logs on selected device...', file=sys.stderr)
            send_diagnostics_broadcast(
                adb_bin,
                serial,
                ACTION_CLEAR_LOGS,
                CLEAR_BROADCAST_OK_RE,
                operation='clear logs',
            )
            print('Logs cleared.', file=sys.stderr)
            return 0

        send_diagnostics_broadcast(
            adb_bin,
            serial,
            ACTION_DUMP_DIAGNOSTICS,
            DUMP_BROADCAST_OK_RE,
            operation='dump diagnostics',
        )
        dump = adb_ui.run_adb(
            adb_bin,
            ['shell', 'run-as', adb_ui.APP_PACKAGE, 'cat', DIAGNOSTICS_REL_PATH],
            serial=serial,
            operation='read diagnostics',
        )
        sys.stdout.write(dump.stdout)
        sys.stdout.flush()
        return 0
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
