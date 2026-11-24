#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Build, install, and run Android instrumented tests on one selected device.

Unlike `./gradlew :app:connectedDebugAndroidTest`, this never depends on the
Gradle daemon or configuration cache carrying `ANDROID_SERIAL`: only the one
chosen device is touched, the app stays installed after the run, a failed APK
install always fails the script, and a failing, crashing, or zero-test
instrumentation run always exits non-zero.

Usage:
  Scripts/connected-test.py [--serial <serial> | --emulator | --wifi-phone] \\
    [--class <fqcn[#method]>]... [-e <key> <value>]... [--no-build]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

FAILURE_PATTERNS = re.compile(
    r'^(FAILURES!!!|INSTRUMENTATION_FAILED:|INSTRUMENTATION_ABORTED:|'
    r'INSTRUMENTATION_RESULT: shortMsg=|INSTRUMENTATION_STATUS: stack=|'
    r'INSTRUMENTATION_CODE: 0$)',
    re.MULTILINE,
)
ZERO_TESTS_RE = re.compile(r'^OK \(0 tests\)$')
PASSING_SUMMARY_RE = re.compile(r'^OK \([1-9][0-9]* tests?\)$')


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/connected-test.py',
        description='Run Android instrumented tests against exactly one target device.',
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
        '--class',
        dest='classes',
        action='append',
        default=[],
        metavar='FQCN[#METHOD]',
        help='Restrict instrumentation to the named test class or method (repeatable).',
    )
    parser.add_argument(
        '-e',
        dest='extra_args',
        nargs=2,
        action='append',
        default=[],
        metavar=('KEY', 'VALUE'),
        help='Additional AndroidJUnitRunner instrumentation argument (repeatable).',
    )
    parser.add_argument(
        '--no-build',
        action='store_true',
        help='Skip assembling APKs with Gradle and install existing debug APKs.',
    )
    args = parser.parse_args(argv)
    if args.serial is not None and not args.serial.strip():
        parser.error('--serial must be non-empty')
    for cls in args.classes:
        if not cls.strip():
            parser.error('--class must be non-empty')
    for key, _ in args.extra_args:
        if not key.strip():
            parser.error('-e KEY must be non-empty')
        if args.classes and key == 'class':
            parser.error("pass either --class or '-e class <value>', not both")
    return args


def resolve_target_serial(adb_bin: str, args: argparse.Namespace) -> str:
    attached = adb_ui.attached_devices(adb_bin)
    online = [serial for serial, state in attached if state == 'device']
    if args.serial:
        return adb_ui.verify_online(online, args.serial)
    if args.emulator:
        return adb_ui.select_one_device(online, adb_ui.EMULATOR_SERIAL_RE, 'running emulator')
    if args.wifi_phone:
        return adb_ui.select_one_device(online, adb_ui.WIFI_SERIAL_RE, 'phone on Wi-Fi debugging')
    env_serial = os.environ.get('ANDROID_SERIAL', '').strip()
    if env_serial:
        return adb_ui.verify_online(online, env_serial)
    if not attached:
        raise adb_ui.AdbError('no connected Android device found')
    # Refuse implicit selection whenever more than one target is attached
    # (including offline/unauthorized entries) so an offline emulator cannot
    # silently redirect a run to the custodian phone.
    if len(attached) > 1:
        raise adb_ui.AdbError(
            f'multiple Android devices attached ({len(attached)}); '
            'pass --serial <serial>, --emulator, or --wifi-phone'
        )
    if len(online) != 1:
        raise adb_ui.AdbError("target device is not online in 'adb devices'")
    return online[0]


def build_remote_instrument_command(
    classes: list[str],
    extra_args: list[list[str]],
) -> str:
    parts = ['am', 'instrument', '-w']
    if classes:
        parts.extend(['-e', 'class', shlex.quote(','.join(classes))])
    for key, value in extra_args:
        parts.extend(['-e', shlex.quote(key), shlex.quote(value)])
    parts.append(shlex.quote(adb_ui.TEST_RUNNER))
    return ' '.join(parts)


def verify_instrument_output(output: str, returncode: int) -> None:
    clean = output.replace('\r', '')
    if returncode != 0:
        raise adb_ui.AdbError(f'instrumentation command exited with status {returncode}')
    if FAILURE_PATTERNS.search(clean):
        raise adb_ui.AdbError('instrumented tests failed')
    non_empty = [line.strip() for line in clean.splitlines() if line.strip()]
    if not non_empty:
        raise adb_ui.AdbError('instrumented test output did not report a passing test summary')
    terminal = non_empty[-1]
    if ZERO_TESTS_RE.match(terminal):
        raise adb_ui.AdbError('instrumented run executed 0 tests; check --class and -e filters')
    if not PASSING_SUMMARY_RE.match(terminal):
        raise adb_ui.AdbError('instrumented test output did not report a passing test summary')


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = adb_ui.repo_root()
    os.chdir(root)

    try:
        adb_bin = adb_ui.resolve_adb()
        serial = resolve_target_serial(adb_bin, args)

        if not args.no_build:
            gradle_wrapper = os.environ.get('REFINEID_CONNECTED_TEST_GRADLE', 'Scripts/gradle.sh')
            build = subprocess.run(
                [gradle_wrapper, ':app:assembleDebug', ':app:assembleDebugAndroidTest'],
                check=False,
            )
            if build.returncode != 0:
                return build.returncode

        for apk in (adb_ui.APP_DEBUG_APK, adb_ui.TEST_DEBUG_APK):
            adb_ui.install_apk(adb_bin, serial, apk, allow_test=True)
            print(f'installed {apk.name}')

        remote_cmd = build_remote_instrument_command(args.classes, args.extra_args)
        collected: list[str] = []
        with subprocess.Popen(
            [adb_bin, '-s', serial, 'shell', remote_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ) as proc:
            assert proc.stdout is not None
            for line in proc.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                collected.append(line)
            returncode = proc.wait()

        verify_instrument_output(''.join(collected), returncode)
        return 0
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
