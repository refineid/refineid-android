#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Execute autonomous multimodal ARTEMIS test suites against one Android device.

Supported suites:
  smoke       - Verify app launch, main navigation, and hardware diagnostics
  browser     - Test in-app browser harness and authentication controls
  signing     - Test document signing UI, format toggles, and status cards
  management  - Test card management views, attempt banners, and task modes
  rapp        - Test RAPP pairing switch, offer generation, and timers
  doctor      - Run Artemis system diagnostics and readiness checks
  ui          - Launch the Artemis web test console
  custom      - Execute an arbitrary natural-language test goal

Usage:
  Scripts/test-artemis.py [suite] [--serial <serial>] [--profile <flash|pro>]
  Scripts/test-artemis.py custom "<natural language goal>" [--serial <serial>]
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

SUITE_GOALS: dict[str, str] = {
    'smoke': (
        'Open the RefineID app (package fi.refineid.android), verify the main screen loads, '
        'dismiss any initial system permission popups, navigate into Diagnostics, inspect the '
        'NFC and USB reader status lines, and navigate back to the main screen.'
    ),
    'browser': (
        'Open the RefineID app (package fi.refineid.android), tap the Browser row to open the '
        'in-app browser harness, verify the URL address bar, back, forward, and reload buttons '
        'are visible and active, then navigate back to the main screen.'
    ),
    'signing': (
        'Open the RefineID app (package fi.refineid.android), tap the Sign row to enter the '
        'Document Signing screen, verify the document selection button, format switch (PDF vs '
        'ASiC container), and PIN2 entry fields are rendered, then navigate back.'
    ),
    'management': (
        'Open the RefineID app (package fi.refineid.android), navigate to Card Management, '
        'verify the card status overview, task selector (Change PIN, Reset PIN, Activate Card), '
        'and attempt counters, then return to home.'
    ),
    'rapp': (
        'Open the RefineID app (package fi.refineid.android), locate the Remote Access card on '
        'the home screen, toggle the remote access switch, verify the CPACE pairing offer and '
        'countdown timer appear, then toggle it off.'
    ),
}
ALL_SUITES = (*SUITE_GOALS.keys(), 'doctor', 'ui', 'custom')
DEFAULT_SUITE = 'smoke'
DEFAULT_PROFILE = 'flash'


def resolve_artemis_dir(repo_root: Path) -> Path | None:
    env_dir = os.environ.get('ARTEMIS_HOME', '').strip()
    if env_dir:
        candidate = Path(env_dir).expanduser().resolve()
        return candidate if candidate.is_dir() else None
    for candidate in (repo_root.parent / 'artemis', Path.home() / 'src' / 'artemis'):
        if candidate.is_dir():
            return candidate.resolve()
    return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/test-artemis.py',
        description='Run ARTEMIS multimodal suites against a single Android target.',
    )
    parser.add_argument(
        'suite',
        nargs='?',
        default=DEFAULT_SUITE,
        choices=ALL_SUITES,
        help=f'Suite to run (default: {DEFAULT_SUITE}).',
    )
    parser.add_argument(
        'custom_goal',
        nargs='?',
        default='',
        help='Natural-language goal string (required when suite is custom).',
    )
    parser.add_argument('--serial', '-s', help='Target online adb device serial.')
    parser.add_argument(
        '--profile',
        '-p',
        default=DEFAULT_PROFILE,
        help=f'ARTEMIS execution profile (default: {DEFAULT_PROFILE}).',
    )
    args = parser.parse_args(argv)
    if args.suite == 'custom' and not args.custom_goal.strip():
        parser.error("'custom' suite requires a goal description string")
    if args.suite != 'custom' and args.custom_goal:
        parser.error(f'unexpected positional argument: {args.custom_goal}')
    if args.serial is not None and not args.serial.strip():
        parser.error('--serial must be non-empty')
    return args


def resolve_serial(adb_bin: str, explicit: str | None) -> str:
    attached = adb_ui.attached_devices(adb_bin)
    online = [serial for serial, state in attached if state == 'device']
    chosen = explicit or os.environ.get('ANDROID_SERIAL', '').strip()
    if chosen:
        return adb_ui.verify_online(online, chosen)
    if not attached:
        raise adb_ui.AdbError('no connected Android device found via adb')
    if len(attached) > 1:
        raise adb_ui.AdbError(
            f'multiple Android devices attached ({len(attached)}); '
            'pass --serial <serial> so ARTEMIS never targets the custodian phone by accident'
        )
    if len(online) != 1:
        raise adb_ui.AdbError("target device is not online in 'adb devices'")
    return online[0]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = adb_ui.repo_root()
    artemis_dir = resolve_artemis_dir(root)
    if artemis_dir is None:
        print('Error: Artemis repository not found.', file=sys.stderr)
        print('Please set ARTEMIS_HOME or clone Artemis into ~/src/artemis', file=sys.stderr)
        return 1

    uv_bin = os.environ.get('REFINEID_UV', '') or shutil.which('uv')
    if not uv_bin:
        print("Error: 'uv' package manager not found on PATH.", file=sys.stderr)
        return 1

    if args.suite == 'doctor':
        print('Running Artemis environment diagnostics...')
        return subprocess.run(
            [uv_bin, 'run', 'artemis', 'doctor'],
            cwd=artemis_dir,
            check=False,
        ).returncode

    if args.suite == 'ui':
        print('Starting Artemis Web Console...')
        return subprocess.run(
            [uv_bin, '--directory', str(artemis_dir), 'run', 'artemis', 'ui'],
            check=False,
        ).returncode

    try:
        serial = resolve_serial(adb_ui.resolve_adb(), args.serial)
    except adb_ui.AdbError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1

    goal = args.custom_goal if args.suite == 'custom' else SUITE_GOALS[args.suite]
    print(f'Starting ARTEMIS suite={args.suite} profile={args.profile}')

    return subprocess.run(
        [
            uv_bin,
            'run',
            'artemis',
            'run',
            goal,
            '--device-serial',
            serial,
            '--profile',
            args.profile,
        ],
        cwd=artemis_dir,
        check=False,
    ).returncode


if __name__ == '__main__':
    sys.exit(main())
