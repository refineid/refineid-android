#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Pair the bridged tablet emulator (RAPP requester) with the physical phone.

Usage:
  Scripts/rapp-tablet-pair.py [--phone <serial>] [--tablet <serial>]

The phone must be reached over Wi-Fi debugging and hold a primed card; the
tablet must run from Scripts/start-tablet-emulator.py. The pairing code is
read from the phone's screen into a variable and typed on the tablet; it is
never printed. Progress goes to stdout; the last line is "paired" on success.
See doc/process/tablet-emulator.md.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

PAIRING_TIMEOUT_SECONDS = 60.0
PAIRING_CODE_LENGTH = 6


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/rapp-tablet-pair.py',
        description='Pair the bridged tablet emulator with the custodian phone over RAPP.',
    )
    parser.add_argument('--phone', help='Custodian phone adb serial (default: sole Wi-Fi phone).')
    parser.add_argument('--tablet', help='Tablet emulator adb serial (default: sole emulator).')
    args = parser.parse_args(argv)
    if args.phone is not None and not args.phone.strip():
        parser.error('--phone must be non-empty')
    if args.tablet is not None and not args.tablet.strip():
        parser.error('--tablet must be non-empty')
    return args


def resolve_pair_targets(adb_bin: str, args: argparse.Namespace) -> tuple[str, str]:
    """Resolve and verify both phone and tablet are online and physically distinct."""
    return adb_ui.resolve_phone_and_tablet(
        adb_bin,
        phone_arg=args.phone,
        tablet_arg=args.tablet,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    os.chdir(adb_ui.repo_root())
    poll_seconds = float(os.environ.get('REFINEID_UI_POLL_SECONDS', str(adb_ui.UI_POLL_SECONDS)))
    timeout_seconds = float(
        os.environ.get('REFINEID_PAIRING_TIMEOUT_SECONDS', str(PAIRING_TIMEOUT_SECONDS))
    )

    try:
        adb_bin = adb_ui.resolve_adb()
        phone, tablet = resolve_pair_targets(adb_bin, args)

        print('phone: opening pairing')
        adb_ui.open_refineid(adb_bin, phone, poll_seconds=poll_seconds)
        if not adb_ui.wait_for_tag(adb_bin, phone, 'RappPairingRow', poll_seconds=poll_seconds):
            raise adb_ui.AdbError(
                'phone: no Remote Access; the phone shows it only while it knows a card'
            )
        adb_ui.tap_tag(adb_bin, phone, 'RappPairingRow')
        if not adb_ui.wait_for_tag(adb_bin, phone, 'cardRemoteAccessSwitch', poll_seconds=poll_seconds):
            raise adb_ui.AdbError('phone: cardRemoteAccessSwitch did not appear')
        adb_ui.set_switch(adb_bin, phone, 'cardRemoteAccessSwitch', True, poll_seconds=poll_seconds)
        if not adb_ui.wait_for_tag(adb_bin, phone, 'offeringCodeText', poll_seconds=poll_seconds):
            raise adb_ui.AdbError('phone: offeringCodeText did not appear')

        raw_code = adb_ui.node_text(adb_bin, phone, 'offeringCodeText')
        code = ''.join(ch for ch in raw_code if ch not in ' -')
        raw_code = ''
        if len(code) != PAIRING_CODE_LENGTH or not (code.isascii() and code.isdigit()):
            code = ''
            raise adb_ui.AdbError('phone: pairing code not readable')

        print('tablet: entering the pairing code')
        adb_ui.launch_refineid(adb_bin, tablet, poll_seconds=poll_seconds)
        adb_ui.tap_tag(adb_bin, tablet, 'requesterPairingRow')
        if not adb_ui.wait_for_tag(
            adb_bin, tablet, 'requesterRemoteUseSwitch', poll_seconds=poll_seconds
        ):
            code = ''
            raise adb_ui.AdbError('tablet: requesterRemoteUseSwitch did not appear')
        # Turning remote use off forgets a held pairing, so the code entry is
        # offered again whatever the tablet held before.
        adb_ui.set_switch(
            adb_bin, tablet, 'requesterRemoteUseSwitch', False, poll_seconds=poll_seconds
        )
        adb_ui.set_switch(
            adb_bin, tablet, 'requesterRemoteUseSwitch', True, poll_seconds=poll_seconds
        )
        if not adb_ui.wait_for_tag(adb_bin, tablet, 'pairingCodeBoxes', poll_seconds=poll_seconds):
            code = ''
            raise adb_ui.AdbError('tablet: pairingCodeBoxes did not appear')
        # The code entry is a transparent field over the boxes, left out of the
        # uiautomator dump; tapping the boxes focuses it.
        adb_ui.tap_tag(adb_bin, tablet, 'pairingCodeBoxes')
        time.sleep(poll_seconds)
        try:
            adb_ui.verify_focused_package(adb_bin, tablet)
            adb_ui.type_text(adb_bin, tablet, code)
        finally:
            code = ''

        print('tablet: waiting for the pairing to finish')
        deadline = time.monotonic() + timeout_seconds
        outcome = ''
        while time.monotonic() < deadline:
            try:
                nodes = adb_ui.dump_nodes(adb_bin, tablet, deadline=deadline)
            except adb_ui.DumpCleanupError:
                raise
            except adb_ui.AdbError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(poll_seconds, remaining))
                continue
            tags = {
                rid
                for node in nodes
                if (rid := node.attrib.get('resource-id', '')) and not rid.startswith('android:id/')
            }
            if 'pairingFailure' in tags:
                outcome = 'failed'
                break
            remote_use_on = any(
                node.attrib.get('resource-id') == 'requesterRemoteUseSwitch'
                and node.attrib.get('checked') == 'true'
                for node in nodes
            )
            if (
                'requesterPairingScreen' in tags
                and remote_use_on
                and 'pairingCodeBoxes' not in tags
            ):
                outcome = 'paired'
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(poll_seconds, remaining))

        if outcome == 'failed':
            raise adb_ui.AdbError('tablet: pairing failed; inspect device UI for details')
        if outcome != 'paired':
            raise adb_ui.AdbError(
                f'tablet: pairing did not finish within {int(timeout_seconds)}s'
            )

        print('paired')
        return 0
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
