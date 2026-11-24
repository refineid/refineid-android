#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Log in from the tablet emulator's in-app browser over RAPP.

Usage:
  Scripts/rapp-tablet-browser-login.py [--url <https url>] [--tablet <serial>] [--phone <serial>]

The tablet must be paired (Scripts/rapp-tablet-pair.py) and run a debug build.
The card signs on the phone, so it must lie on the phone's NFC reader; when
the phone asks for the card or for PIN 1, the script says so and waits. The
PIN is entered on the phone by its holder, never by a script. A PIN field on
the tablet fails the run. Page content is never printed; it can hold the
certificate subject. See doc/process/tablet-emulator.md.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

# A public test service that requests a client certificate from any issuer.
DEFAULT_URL = 'https://certauth.cryptomix.com/json/'
LOGIN_TIMEOUT_SECONDS = 120.0
TABLET_PIN_TAGS = (
    'browserPin1Field',
    'browserUnlockPin1Field',
    'browserUnlockCanField',
)
BROWSER_SCREEN_TAGS = (
    'browserView',
    'browserUrlField',
)
PHONE_PIN_TAG = 'rappPinField'
PHONE_CARD_TAG = 'RappCardTapMessage'

# Threadtime logcat header anchored specifically to the `RefineID` tag so
# another logger's message containing "RefineID:" can never match. Captures
# `(timestamp, pid, tid, payload)` so request matching is scoped per PID.
REFINEID_LOGCAT_RE = re.compile(
    r'^([0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3})\s+'
    r'([0-9]+)\s+([0-9]+)\s+[VDIWEFA]\s+RefineID\s*:\s*(.+)$'
)

# Strict allowlist enumerating the exact debug browser trace payloads and enum
# values from AppTrace.kt, BrowserClientIdentity.kt, and BrowserPinCoordinator.kt.
ALLOWED_BROWSER_TRACE_RE = re.compile(
    r'^browser:(?:'
    r'opened'
    r'|closed'
    r'|navigation-blocked'
    r'|client-certificate-unlock-requested'
    r'|initialized provider-ready=(?:true|false) issuer-count=[0-9]+'
    r'|tls-error primary-error=-?[0-9]+'
    r'|client-certificate-request origin-allowed=(?:true|false) key-type-count=[0-9]+ issuer-count=[0-9]+'
    r'|client-certificate-completed outcome=(?:PROCEEDED|ORIGIN_REJECTED|CARD_UNAVAILABLE|IDENTITY_INVALID|HINT_MISMATCH|CLOSED)'
    r'|signature status=(?:IDLE|PIN_REQUIRED|SIGNING|SUCCEEDED|WRONG_PIN|PIN_LOCKED|REFUSED|CANCELLED|TIMED_OUT|INTERRUPTED|ERROR)'
    r')$'
)
SIGNATURE_FAILED_RE = re.compile(
    r'^browser:signature status=(?:WRONG_PIN|PIN_LOCKED|REFUSED|CANCELLED|TIMED_OUT|INTERRUPTED|ERROR)$'
)
CERT_FAILED_RE = re.compile(
    r'^browser:client-certificate-completed outcome=(?:ORIGIN_REJECTED|CARD_UNAVAILABLE|IDENTITY_INVALID|HINT_MISMATCH|CLOSED)$'
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='Scripts/rapp-tablet-browser-login.py',
        description='Verify in-app browser mutual-TLS login from the tablet emulator over RAPP.',
    )
    parser.add_argument('--url', default=DEFAULT_URL, help='HTTPS test URL to load.')
    parser.add_argument('--tablet', help='Tablet emulator adb serial (default: sole emulator).')
    parser.add_argument('--phone', help='Custodian phone adb serial (default: sole Wi-Fi phone).')
    args = parser.parse_args(argv)
    if not args.url.startswith('https://'):
        parser.error('--url must start with https://')
    if args.tablet is not None and not args.tablet.strip():
        parser.error('--tablet must be non-empty')
    if args.phone is not None and not args.phone.strip():
        parser.error('--phone must be non-empty')
    return args


def resolve_login_targets(adb_bin: str, args: argparse.Namespace) -> tuple[str, str]:
    """Resolve and verify both tablet and phone are online and physically distinct."""
    phone, tablet = adb_ui.resolve_phone_and_tablet(
        adb_bin,
        phone_arg=args.phone,
        tablet_arg=args.tablet,
    )
    return tablet, phone


def extract_browser_traces(
    logcat_output: str,
    *,
    expected_pid: str | None = None,
) -> list[tuple[str, str, str]]:
    """Return `(event_stamp, pid, payload)` tuples for allowlisted `RefineID` browser traces."""
    entries: list[tuple[str, str, str]] = []
    for line in logcat_output.splitlines():
        match = REFINEID_LOGCAT_RE.match(line.rstrip('\r'))
        if not match:
            continue
        ts, pid, tid, raw_payload = match.groups()
        if expected_pid is not None and pid != expected_pid:
            continue
        payload = raw_payload.strip()
        if ALLOWED_BROWSER_TRACE_RE.fullmatch(payload):
            stamp = f'{" ".join(ts.split())} {pid} {tid}'
            entries.append((stamp, pid, payload))
    return entries


def classify_traces(entries: list[tuple[str, str, str]]) -> tuple[str, str]:
    """Classify the snapshot in chronological request order, scoped per process PID.

    Returns `(outcome, event_id)` where `event_id` identifies the `PROCEEDED`
    event that initiated the current signed request from the same PID so events
    from different processes can never be combined.
    """
    latest_proceeded_id = ''
    latest_proceeded_pid = ''
    latest_succeeded = False
    for stamp, pid, trace in entries:
        if trace.startswith('browser:tls-error'):
            return 'tls-error', latest_proceeded_id
        if SIGNATURE_FAILED_RE.match(trace):
            return 'signature-failed', latest_proceeded_id
        if CERT_FAILED_RE.match(trace):
            return 'certificate-rejected', latest_proceeded_id
        if trace.startswith('browser:client-certificate-request '):
            latest_proceeded_id = ''
            latest_proceeded_pid = ''
            latest_succeeded = False
        elif trace == 'browser:client-certificate-completed outcome=PROCEEDED':
            latest_proceeded_id = stamp
            latest_proceeded_pid = pid
            latest_succeeded = False
        elif (
            trace == 'browser:signature status=SUCCEEDED'
            and latest_proceeded_id
            and pid == latest_proceeded_pid
        ):
            latest_succeeded = True
    if latest_proceeded_id and latest_succeeded:
        return 'signed', latest_proceeded_id
    return '', latest_proceeded_id


def app_pid(adb_bin: str, serial: str) -> str | None:
    """Return the single numeric PID of the launched RefineID process, or None."""
    result = adb_ui.run_adb(
        adb_bin,
        ['shell', 'pidof', adb_ui.APP_PACKAGE],
        serial=serial,
        operation='pidof',
        check=False,
    )
    if result.returncode != 0:
        return None
    pids = [tok for tok in result.stdout.strip().split() if tok.isdigit()]
    return pids[0] if len(pids) == 1 else None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    os.chdir(adb_ui.repo_root())
    poll_seconds = float(os.environ.get('REFINEID_UI_POLL_SECONDS', str(adb_ui.UI_POLL_SECONDS)))
    timeout_seconds = float(
        os.environ.get('REFINEID_LOGIN_TIMEOUT_SECONDS', str(LOGIN_TIMEOUT_SECONDS))
    )

    try:
        adb_bin = adb_ui.resolve_adb()
        tablet, phone = resolve_login_targets(adb_bin, args)

        print('tablet: opening the browser')
        adb_ui.launch_refineid(adb_bin, tablet, poll_seconds=poll_seconds)
        launched_pid = app_pid(adb_bin, tablet)
        if not adb_ui.wait_for_tag(adb_bin, tablet, 'browserAction', poll_seconds=poll_seconds):
            raise adb_ui.AdbError(
                "tablet: no browser action; is the tablet paired and the phone's card presented?"
            )
        adb_ui.tap_tag(adb_bin, tablet, 'browserAction')
        if not adb_ui.wait_for_tag(adb_bin, tablet, 'browserUrlField', poll_seconds=poll_seconds):
            raise adb_ui.AdbError('tablet: the browser did not open')
        adb_ui.tap_tag(adb_bin, tablet, 'browserUrlField')
        time.sleep(poll_seconds)
        adb_ui.verify_focused_package(adb_bin, tablet)
        adb_ui.run_adb(
            adb_bin,
            ['shell', 'input', 'keycombination', 'KEYCODE_CTRL_LEFT', 'KEYCODE_A'],
            serial=tablet,
            operation='input keycombination',
        )
        adb_ui.verify_focused_package(adb_bin, tablet)
        adb_ui.run_adb(
            adb_bin,
            ['shell', 'input', 'keyevent', 'KEYCODE_DEL'],
            serial=tablet,
            operation='input keyevent',
        )
        adb_ui.verify_focused_package(adb_bin, tablet)
        adb_ui.type_text(adb_bin, tablet, args.url)
        # Establish the logcat boundary immediately before submitting the
        # requested URL so any handshake traces emitted while opening the
        # browser cannot be credited to this navigation.
        adb_ui.run_adb(adb_bin, ['logcat', '-c'], serial=tablet, operation='logcat clear')
        adb_ui.verify_focused_package(adb_bin, tablet)
        adb_ui.run_adb(
            adb_bin,
            ['shell', 'input', 'keyevent', 'KEYCODE_ENTER'],
            serial=tablet,
            operation='input keyevent',
        )

        print('tablet: waiting for the client-certificate handshake')
        deadline = time.monotonic() + timeout_seconds
        asked_for_pin = False
        asked_for_card = False
        confirmed_event_id = ''
        outcome = ''
        traces: list[tuple[str, str, str]] = []

        while time.monotonic() < deadline:
            try:
                tablet_tags = adb_ui.visible_tags(adb_bin, tablet, deadline=deadline)
                tablet_inspected = any(tag in tablet_tags for tag in BROWSER_SCREEN_TAGS)
            except adb_ui.DumpCleanupError:
                raise
            except adb_ui.AdbError:
                tablet_tags = set()
                tablet_inspected = False

            for tag in TABLET_PIN_TAGS:
                if tag in tablet_tags:
                    raise adb_ui.AdbError(
                        f'tablet: shows {tag}; a remote login must never ask for a secret on the requester'
                    )

            if time.monotonic() >= deadline:
                break

            try:
                phone_tags = adb_ui.visible_tags(adb_bin, phone, deadline=deadline)
            except adb_ui.DumpCleanupError:
                raise
            except adb_ui.AdbError:
                phone_tags = set()

            if not asked_for_card and PHONE_CARD_TAG in phone_tags:
                print('phone: hold the card to the phone')
                asked_for_card = True
            if not asked_for_pin and PHONE_PIN_TAG in phone_tags:
                print('phone: enter PIN 1 on the phone')
                asked_for_pin = True

            logcat_remaining = deadline - time.monotonic()
            if logcat_remaining <= 0:
                break

            try:
                logcat = adb_ui.run_adb(
                    adb_bin,
                    ['logcat', '-d', '-v', 'threadtime', '-s', 'RefineID:V'],
                    serial=tablet,
                    operation='logcat read',
                    timeout=logcat_remaining,
                    check=False,
                )
            except adb_ui.AdbError:
                logcat = None
            if logcat is not None and logcat.returncode == 0:
                traces = extract_browser_traces(logcat.stdout, expected_pid=launched_pid)
                candidate, event_id = classify_traces(traces)
                if candidate in ('tls-error', 'signature-failed', 'certificate-rejected'):
                    outcome = candidate
                    break
                if candidate == 'signed' and tablet_inspected:
                    # Require two consecutive clean inspections for the same
                    # request event id so a new request or trailing TLS error is observed.
                    if confirmed_event_id and confirmed_event_id == event_id:
                        outcome = 'signed'
                        break
                    confirmed_event_id = event_id
                else:
                    confirmed_event_id = ''
            else:
                confirmed_event_id = ''
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(poll_seconds, remaining))

        print('traces:')
        for _, _, payload in traces:
            print(f'  {payload}')

        if outcome == 'signed':
            print('client-certificate signature succeeded')
            return 0
        if not outcome:
            raise adb_ui.AdbError(f'no handshake outcome within {int(timeout_seconds)}s')
        raise adb_ui.AdbError(f'login failed: {outcome}')
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
