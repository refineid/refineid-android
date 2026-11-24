#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Stop the bridged tablet emulator and return ~/.android ownership to the user.

Usage:
  Scripts/stop-tablet-emulator.py
"""

from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import adb_ui  # noqa: E402

EXIT_WAIT_SECONDS = 30.0
KNOWN_EMU_HOME_ENTRIES = (
    'adbkey',
    'adbkey.pub',
    'analytics.settings',
    'emu-update-last-check.ini',
    'metrics',
    'cache',
)


def known_ownership_targets(emu_home: Path, avd_home: Path) -> list[Path]:
    """Return existing non-symlink `refineid_tablet` AVD and emulator state paths to repair.

    Refuses to repair anything unless the `refineid_tablet` AVD state exists under
    `avd_home`, and never targets `emu_home` itself so a misconfigured
    `ANDROID_EMULATOR_HOME` cannot alter ownership of unrelated directories.
    """
    avd_candidates = [
        avd_home / f'{adb_ui.AVD_NAME}.avd',
        avd_home / f'{adb_ui.AVD_NAME}.ini',
    ]
    avd_targets = [
        path for path in avd_candidates if path.exists() and not path.is_symlink()
    ]
    if not avd_targets:
        return []
    targets = list(avd_targets)
    if avd_home == emu_home / 'avd':
        for name in KNOWN_EMU_HOME_ENTRIES:
            candidate = emu_home / name
            if candidate.exists() and not candidate.is_symlink():
                targets.append(candidate)
    return targets


def _is_emulator_executable(comm: str) -> bool:
    name = Path(comm).name
    return name == 'emulator' or name.startswith('qemu-system-')


def _args_select_avd(comm: str, full_args: str, avd_name: str) -> bool:
    """Return True if `full_args` after executable `comm` selects `avd_name`."""
    rest = full_args[len(comm) :] if full_args.startswith(comm) else full_args
    tokens = rest.split()
    if f'@{avd_name}' in tokens:
        return True
    for idx in range(len(tokens) - 1):
        if tokens[idx] == '-avd' and tokens[idx + 1] == avd_name:
            return True
    return False


def _parse_pid_table(output: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            table[parts[0]] = parts[1]
    return table


def tablet_process_running() -> bool:
    """Return True if an Android emulator / qemu process for `refineid_tablet` is running.

    Inspects executable path (`comm`) and full command line (`args`) separately via `ps`
    so spaces in the Android SDK path never break executable matching and unrelated
    processes mentioning `refineid_tablet` in their arguments never false-match.
    """
    ps_bin = os.environ.get('REFINEID_PS', 'ps')
    comm_res = subprocess.run(
        [ps_bin, '-axww', '-o', 'pid=,comm='],
        text=True,
        capture_output=True,
        check=False,
    )
    if comm_res.returncode != 0:
        raise adb_ui.AdbError(f'process lookup failed with exit code {comm_res.returncode}')
    comms = _parse_pid_table(comm_res.stdout)
    candidate_pids = {pid: comm for pid, comm in comms.items() if _is_emulator_executable(comm)}
    if not candidate_pids:
        return False

    args_res = subprocess.run(
        [ps_bin, '-axww', '-o', 'pid=,args='],
        text=True,
        capture_output=True,
        check=False,
    )
    if args_res.returncode != 0:
        raise adb_ui.AdbError(f'process lookup failed with exit code {args_res.returncode}')
    args_by_pid = _parse_pid_table(args_res.stdout)
    for pid, comm in candidate_pids.items():
        full_args = args_by_pid.get(pid)
        if full_args is not None and _args_select_avd(comm, full_args, adb_ui.AVD_NAME):
            return True
    return False


def main() -> int:
    os.chdir(adb_ui.repo_root())
    poll_seconds = float(os.environ.get('REFINEID_UI_POLL_SECONDS', str(adb_ui.UI_POLL_SECONDS)))
    exit_wait = float(os.environ.get('REFINEID_EMU_EXIT_WAIT_SECONDS', str(EXIT_WAIT_SECONDS)))

    try:
        android_home = adb_ui.emulator_home()
        avd_home = adb_ui.avd_home(android_home)
        if not android_home.is_dir():
            raise adb_ui.AdbError(f'Android emulator home directory does not exist: {android_home}')

        adb_bin = adb_ui.resolve_adb()
        serial = adb_ui.find_avd_emulator(adb_bin, adb_ui.AVD_NAME)

        if serial is not None:
            adb_ui.run_adb(adb_bin, ['emu', 'kill'], serial=serial, operation='emu kill')
            deadline = time.monotonic() + exit_wait
            stopped = False
            while time.monotonic() < deadline:
                try:
                    still_in_adb = (
                        adb_ui.find_avd_emulator(adb_bin, adb_ui.AVD_NAME, deadline=deadline)
                        is not None
                    )
                except adb_ui.AdbError:
                    break
                if not still_in_adb and not tablet_process_running():
                    stopped = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(poll_seconds, remaining))
            if not stopped:
                raise adb_ui.AdbError(
                    f'{adb_ui.AVD_NAME} did not exit within {int(exit_wait)}s; '
                    'refusing to repair ownership while emulator is still running'
                )
        elif tablet_process_running():
            raise adb_ui.AdbError(
                f'{adb_ui.AVD_NAME} emulator process is still running but unreachable over adb; '
                'refusing to repair ownership while it may still write'
            )

        targets = known_ownership_targets(android_home, avd_home)
        if not targets:
            print(f'no {adb_ui.AVD_NAME} AVD state found; skipped ownership repair')
            return 0

        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        sudo_bin = os.environ.get('REFINEID_SUDO', 'sudo')
        chown = subprocess.run(
            [sudo_bin, 'chown', '-R', '--', f'{user}:{group}', *(str(p) for p in targets)],
            check=False,
        )
        if chown.returncode != 0:
            return chown.returncode
        print(f'tablet emulator stopped; {adb_ui.AVD_NAME} state owned by {user}')
        return 0
    except adb_ui.AdbError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
