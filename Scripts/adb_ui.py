# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Shared ADB device targeting, APK install, and UI automation helpers.

Used by the Python Android test and emulator scripts under `Scripts/`.
Nodes are located by Compose test tags exposed as `resource-id`
(`testTagsAsResourceId`). Helpers never print node text or command arguments
that could carry secrets (pairing codes, PINs, CANs, URLs, or serials).
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

UI_POLL_SECONDS = 1.0
UI_DEFAULT_TIMEOUT_SECONDS = 20.0
# A cold start right after the emulator boots loads the native library and
# compiles; it has taken longer than the default wait.
UI_LAUNCH_TIMEOUT_SECONDS = 90.0
# The deepest screen stack the scripts back out of to reach home.
UI_BACK_LIMIT = 4
DEFAULT_ADB_TIMEOUT_SECONDS = 30.0
CLEANUP_TIMEOUT_SECONDS = 5.0
UI_DUMP_DIR = '/data/local/tmp'

AVD_NAME = 'refineid_tablet'
APP_PACKAGE = 'fi.refineid.android'
MAIN_ACTIVITY = 'fi.refineid.android/.MainActivity'
TEST_RUNNER = 'fi.refineid.android.test/androidx.test.runner.AndroidJUnitRunner'
APP_DEBUG_APK = Path('app/build/outputs/apk/debug/app-debug.apk')
TEST_DEBUG_APK = Path('app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')

EMULATOR_SERIAL_RE = re.compile(r'^emulator-[0-9]+$')
WIFI_SERIAL_RE = re.compile(
    r'^(?:[0-9.]+:[0-9]+|\[[0-9a-fA-F:]+\]:[0-9]+|adb-[A-Za-z0-9_-]+\._adb-tls-connect\._tcp\.?)$'
)
BOUNDS_RE = re.compile(r'^\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]$')
INSTALL_FAILURE_RE = re.compile(r'(^|\s)Failure(\s|\[|$)', re.MULTILINE)
INSTALL_SUCCESS_RE = re.compile(r'^Success$', re.MULTILINE)
CURRENT_FOCUS_RE = re.compile(r'\bmCurrentFocus=Window\{[^}]*\s([^\s}]+)\}')


class AdbError(RuntimeError):
    """Raised when an adb lookup, install, or UI interaction fails."""


class DumpCleanupError(AdbError):
    """Raised when a UI hierarchy dump file cannot be deleted from the device."""


def repo_root() -> Path:
    """Return the repository root directory containing `Scripts/`."""
    return Path(__file__).resolve().parent.parent


def sdk_root() -> Path:
    """Return the Android SDK directory from environment or macOS default."""
    env_sdk = (os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '').strip()
    if env_sdk:
        return Path(env_sdk).expanduser()
    return Path.home() / 'Library' / 'Android' / 'sdk'


def emulator_home() -> Path:
    """Return the validated Android emulator home directory (default `~/.android`)."""
    raw = (os.environ.get('ANDROID_EMULATOR_HOME') or '').strip()
    target = Path(raw).expanduser() if raw else (Path.home() / '.android')
    if not target.is_absolute():
        raise AdbError('ANDROID_EMULATOR_HOME must be an absolute path')
    resolved = target.resolve()
    if resolved == Path('/') or resolved == repo_root().resolve():
        raise AdbError('ANDROID_EMULATOR_HOME points to a disallowed directory')
    return resolved


def avd_home(emu_home: Path | None = None) -> Path:
    """Return the validated Android AVD directory (`ANDROID_AVD_HOME` or `<emu_home>/avd`)."""
    raw = (os.environ.get('ANDROID_AVD_HOME') or '').strip()
    base = emulator_home() if emu_home is None else emu_home
    target = Path(raw).expanduser() if raw else (base / 'avd')
    if not target.is_absolute():
        raise AdbError('ANDROID_AVD_HOME must be an absolute path')
    resolved = target.resolve()
    if resolved == Path('/') or resolved == repo_root().resolve():
        raise AdbError('ANDROID_AVD_HOME points to a disallowed directory')
    return resolved


def remaining_timeout(
    deadline: float | None,
    default: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> float | None:
    """Compute remaining seconds before `deadline`, raising `AdbError` if already expired."""
    if deadline is None:
        return default
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AdbError('operation timed out')
    return remaining


def resolve_adb() -> str:
    """Return the adb executable path: override, SDK platform-tools, or PATH."""
    override = os.environ.get('REFINEID_ADB', '').strip()
    if override:
        return override
    sdk_adb = sdk_root() / 'platform-tools' / 'adb'
    if sdk_adb.is_file() and os.access(sdk_adb, os.X_OK):
        return str(sdk_adb)
    return 'adb'


def run_adb(
    adb_bin: str,
    args: list[str],
    *,
    serial: str | None = None,
    operation: str = 'command',
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run adb with optional `-s <serial>`, never embedding raw arguments or stdin in errors."""
    cmd = [adb_bin]
    if serial is not None:
        cmd.extend(['-s', serial])
    cmd.extend(args)
    try:
        result = subprocess.run(
            cmd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise AdbError(f'adb {operation} timed out') from None
    if check and result.returncode != 0:
        raise AdbError(f'adb {operation} failed with exit code {result.returncode}')
    return result


def attached_devices(
    adb_bin: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> list[tuple[str, str]]:
    """Return `(serial, state)` for every attached entry from `adb devices`."""
    result = run_adb(adb_bin, ['devices'], operation='devices', timeout=timeout)
    entries: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('List of devices'):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1]))
    return entries


def online_devices(
    adb_bin: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> list[str]:
    """Return serials of currently online (`device`) targets from `adb devices`."""
    return [serial for serial, state in attached_devices(adb_bin, timeout=timeout) if state == 'device']


def select_one_device(
    devices: list[str],
    pattern: re.Pattern[str],
    description: str,
) -> str:
    """Return the unique serial matching `pattern`, or fail without printing serials."""
    matches = [serial for serial in devices if pattern.match(serial)]
    if len(matches) != 1:
        raise AdbError(f'expected exactly one {description}, found {len(matches)}')
    return matches[0]


def wifi_phone(adb_bin: str) -> str:
    """Return the serial of the single physical phone reached over Wi-Fi debugging."""
    return select_one_device(
        online_devices(adb_bin),
        WIFI_SERIAL_RE,
        'phone on Wi-Fi debugging',
    )


def emulator(adb_bin: str) -> str:
    """Return the serial of the single running emulator."""
    return select_one_device(
        online_devices(adb_bin),
        EMULATOR_SERIAL_RE,
        'running emulator',
    )


def find_avd_emulator(
    adb_bin: str,
    avd_name: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> str | None:
    """Return the online `emulator-*` serial whose AVD name equals `avd_name`, or None."""
    emulators = [
        s
        for s in online_devices(adb_bin, timeout=remaining_timeout(deadline, timeout))
        if EMULATOR_SERIAL_RE.match(s)
    ]
    matches: list[str] = []
    for serial in emulators:
        result = run_adb(
            adb_bin,
            ['emu', 'avd', 'name'],
            serial=serial,
            operation='emu avd name',
            timeout=remaining_timeout(deadline, timeout),
            check=False,
        )
        if result.returncode != 0:
            continue
        first_line = ''
        for line in result.stdout.replace('\r', '').splitlines():
            if line.strip():
                first_line = line.strip()
                break
        if first_line == avd_name:
            matches.append(serial)
    if len(matches) > 1:
        raise AdbError(f'expected at most one {avd_name} emulator, found {len(matches)}')
    return matches[0] if matches else None


def verify_online(devices: list[str], serial: str) -> str:
    """Confirm `serial` is online in `devices`, raising `AdbError` otherwise."""
    if serial not in devices:
        raise AdbError("target device is not online in 'adb devices'")
    return serial


def _read_device_prop(
    adb_bin: str,
    serial: str,
    args: list[str],
    ignored: set[str],
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> str | None:
    result = run_adb(
        adb_bin,
        args,
        serial=serial,
        operation='device identity check',
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip().replace('\r', '')
    if not value or value.lower() in ignored:
        return None
    return value


def devices_are_same_hardware(
    adb_bin: str,
    serial_a: str,
    serial_b: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> bool:
    """Compare two online transports using the same identity source on both devices."""
    sn_a = _read_device_prop(
        adb_bin, serial_a, ['shell', 'getprop', 'ro.serialno'], {'unknown'}, timeout=timeout
    )
    sn_b = _read_device_prop(
        adb_bin, serial_b, ['shell', 'getprop', 'ro.serialno'], {'unknown'}, timeout=timeout
    )
    if sn_a is not None and sn_b is not None:
        return sn_a == sn_b

    aid_a = _read_device_prop(
        adb_bin,
        serial_a,
        ['shell', 'settings', 'get', 'secure', 'android_id'],
        {'null'},
        timeout=timeout,
    )
    aid_b = _read_device_prop(
        adb_bin,
        serial_b,
        ['shell', 'settings', 'get', 'secure', 'android_id'],
        {'null'},
        timeout=timeout,
    )
    if aid_a is not None and aid_b is not None:
        return aid_a == aid_b

    raise AdbError('unable to verify target device identity')


def resolve_phone_and_tablet(
    adb_bin: str,
    *,
    phone_arg: str | None,
    tablet_arg: str | None,
) -> tuple[str, str]:
    """Resolve phone and tablet from one online inventory and verify they are distinct hardware."""
    online = online_devices(adb_bin)
    phone = (
        verify_online(online, phone_arg)
        if phone_arg
        else select_one_device(online, WIFI_SERIAL_RE, 'phone on Wi-Fi debugging')
    )
    tablet = (
        verify_online(online, tablet_arg)
        if tablet_arg
        else select_one_device(online, EMULATOR_SERIAL_RE, 'running emulator')
    )
    if phone == tablet:
        raise AdbError('phone and tablet targets must be distinct devices')
    if devices_are_same_hardware(adb_bin, phone, tablet):
        raise AdbError('phone and tablet targets refer to the same physical device')
    return phone, tablet


def verify_focused_package(
    adb_bin: str,
    serial: str,
    package: str = APP_PACKAGE,
    *,
    deadline: float | None = None,
) -> None:
    """Abort unless every `mCurrentFocus=` entry unambiguously belongs to `package`."""
    result = run_adb(
        adb_bin,
        ['shell', 'dumpsys', 'window'],
        serial=serial,
        operation='window focus check',
        timeout=remaining_timeout(deadline),
    )
    focus_lines = [line.strip() for line in result.stdout.splitlines() if 'mCurrentFocus=' in line]
    if not focus_lines:
        raise AdbError(
            f'refusing to type: unable to determine focused window for {package}'
        )
    for line in focus_lines:
        match = CURRENT_FOCUS_RE.search(line)
        if not match or not match.group(1).startswith(f'{package}/'):
            raise AdbError(
                f'refusing to type: focused window on target device is not {package}'
            )


def install_apk(
    adb_bin: str,
    serial: str,
    apk_path: Path,
    *,
    allow_test: bool = False,
) -> None:
    """Install `apk_path` onto `serial` only; fail on non-zero exit or Failure output."""
    if not apk_path.is_file():
        raise AdbError(f'APK not found: {apk_path}')
    args = ['install', '-r']
    if allow_test:
        args.append('-t')
    args.append(str(apk_path))
    result = run_adb(adb_bin, args, serial=serial, operation='install', check=False)
    clean = (result.stdout + '\n' + result.stderr).replace('\r', '')
    if (
        result.returncode != 0
        or INSTALL_FAILURE_RE.search(clean)
        or not INSTALL_SUCCESS_RE.search(clean)
    ):
        reason_match = re.search(r'Failure\s+\[([A-Z0-9_]+)\]', clean)
        detail = f' ({reason_match.group(1)})' if reason_match else ''
        raise AdbError(f'failed to install {apk_path} on target device{detail}')


def dump_nodes(
    adb_bin: str,
    serial: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> list[ET.Element]:
    """Dump the UI hierarchy of `serial` to a shell-private path and always delete it."""
    dump_path = f'{UI_DUMP_DIR}/refineid-ui-{os.getpid()}-{uuid.uuid4().hex[:8]}.xml'
    primary_error: AdbError | None = None
    dump_started = False
    nodes: list[ET.Element] = []
    try:
        dump_timeout = remaining_timeout(deadline, timeout)
        dump_started = True
        dump = run_adb(
            adb_bin,
            ['shell', 'uiautomator', 'dump', dump_path],
            serial=serial,
            operation='uiautomator dump',
            timeout=dump_timeout,
            check=False,
        )
        if dump.returncode != 0:
            raise AdbError('UI hierarchy dump failed')
        read_timeout = remaining_timeout(deadline, timeout)
        content = run_adb(
            adb_bin,
            ['exec-out', 'cat', dump_path],
            serial=serial,
            operation='uiautomator read',
            timeout=read_timeout,
            check=False,
        )
        if content.returncode != 0 or not content.stdout.strip():
            raise AdbError('UI hierarchy read failed')
        try:
            root = ET.fromstring(content.stdout)
        except ET.ParseError as exc:
            raise AdbError('UI hierarchy XML invalid') from exc
        nodes = list(root.iter('node'))
    except AdbError as err:
        primary_error = err
    finally:
        if dump_started:
            cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
            cleaned = False
            for _ in range(2):
                try:
                    cleanup_timeout = remaining_timeout(cleanup_deadline, CLEANUP_TIMEOUT_SECONDS)
                    cleanup = run_adb(
                        adb_bin,
                        ['shell', 'rm', '-f', dump_path],
                        serial=serial,
                        operation='uiautomator cleanup',
                        timeout=cleanup_timeout,
                        check=False,
                    )
                except AdbError:
                    if time.monotonic() >= cleanup_deadline:
                        break
                    continue
                if cleanup.returncode == 0:
                    cleaned = True
                    break
            if not cleaned:
                raise DumpCleanupError('failed to remove UI dump file from device') from None
    if primary_error is not None:
        raise primary_error
    return nodes


def find_node(
    adb_bin: str,
    serial: str,
    tag: str,
    *,
    attribute: str = 'resource-id',
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> ET.Element | None:
    """Return the first UI node whose `attribute` equals `tag`, or `None`."""
    for node in dump_nodes(adb_bin, serial, timeout=timeout, deadline=deadline):
        if node.attrib.get(attribute) == tag:
            return node
    return None


def has_tag(
    adb_bin: str,
    serial: str,
    tag: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> bool:
    """Return True if `serial` currently shows a node tagged `tag`."""
    return find_node(adb_bin, serial, tag, timeout=timeout, deadline=deadline) is not None


def wait_for_tag(
    adb_bin: str,
    serial: str,
    tag: str,
    timeout: float = UI_DEFAULT_TIMEOUT_SECONDS,
    poll_seconds: float = UI_POLL_SECONDS,
) -> bool:
    """Wait up to `timeout` seconds for `serial` to show a node tagged `tag`."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            if has_tag(adb_bin, serial, tag, deadline=deadline):
                return True
        except DumpCleanupError:
            raise
        except AdbError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(poll_seconds, remaining))


def bounds_center(bounds: str) -> tuple[int, int]:
    """Parse `[left,top][right,bottom]` into its integer center `(x, y)`."""
    match = BOUNDS_RE.match(bounds)
    if not match:
        raise AdbError('node has no usable bounds')
    left, top, right, bottom = (int(group) for group in match.groups())
    return (left + right) // 2, (top + bottom) // 2


def tap_node(
    adb_bin: str,
    serial: str,
    node: ET.Element,
    *,
    deadline: float | None = None,
) -> None:
    """Tap the center of `node` on `serial`."""
    x_pos, y_pos = bounds_center(node.attrib.get('bounds', ''))
    run_adb(
        adb_bin,
        ['shell', 'input', 'tap', str(x_pos), str(y_pos)],
        serial=serial,
        operation='input tap',
        timeout=remaining_timeout(deadline),
    )


def tap_tag(adb_bin: str, serial: str, tag: str) -> None:
    """Find the node tagged `tag` on `serial` and tap its center."""
    node = find_node(adb_bin, serial, tag)
    if node is None:
        raise AdbError(f'no node tagged {tag}')
    tap_node(adb_bin, serial, node)


def type_text(
    adb_bin: str,
    serial: str,
    text: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
) -> None:
    """Type `text` into the focused field via non-PTY stdin so `text` never enters argv."""
    run_adb(
        adb_bin,
        ['shell', '-T'],
        serial=serial,
        operation='input text',
        timeout=timeout,
        input_text=f'input text {shlex.quote(text)}\n',
    )


def node_text(adb_bin: str, serial: str, tag: str) -> str:
    """Read the `text` attribute of the node tagged `tag`; callers must never log secrets."""
    node = find_node(adb_bin, serial, tag)
    if node is None:
        return ''
    return node.attrib.get('text', '')


def checked_state(
    adb_bin: str,
    serial: str,
    tag: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> bool | None:
    """Return True/False for explicit `checked` state on `tag`, or None if absent."""
    node = find_node(adb_bin, serial, tag, timeout=timeout, deadline=deadline)
    if node is None:
        return None
    value = node.attrib.get('checked')
    if value == 'true':
        return True
    if value == 'false':
        return False
    return None


def is_checked(
    adb_bin: str,
    serial: str,
    tag: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> bool:
    """Return True if the node tagged `tag` reports `checked="true"`."""
    return checked_state(adb_bin, serial, tag, timeout=timeout, deadline=deadline) is True


def visible_tags(
    adb_bin: str,
    serial: str,
    *,
    timeout: float | None = DEFAULT_ADB_TIMEOUT_SECONDS,
    deadline: float | None = None,
) -> set[str]:
    """Return non-system `resource-id` tags visible on `serial`, never any node text."""
    tags: set[str] = set()
    for node in dump_nodes(adb_bin, serial, timeout=timeout, deadline=deadline):
        resource_id = node.attrib.get('resource-id', '')
        if resource_id and not resource_id.startswith('android:id/'):
            tags.add(resource_id)
    return tags


def _start_main_activity(adb_bin: str, serial: str) -> None:
    """Start RefineID's main activity and fail on non-zero exit or `Error:` output."""
    launch = run_adb(
        adb_bin,
        ['shell', 'am', 'start', '-n', MAIN_ACTIVITY],
        serial=serial,
        operation='am start',
    )
    combined = f'{launch.stdout}\n{launch.stderr}'
    if re.search(r'(^|\s)Error:', combined, re.MULTILINE):
        raise AdbError('failed to start RefineID activity')


def launch_refineid(
    adb_bin: str,
    serial: str,
    *,
    timeout: float = UI_LAUNCH_TIMEOUT_SECONDS,
    poll_seconds: float = UI_POLL_SECONDS,
) -> None:
    """Force-stop and relaunch RefineID on `serial`, waiting for `mainScreen`."""
    run_adb(
        adb_bin,
        ['shell', 'am', 'force-stop', APP_PACKAGE],
        serial=serial,
        operation='am force-stop',
    )
    _start_main_activity(adb_bin, serial)
    if not wait_for_tag(adb_bin, serial, 'mainScreen', timeout=timeout, poll_seconds=poll_seconds):
        raise AdbError('timed out waiting for mainScreen')


def open_refineid(
    adb_bin: str,
    serial: str,
    *,
    timeout: float = UI_LAUNCH_TIMEOUT_SECONDS,
    poll_seconds: float = UI_POLL_SECONDS,
) -> None:
    """Bring RefineID to the front without restarting it and back out to `mainScreen`."""
    _start_main_activity(adb_bin, serial)
    for _ in range(UI_BACK_LIMIT):
        try:
            if has_tag(adb_bin, serial, 'mainScreen'):
                return
        except DumpCleanupError:
            raise
        except AdbError:
            pass
        verify_focused_package(adb_bin, serial)
        run_adb(
            adb_bin,
            ['shell', 'input', 'keyevent', 'KEYCODE_BACK'],
            serial=serial,
            operation='input keyevent',
        )
        time.sleep(poll_seconds)
    if not wait_for_tag(adb_bin, serial, 'mainScreen', timeout=timeout, poll_seconds=poll_seconds):
        raise AdbError('timed out waiting for mainScreen')


def set_switch(
    adb_bin: str,
    serial: str,
    tag: str,
    wanted: bool,
    *,
    timeout: float = UI_DEFAULT_TIMEOUT_SECONDS,
    poll_seconds: float = UI_POLL_SECONDS,
) -> None:
    """Toggle switch `tag` until its explicit `checked` attribute equals `wanted`."""
    deadline = time.monotonic() + timeout
    node = find_node(adb_bin, serial, tag, deadline=deadline)
    if node is None:
        raise AdbError(f'no node tagged {tag}')
    raw_checked = node.attrib.get('checked')
    if raw_checked not in ('true', 'false'):
        raise AdbError(f'{tag} has no checked state')
    if (raw_checked == 'true') == wanted:
        return
    tap_node(adb_bin, serial, node, deadline=deadline)
    while True:
        try:
            if checked_state(adb_bin, serial, tag, deadline=deadline) is wanted:
                return
        except DumpCleanupError:
            raise
        except AdbError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            state = 'true' if wanted else 'false'
            raise AdbError(f'{tag} did not turn {state}')
        time.sleep(min(poll_seconds, remaining))
