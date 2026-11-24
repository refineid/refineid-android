#!/usr/bin/env python3
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
"""Usage: python3 -B -W error Scripts/TestAndroidTestScripts.py.

Hermetic tests for the Python Android test scripts (`adb_ui.py`,
`connected-test.py`, `dump-phone-diagnostics.py`, `rapp-tablet-pair.py`,
`rapp-tablet-browser-login.py`, `start-tablet-emulator.py`,
`stop-tablet-emulator.py`, `test-artemis.py`)
and `Scripts/install-device.sh`, using fake adb/Gradle/sudo/pgrep/uv binaries
so targeting, secret hygiene, XML parsing, install checks, and result parsing
are verified without attached hardware.
"""

from __future__ import annotations

import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / 'Scripts'
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import adb_ui  # noqa: E402


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


START_EMU = load_module('start_tablet_emulator', SCRIPTS_DIR / 'start-tablet-emulator.py')
BROWSER_LOGIN = load_module('rapp_tablet_browser_login', SCRIPTS_DIR / 'rapp-tablet-browser-login.py')


FAKE_ADB = """#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

log_file = Path(os.environ['FAKE_ADB_LOG'])
with log_file.open('a', encoding='utf-8') as handle:
    handle.write(' '.join(sys.argv[1:]) + '\\n')

args = sys.argv[1:]
if args == ['devices']:
    sys.stdout.write('List of devices attached\\n')
    state_path = os.environ.get('FAKE_DEVICES_STATE')
    if state_path and Path(state_path).is_file():
        lines = json.loads(Path(state_path).read_text(encoding='utf-8'))
        for line in lines:
            if line.strip():
                sys.stdout.write(line + '\\n')
    else:
        for line in os.environ.get('FAKE_ADB_DEVICES', '').splitlines():
            if line.strip():
                sys.stdout.write(line + '\\n')
    sys.exit(0)

if len(args) >= 3 and args[0] == '-s':
    serial = args[1]
    sub = args[2:]

    if sub[0] == 'install':
        apk = sub[-1]
        fail_apk = os.environ.get('FAKE_ADB_INSTALL_FAIL_APK', '')
        if fail_apk and apk.endswith(fail_apk):
            sys.stdout.write(
                os.environ.get(
                    'FAKE_ADB_INSTALL_FAIL_OUT',
                    'Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE]\\n',
                )
            )
            sys.exit(int(os.environ.get('FAKE_ADB_INSTALL_FAIL_RC', '0')))
        sys.stdout.write('Performing Streamed Install\\nSuccess\\n')
        sys.exit(0)

    if sub == ['emu', 'avd', 'name']:
        mapping = json.loads(os.environ.get('FAKE_EMU_AVD_NAMES', '{"emulator-5554": "refineid_tablet"}'))
        name = mapping.get(serial)
        if not name:
            sys.exit(1)
        sys.stdout.write(f'{name}\\r\\nOK\\r\\n')
        sys.exit(0)

    if sub == ['emu', 'kill']:
        state_path = os.environ.get('FAKE_DEVICES_STATE')
        if state_path and Path(state_path).is_file() and os.environ.get('FAKE_EMU_STUCK') != '1':
            lines = json.loads(Path(state_path).read_text(encoding='utf-8'))
            lines = [line for line in lines if not line.startswith(serial + '\\t')]
            Path(state_path).write_text(json.dumps(lines), encoding='utf-8')
        sys.stdout.write('OK: killing emulator, bye bye\\n')
        sys.exit(0)

    if sub == ['logcat', '-c']:
        buf_path = os.environ.get('FAKE_ADB_LOGCAT_BUFFER')
        if buf_path and Path(buf_path).is_file():
            Path(buf_path).write_text('', encoding='utf-8')
        sys.exit(0)

    if sub[:2] == ['logcat', '-d']:
        buf_path = os.environ.get('FAKE_ADB_LOGCAT_BUFFER')
        if buf_path and Path(buf_path).is_file():
            sys.stdout.write(Path(buf_path).read_text(encoding='utf-8'))
            sys.exit(0)
        logcat_state = os.environ.get('FAKE_ADB_LOGCAT_STATE')
        if logcat_state and Path(logcat_state).is_file():
            queue = json.loads(Path(logcat_state).read_text(encoding='utf-8'))
            chunk = queue.pop(0) if len(queue) > 1 else (queue[0] if queue else '')
            Path(logcat_state).write_text(json.dumps(queue), encoding='utf-8')
            sys.stdout.write(chunk)
        else:
            sys.stdout.write(os.environ.get('FAKE_ADB_LOGCAT', ''))
        sys.exit(0)

    if sub[:2] == ['exec-out', 'cat']:
        sleep_secs = float(os.environ.get('FAKE_ADB_SLEEP_DUMP', '0'))
        if sleep_secs > 0:
            time.sleep(sleep_secs)
        if os.environ.get('FAKE_ADB_FAIL_CAT') == '1':
            sys.exit(1)
        state_path = os.environ.get('FAKE_UI_STATE')
        if state_path and Path(state_path).is_file():
            state = json.loads(Path(state_path).read_text(encoding='utf-8'))
            queue = state.get(serial, [])
            xml = queue.pop(0) if len(queue) > 1 else (queue[0] if queue else '<hierarchy/>')
            state[serial] = queue
            Path(state_path).write_text(json.dumps(state), encoding='utf-8')
        else:
            xml = os.environ.get('FAKE_ADB_UI_XML', '<hierarchy/>')
        reads_log = os.environ.get('FAKE_UI_READS_LOG')
        if reads_log:
            with Path(reads_log).open('a', encoding='utf-8') as handle:
                handle.write(f'{serial}:{xml}\\n')
        sys.stdout.write(xml)
        sys.exit(0)

    if sub == ['shell', '-T']:
        stdin_text = sys.stdin.read()
        stdin_log = os.environ.get('FAKE_ADB_STDIN_LOG')
        if stdin_log:
            with Path(stdin_log).open('a', encoding='utf-8') as handle:
                handle.write(f'{serial}: {stdin_text}')
        sleep_secs = float(os.environ.get('FAKE_ADB_SLEEP_INPUT_TEXT', '0'))
        if sleep_secs > 0:
            time.sleep(sleep_secs)
        if os.environ.get('FAKE_ADB_FAIL_INPUT_TEXT') == '1':
            sys.exit(1)
        sys.exit(0)

    if sub[0] == 'shell':
        cmd = ' '.join(sub[1:])
        if cmd.startswith('uiautomator dump'):
            sleep_secs = float(os.environ.get('FAKE_ADB_SLEEP_DUMP', '0'))
            if sleep_secs > 0:
                time.sleep(sleep_secs)
            if os.environ.get('FAKE_ADB_FAIL_DUMP') == '1':
                sys.exit(1)
            sys.exit(0)
        if cmd.startswith('rm -f'):
            sleep_rm = float(os.environ.get('FAKE_ADB_SLEEP_RM', '0'))
            if sleep_rm > 0:
                time.sleep(sleep_rm)
            if os.environ.get('FAKE_ADB_FAIL_RM') == '1':
                sys.exit(1)
            sys.exit(0)
        if cmd.startswith('am instrument'):
            sys.stdout.write(os.environ.get('FAKE_ADB_INSTRUMENT_OUT', 'OK (1 test)\\n'))
            sys.exit(int(os.environ.get('FAKE_ADB_INSTRUMENT_RC', '0')))
        if cmd == 'getprop ro.serialno':
            mapping = json.loads(os.environ.get('FAKE_DEVICE_SERIALNOS', '{}'))
            sys.stdout.write(mapping.get(serial, f'hw-{serial}') + '\\n')
            sys.exit(0)
        if cmd == 'settings get secure android_id':
            mapping = json.loads(os.environ.get('FAKE_DEVICE_ANDROID_IDS', '{}'))
            sys.stdout.write(mapping.get(serial, f'aid-{serial}') + '\\n')
            sys.exit(0)
        if cmd == 'dumpsys window':
            default_focus = '  mCurrentFocus=Window{1234 u0 fi.refineid.android/fi.refineid.android.MainActivity}\\n'
            focus_state = os.environ.get('FAKE_ADB_FOCUS_STATE')
            if focus_state and Path(focus_state).is_file():
                queue = json.loads(Path(focus_state).read_text(encoding='utf-8'))
                out = queue.pop(0) if len(queue) > 1 else (queue[0] if queue else default_focus)
                Path(focus_state).write_text(json.dumps(queue), encoding='utf-8')
                sys.stdout.write(out)
            else:
                sys.stdout.write(os.environ.get('FAKE_ADB_FOCUS', default_focus))
            sys.exit(0)
        if cmd == 'pidof fi.refineid.android':
            pid = os.environ.get('FAKE_ADB_APP_PID', '1')
            if not pid:
                sys.exit(1)
            sys.stdout.write(pid + '\\n')
            sys.exit(0)
        if cmd.startswith('am start'):
            if os.environ.get('FAKE_ADB_AM_START_OUT'):
                sys.stdout.write(os.environ['FAKE_ADB_AM_START_OUT'])
            if os.environ.get('FAKE_ADB_FAIL_AM_START') == '1':
                sys.exit(1)
            sys.exit(0)
        if cmd.startswith('am broadcast'):
            if os.environ.get('FAKE_ADB_FAIL_BROADCAST') == '1':
                sys.exit(1)
            default_broadcast = (
                'Broadcasting: Intent { act=fi.refineid.android.CLEAR_LOGS pkg=fi.refineid.android }\\n'
                'Broadcast completed: result=0, data="LOGS_CLEARED"\\n'
                if 'fi.refineid.android.CLEAR_LOGS' in cmd
                else 'Broadcasting: Intent { act=fi.refineid.android.DUMP_DIAGNOSTICS pkg=fi.refineid.android }\\n'
                'Broadcast completed: result=0, data="DUMP_OK: 3 trace lines written to files/diagnostics.txt"\\n'
            )
            sys.stdout.write(os.environ.get('FAKE_ADB_BROADCAST_OUT', default_broadcast))
            sys.exit(0)
        if cmd == 'run-as fi.refineid.android cat files/diagnostics.txt':
            if os.environ.get('FAKE_ADB_FAIL_RUN_AS') == '1':
                sys.exit(1)
            sys.stdout.write(
                os.environ.get('FAKE_ADB_DIAGNOSTICS_TEXT', '== RefineID Diagnostics ==\\nstatus=ok\\n')
            )
            sys.exit(0)
        if cmd.startswith(('am force-stop', 'input ')):
            sys.exit(0)

sys.stderr.write(f'unexpected fake adb args: {args}\\n')
sys.exit(99)
"""


FAKE_GRADLE = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

log_file = Path(os.environ['FAKE_GRADLE_LOG'])
with log_file.open('a', encoding='utf-8') as handle:
    handle.write(' '.join(sys.argv[1:]) + '\\n')

if os.environ.get('FAKE_GRADLE_SKIP_APKS') != '1':
    for rel in (
        'app/build/outputs/apk/debug/app-debug.apk',
        'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk',
    ):
        target = Path(rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'fake-apk')

sys.exit(int(os.environ.get('FAKE_GRADLE_RC', '0')))
"""


FAKE_ECHO_TOOL = """#!/usr/bin/env python3
import os
import sys
from pathlib import Path

log_file = Path(os.environ['FAKE_TOOL_LOG'])
with log_file.open('a', encoding='utf-8') as handle:
    handle.write(' '.join(sys.argv[1:]) + '\\n')
sys.exit(int(os.environ.get('FAKE_TOOL_RC', '0')))
"""


FAKE_PS = """#!/usr/bin/env python3
import json
import os
import sys

rc = os.environ.get('FAKE_PS_RC')
if rc is not None:
    sys.exit(int(rc))
if len(sys.argv) < 4 or sys.argv[1:3] != ['-axww', '-o']:
    sys.exit(2)
fmt = sys.argv[3]
procs = json.loads(os.environ.get('FAKE_PS_PROCS', '[]'))
for pid, comm, args in procs:
    if fmt == 'pid=,comm=':
        sys.stdout.write(f'{pid} {comm}\\n')
    elif fmt == 'pid=,args=':
        sys.stdout.write(f'{pid} {args}\\n')
    else:
        sys.exit(2)
sys.exit(0)
"""


def make_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class AndroidTestScriptsSuite(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        scripts_copy = self.root / 'Scripts'
        scripts_copy.mkdir(parents=True, exist_ok=True)
        for name in (
            'adb_ui.py',
            'connected-test.py',
            'dump-phone-diagnostics.py',
            'rapp-tablet-pair.py',
            'rapp-tablet-browser-login.py',
            'start-tablet-emulator.py',
            'stop-tablet-emulator.py',
            'test-artemis.py',
            'install-device.sh',
        ):
            shutil.copy2(SCRIPTS_DIR / name, scripts_copy / name)
        self.scripts = scripts_copy

        self.fake_adb = self.root / 'fake-adb'
        self.fake_gradle = self.root / 'fake-gradle'
        self.fake_tool = self.root / 'fake-tool'
        self.fake_ps = self.root / 'fake-ps'
        make_executable(self.fake_adb, FAKE_ADB)
        make_executable(self.fake_gradle, FAKE_GRADLE)
        make_executable(self.fake_tool, FAKE_ECHO_TOOL)
        make_executable(self.fake_ps, FAKE_PS)

        self.adb_log = self.root / 'adb.log'
        self.adb_stdin_log = self.root / 'adb-stdin.log'
        self.gradle_log = self.root / 'gradle.log'
        self.tool_log = self.root / 'tool.log'

    def tearDown(self):
        self.tempdir.cleanup()

    def base_env(self, **overrides: str) -> dict[str, str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(('FAKE_', 'REFINEID_'))
            and key not in ('ANDROID_SERIAL', 'ANDROID_EMULATOR_HOME', 'ANDROID_AVD_HOME')
        }
        env.update({
            'REFINEID_ADB': str(self.fake_adb),
            'REFINEID_CONNECTED_TEST_GRADLE': str(self.fake_gradle),
            'REFINEID_INSTALL_GRADLE': str(self.fake_gradle),
            'REFINEID_SUDO': str(self.fake_tool),
            'REFINEID_UV': str(self.fake_tool),
            'REFINEID_PS': str(self.fake_ps),
            'REFINEID_UI_POLL_SECONDS': '0.01',
            'REFINEID_PAIRING_TIMEOUT_SECONDS': '5.0',
            'REFINEID_LOGIN_TIMEOUT_SECONDS': '5.0',
            'REFINEID_EMU_EXIT_WAIT_SECONDS': '1.0',
            'FAKE_ADB_LOG': str(self.adb_log),
            'FAKE_ADB_STDIN_LOG': str(self.adb_stdin_log),
            'FAKE_GRADLE_LOG': str(self.gradle_log),
            'FAKE_TOOL_LOG': str(self.tool_log),
            'FAKE_ADB_DEVICES': 'emulator-5554\tdevice\n192.0.2.10:5555\tdevice\n',
            'FAKE_ADB_INSTRUMENT_OUT': (
                'fi.refineid.android.ExampleTest:.\r\n\r\nTime: 0.25\r\n\r\nOK (1 test)\r\n'
            ),
        })
        env.update(overrides)
        return env

    def run_py(self, script_name: str, *args: str, **env_overrides: str):
        return subprocess.run(
            [sys.executable, '-B', '-W', 'error', str(self.scripts / script_name), *args],
            cwd=self.root,
            env=self.base_env(**env_overrides),
            text=True,
            capture_output=True,
            check=False,
        )

    def run_install(self, *args: str, **env_overrides: str):
        return subprocess.run(
            ['bash', str(self.scripts / 'install-device.sh'), *args],
            cwd=self.root,
            env=self.base_env(**env_overrides),
            text=True,
            capture_output=True,
            check=False,
        )

    def read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return path.read_text(encoding='utf-8').splitlines()

    def clear_logs(self) -> None:
        for log in (self.adb_log, self.adb_stdin_log, self.gradle_log, self.tool_log):
            if log.exists():
                log.unlink()

    def assert_connected_test_targeted(self, serial: str) -> None:
        adb_calls = self.read_lines(self.adb_log)
        self.assertEqual(len(adb_calls), 4, msg=f'unexpected adb calls: {adb_calls}')
        self.assertEqual(adb_calls[0], 'devices')
        self.assertEqual(
            adb_calls[1],
            f'-s {serial} install -r -t app/build/outputs/apk/debug/app-debug.apk',
        )
        self.assertEqual(
            adb_calls[2],
            f'-s {serial} install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk',
        )
        self.assertTrue(
            adb_calls[3].startswith(f'-s {serial} shell am instrument -w '),
            msg=f'unexpected instrumentation target: {adb_calls[3]}',
        )

    def test_adb_ui_cleanup_budgets_switch_verification_and_stdin_secrecy(self):
        old_env = os.environ.copy()
        old_cleanup_timeout = adb_ui.CLEANUP_TIMEOUT_SECONDS
        try:
            env = self.base_env(FAKE_ADB_FAIL_DUMP='1')
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.AdbError):
                adb_ui.dump_nodes(str(self.fake_adb), 'emulator-5554')
            calls = self.read_lines(self.adb_log)
            rm_calls = [line for line in calls if 'shell rm -f /data/local/tmp/refineid-ui-' in line]
            self.assertEqual(len(rm_calls), 1, msg=f'expected cleanup after failed dump: {calls}')

            self.clear_logs()
            env = self.base_env(FAKE_ADB_FAIL_CAT='1')
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.AdbError):
                adb_ui.dump_nodes(str(self.fake_adb), 'emulator-5554')
            calls = self.read_lines(self.adb_log)
            rm_calls = [line for line in calls if 'shell rm -f /data/local/tmp/refineid-ui-' in line]
            self.assertEqual(len(rm_calls), 1, msg=f'expected cleanup after failed cat: {calls}')

            self.clear_logs()
            env = self.base_env(FAKE_ADB_FAIL_RM='1', FAKE_ADB_UI_XML='<hierarchy/>')
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.DumpCleanupError) as ctx:
                adb_ui.wait_for_tag(str(self.fake_adb), 'emulator-5554', 'mainScreen', timeout=0.5, poll_seconds=0.01)
            self.assertIn('remove UI dump', str(ctx.exception))

            # Stalled cleanup must share one deadline across retries rather than doubling it.
            self.clear_logs()
            adb_ui.CLEANUP_TIMEOUT_SECONDS = 0.12
            env = self.base_env(FAKE_ADB_SLEEP_RM='0.5', FAKE_ADB_UI_XML='<hierarchy/>')
            os.environ.clear()
            os.environ.update(env)
            start = time.monotonic()
            with self.assertRaises(adb_ui.DumpCleanupError):
                adb_ui.dump_nodes(str(self.fake_adb), 'emulator-5554')
            cleanup_elapsed = time.monotonic() - start
            rm_calls = [
                line for line in self.read_lines(self.adb_log)
                if 'shell rm -f /data/local/tmp/refineid-ui-' in line
            ]
            self.assertEqual(len(rm_calls), 1, msg=f'stalled cleanup should not start second attempt: {rm_calls}')
            self.assertLess(cleanup_elapsed, 0.45)
            adb_ui.CLEANUP_TIMEOUT_SECONDS = old_cleanup_timeout

            # Stalled initial switch lookup must honor set_switch's timeout budget from entry.
            self.clear_logs()
            env = self.base_env(FAKE_ADB_SLEEP_DUMP='0.5', FAKE_ADB_UI_XML='<hierarchy/>')
            os.environ.clear()
            os.environ.update(env)
            start = time.monotonic()
            with self.assertRaises(adb_ui.AdbError):
                adb_ui.set_switch(str(self.fake_adb), 'emulator-5554', 'requesterRemoteUseSwitch', False, timeout=0.12, poll_seconds=0.01)
            self.assertLess(time.monotonic() - start, 0.5)

            # Missing switch during transient UI redraw must NEVER count as confirmed False.
            # Use a deterministic clock and record successful XML reads so we prove the
            # loop literally observed checked -> missing -> checked.
            self.clear_logs()
            checked_xml = '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/></hierarchy>'
            switch_state = self.root / 'switch-disappear.json'
            ui_reads_log = self.root / 'ui-reads.log'
            switch_state.write_text(
                json.dumps({
                    'emulator-5554': [
                        checked_xml,
                        '<hierarchy/>',
                        checked_xml,
                    ],
                }),
                encoding='utf-8',
            )
            env = self.base_env(
                FAKE_UI_STATE=str(switch_state),
                FAKE_UI_READS_LOG=str(ui_reads_log),
            )
            os.environ.clear()
            os.environ.update(env)
            fake_clock = [0.0]
            orig_monotonic = adb_ui.time.monotonic
            orig_sleep = adb_ui.time.sleep
            def step_monotonic() -> float:
                return fake_clock[0]
            def step_sleep(secs: float) -> None:
                fake_clock[0] += max(secs, 0.05)
            adb_ui.time.monotonic = step_monotonic
            adb_ui.time.sleep = step_sleep
            try:
                with self.assertRaises(adb_ui.AdbError) as ctx:
                    adb_ui.set_switch(
                        str(self.fake_adb),
                        'emulator-5554',
                        'requesterRemoteUseSwitch',
                        False,
                        timeout=0.10,
                        poll_seconds=0.05,
                    )
                self.assertIn('did not turn false', str(ctx.exception))
            finally:
                adb_ui.time.monotonic = orig_monotonic
                adb_ui.time.sleep = orig_sleep
            observed_reads = self.read_lines(ui_reads_log)
            self.assertEqual(
                observed_reads,
                [
                    f'emulator-5554:{checked_xml}',
                    'emulator-5554:<hierarchy/>',
                    f'emulator-5554:{checked_xml}',
                ],
                msg=f'expected exact checked -> missing -> checked sequence, got: {observed_reads}',
            )

            # launch_refineid and open_refineid must fail immediately on zero-exit `Error:` from am start.
            self.clear_logs()
            env = self.base_env(
                FAKE_ADB_AM_START_OUT='Starting: Intent {...}\nError: Activity class does not exist.\n',
                FAKE_ADB_UI_XML='<hierarchy/>',
            )
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.AdbError) as ctx:
                adb_ui.launch_refineid(str(self.fake_adb), 'emulator-5554', timeout=5.0, poll_seconds=0.01)
            self.assertIn('failed to start RefineID', str(ctx.exception))
            self.assertFalse(any('uiautomator dump' in line for line in self.read_lines(self.adb_log)))

            # open_refineid must abort on failed launch and on focus loss without sending Back to another app.
            self.clear_logs()
            env = self.base_env(FAKE_ADB_FAIL_AM_START='1', FAKE_ADB_UI_XML='<hierarchy/>')
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.AdbError):
                adb_ui.open_refineid(str(self.fake_adb), 'emulator-5554', timeout=0.2, poll_seconds=0.01)
            self.assertFalse(any('KEYCODE_BACK' in line for line in self.read_lines(self.adb_log)))

            self.clear_logs()
            focus_seq = self.root / 'open-focus-seq.json'
            focus_seq.write_text(
                json.dumps([
                    '  mCurrentFocus=Window{1 u0 fi.refineid.android/fi.refineid.android.MainActivity}\n',
                    '  mCurrentFocus=Window{2 u0 com.android.launcher3/Launcher}\n',
                ]),
                encoding='utf-8',
            )
            env = self.base_env(
                FAKE_ADB_FOCUS_STATE=str(focus_seq),
                FAKE_ADB_UI_XML='<hierarchy/>',
            )
            os.environ.clear()
            os.environ.update(env)
            with self.assertRaises(adb_ui.AdbError) as ctx:
                adb_ui.open_refineid(str(self.fake_adb), 'emulator-5554', timeout=0.2, poll_seconds=0.01)
            self.assertIn('focused window', str(ctx.exception))
            back_calls = [line for line in self.read_lines(self.adb_log) if 'KEYCODE_BACK' in line]
            self.assertEqual(len(back_calls), 1, msg=f'expected exactly one Back before focus loss: {back_calls}')

            self.clear_logs()
            env = self.base_env(FAKE_ADB_FAIL_INPUT_TEXT='1')
            os.environ.clear()
            os.environ.update(env)
            secret_code = '739184'
            with self.assertRaises(adb_ui.AdbError) as ctx:
                adb_ui.type_text(str(self.fake_adb), 'emulator-5554', secret_code)
            self.assertNotIn(secret_code, str(ctx.exception))
            self.assertNotIn(secret_code, '\n'.join(self.read_lines(self.adb_log)))
            self.assertIn(f'emulator-5554: input text {secret_code}', self.read_lines(self.adb_stdin_log))

            self.clear_logs()
            env = self.base_env(FAKE_ADB_SLEEP_INPUT_TEXT='0.5')
            os.environ.clear()
            os.environ.update(env)
            timed_out_tb = ''
            try:
                adb_ui.type_text(str(self.fake_adb), 'emulator-5554', secret_code, timeout=0.05)
            except adb_ui.AdbError:
                timed_out_tb = traceback.format_exc()
            self.assertIn('timed out', timed_out_tb)
            self.assertNotIn(secret_code, timed_out_tb)
            self.assertNotIn(secret_code, '\n'.join(self.read_lines(self.adb_log)))
            self.assertEqual(adb_ui.bounds_center('[10,20][30,40]'), (20, 30))
        finally:
            adb_ui.CLEANUP_TIMEOUT_SECONDS = old_cleanup_timeout
            os.environ.clear()
            os.environ.update(old_env)

    def test_connected_test_refuses_ambiguous_or_offline_mixed_devices(self):
        result = self.run_py('connected-test.py')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', result.stderr)
        self.assertEqual(self.read_lines(self.gradle_log), [])

        mixed = self.run_py(
            'connected-test.py',
            FAKE_ADB_DEVICES='emulator-5554\toffline\n192.0.2.10:5555\tdevice\n',
        )
        self.assertNotEqual(mixed.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', mixed.stderr)
        self.assertEqual(self.read_lines(self.gradle_log), [])

    def test_connected_test_emulator_targets_only_emulator_with_shell_quoting(self):
        result = self.run_py(
            'connected-test.py',
            '--emulator',
            '--class',
            'fi.refineid.android.FooTest#methodOne',
            '--class',
            'fi.refineid.android.BarTest',
            '-e',
            'refineidLivePin2Preflight',
            'true',
            '-e',
            'note',
            "a 'quoted' $val",
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(
            self.read_lines(self.gradle_log),
            [':app:assembleDebug :app:assembleDebugAndroidTest'],
        )
        self.assert_connected_test_targeted('emulator-5554')
        remote_tokens = shlex.split(self.read_lines(self.adb_log)[3].split('shell ', 1)[1])
        self.assertEqual(
            remote_tokens,
            [
                'am',
                'instrument',
                '-w',
                '-e',
                'class',
                'fi.refineid.android.FooTest#methodOne,fi.refineid.android.BarTest',
                '-e',
                'refineidLivePin2Preflight',
                'true',
                '-e',
                'note',
                "a 'quoted' $val",
                'fi.refineid.android.test/androidx.test.runner.AndroidJUnitRunner',
            ],
        )

    def test_connected_test_selectors_standard_mdns_and_explicit_over_env_precedence(self):
        wifi = self.run_py('connected-test.py', '--wifi-phone')
        self.assertEqual(wifi.returncode, 0, msg=wifi.stderr)
        self.assert_connected_test_targeted('192.0.2.10:5555')

        for mdns_serial in (
            'adb-phone123-abcdef._adb-tls-connect._tcp',
            'adb-phone123-abcdef._adb-tls-connect._tcp.',
        ):
            with self.subTest(mdns=mdns_serial):
                self.clear_logs()
                mdns_wifi = self.run_py(
                    'connected-test.py',
                    '--wifi-phone',
                    FAKE_ADB_DEVICES=f'{mdns_serial}\tdevice\nemulator-5554\tdevice\n',
                )
                self.assertEqual(mdns_wifi.returncode, 0, msg=mdns_wifi.stderr)
                self.assert_connected_test_targeted(mdns_serial)

        self.clear_logs()
        env_serial = self.run_py('connected-test.py', ANDROID_SERIAL='emulator-5554')
        self.assertEqual(env_serial.returncode, 0, msg=env_serial.stderr)
        self.assert_connected_test_targeted('emulator-5554')

        # Explicit selector must override conflicting ANDROID_SERIAL.
        self.clear_logs()
        explicit_over_env = self.run_py(
            'connected-test.py',
            '--wifi-phone',
            ANDROID_SERIAL='emulator-5554',
        )
        self.assertEqual(explicit_over_env.returncode, 0, msg=explicit_over_env.stderr)
        self.assert_connected_test_targeted('192.0.2.10:5555')

        self.clear_logs()
        explicit_serial_over_env = self.run_py(
            'connected-test.py',
            '--serial',
            '192.0.2.10:5555',
            ANDROID_SERIAL='emulator-5554',
        )
        self.assertEqual(explicit_serial_over_env.returncode, 0, msg=explicit_serial_over_env.stderr)
        self.assert_connected_test_targeted('192.0.2.10:5555')

        self.clear_logs()
        single = self.run_py('connected-test.py', FAKE_ADB_DEVICES='emulator-5554\tdevice\n')
        self.assertEqual(single.returncode, 0, msg=single.stderr)
        self.assert_connected_test_targeted('emulator-5554')

        offline = self.run_py('connected-test.py', '--serial', 'emulator-5556')
        self.assertNotEqual(offline.returncode, 0)
        self.assertIn('not online', offline.stderr)

        conflict = self.run_py('connected-test.py', '--emulator', '--wifi-phone')
        self.assertEqual(conflict.returncode, 2)

        dup_class = self.run_py('connected-test.py', '--emulator', '--class', 'A', '-e', 'class', 'B')
        self.assertEqual(dup_class.returncode, 2)

    def test_connected_test_fails_on_install_failure_and_bad_or_contradictory_output(self):
        for apk_name in ('app-debug.apk', 'app-debug-androidTest.apk'):
            with self.subTest(apk=apk_name):
                self.clear_logs()
                result = self.run_py(
                    'connected-test.py',
                    '--emulator',
                    FAKE_ADB_INSTALL_FAIL_APK=apk_name,
                    FAKE_ADB_INSTALL_FAIL_RC='0',
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('failed to install', result.stderr)
                self.assertIn('INSTALL_FAILED_UPDATE_INCOMPATIBLE', result.stderr)
                self.assertFalse(any('am instrument' in line for line in self.read_lines(self.adb_log)))

        cases = [
            ('failures', 'FAILURES!!!\nTests run: 2,  Failures: 1\n', '0'),
            ('crash', 'INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n', '0'),
            ('aborted_after_ok', 'OK (1 test)\nINSTRUMENTATION_ABORTED: system died\n', '0'),
            ('trailing_garbage_after_ok', 'OK (1 test)\nunexpected crash trailer\n', '0'),
            ('runner_missing', 'INSTRUMENTATION_FAILED: runner\n', '0'),
            ('zero_tests', 'Time: 0.01\n\nOK (0 tests)\n', '0'),
            ('nonzero_shell', 'OK (1 test)\n', '1'),
            ('missing_summary', 'unexpected output\n', '0'),
        ]
        for name, output, rc in cases:
            with self.subTest(case=name):
                result = self.run_py(
                    'connected-test.py',
                    '--emulator',
                    FAKE_ADB_INSTRUMENT_OUT=output,
                    FAKE_ADB_INSTRUMENT_RC=rc,
                )
                self.assertNotEqual(result.returncode, 0, msg=f'{name} unexpectedly succeeded')

    def test_connected_test_no_build_skips_gradle(self):
        for rel in (adb_ui.APP_DEBUG_APK, adb_ui.TEST_DEBUG_APK):
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'prebuilt')
        result = self.run_py('connected-test.py', '--emulator', '--no-build')
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.read_lines(self.gradle_log), [])

    def test_rapp_tablet_pair_validates_targets_hides_code_from_argv_and_redacts_failure_ui(self):
        same_target = self.run_py(
            'rapp-tablet-pair.py',
            '--phone',
            'emulator-5554',
            '--tablet',
            'emulator-5554',
        )
        self.assertNotEqual(same_target.returncode, 0)
        self.assertIn('distinct', same_target.stderr)

        offline_tablet = self.run_py(
            'rapp-tablet-pair.py',
            '--phone',
            '192.0.2.10:5555',
            '--tablet',
            'emulator-9999',
        )
        self.assertNotEqual(offline_tablet.returncode, 0)
        self.assertIn('not online', offline_tablet.stderr)
        self.assertEqual(self.read_lines(self.adb_log), ['devices', 'devices'])

        # Dual transports (USB + Wi-Fi) pointing to the same physical phone must abort before mutation,
        # including when ro.serialno succeeds on one transport and falls back to android_id on the other.
        self.clear_logs()
        same_hw = self.run_py(
            'rapp-tablet-pair.py',
            '--phone',
            '192.0.2.10:5555',
            '--tablet',
            'USB123',
            FAKE_ADB_DEVICES='USB123\tdevice\n192.0.2.10:5555\tdevice\n',
            FAKE_DEVICE_SERIALNOS=json.dumps({'USB123': 'HW999', '192.0.2.10:5555': 'HW999'}),
        )
        self.assertNotEqual(same_hw.returncode, 0)
        self.assertIn('same physical device', same_hw.stderr)
        self.assertFalse(any('am start' in line or 'am force-stop' in line for line in self.read_lines(self.adb_log)))

        self.clear_logs()
        asymmetric_hw = self.run_py(
            'rapp-tablet-pair.py',
            '--phone',
            '192.0.2.10:5555',
            '--tablet',
            'USB123',
            FAKE_ADB_DEVICES='USB123\tdevice\n192.0.2.10:5555\tdevice\n',
            FAKE_DEVICE_SERIALNOS=json.dumps({'USB123': 'HW999', '192.0.2.10:5555': 'unknown'}),
            FAKE_DEVICE_ANDROID_IDS=json.dumps({'USB123': 'SAME-AID', '192.0.2.10:5555': 'SAME-AID'}),
        )
        self.assertNotEqual(asymmetric_hw.returncode, 0)
        self.assertIn('same physical device', asymmetric_hw.stderr)
        self.assertFalse(any('am start' in line or 'am force-stop' in line for line in self.read_lines(self.adb_log)))

        # Happy path: code delivered via shell -T stdin and absent from argv, stdout, and stderr.
        self.clear_logs()
        state_file = self.root / 'ui-state.json'
        state_file.write_text(
            json.dumps({
                '192.0.2.10:5555': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="cardRemoteAccessSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="offeringCodeText" text="482 917" bounds="[0,0][100,100]"/></hierarchy>',
                ],
                'emulator-5554': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterPairingScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/></hierarchy>',
                ],
            }),
            encoding='utf-8',
        )
        result = self.run_py('rapp-tablet-pair.py', FAKE_UI_STATE=str(state_file))
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], 'paired')
        self.assertNotIn('482917', result.stdout + result.stderr)
        self.assertNotIn('482 917', result.stdout + result.stderr)
        self.assertNotIn('482917', '\n'.join(self.read_lines(self.adb_log)))
        self.assertIn('-s emulator-5554 shell -T', self.read_lines(self.adb_log))
        self.assertIn('emulator-5554: input text 482917', self.read_lines(self.adb_stdin_log))

        # Focus loss before typing must abort and deliver NO pairing code to stdin.
        self.clear_logs()
        focus_loss_state = self.root / 'focus-loss-state.json'
        focus_loss_state.write_text(
            json.dumps({
                '192.0.2.10:5555': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="cardRemoteAccessSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="offeringCodeText" text="482 917" bounds="[0,0][100,100]"/></hierarchy>',
                ],
                'emulator-5554': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                ],
            }),
            encoding='utf-8',
        )
        focus_lost = self.run_py(
            'rapp-tablet-pair.py',
            FAKE_UI_STATE=str(focus_loss_state),
            FAKE_ADB_FOCUS='  mCurrentFocus=Window{999 u0 com.android.launcher3/com.android.launcher3.Launcher}\n',
        )
        self.assertNotEqual(focus_lost.returncode, 0)
        self.assertIn('focused window', focus_lost.stderr)
        self.assertEqual(self.read_lines(self.adb_stdin_log), [])
        self.assertNotIn('482917', focus_lost.stdout + focus_lost.stderr)

        # Mixed multi-display focus dump (null on one display, RefineID on another) must also abort.
        self.clear_logs()
        focus_loss_state.write_text(
            json.dumps({
                '192.0.2.10:5555': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="cardRemoteAccessSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="offeringCodeText" text="482 917" bounds="[0,0][100,100]"/></hierarchy>',
                ],
                'emulator-5554': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                ],
            }),
            encoding='utf-8',
        )
        mixed_focus = self.run_py(
            'rapp-tablet-pair.py',
            FAKE_UI_STATE=str(focus_loss_state),
            FAKE_ADB_FOCUS=(
                '  mCurrentFocus=null\n'
                '  mCurrentFocus=Window{1234 u0 fi.refineid.android/fi.refineid.android.MainActivity}\n'
            ),
        )
        self.assertNotEqual(mixed_focus.returncode, 0)
        self.assertIn('focused window', mixed_focus.stderr)
        self.assertEqual(self.read_lines(self.adb_stdin_log), [])

        # Digit-free pairingFailureReason text must never leak to stdout or stderr.
        sentinel = 'PrivateCustodianDeviceAlpha'
        fail_state = self.root / 'pair-fail-state.json'
        fail_state.write_text(
            json.dumps({
                '192.0.2.10:5555': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="cardRemoteAccessSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="offeringCodeText" text="482 917" bounds="[0,0][100,100]"/></hierarchy>',
                ],
                'emulator-5554': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="false" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="requesterRemoteUseSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    '<hierarchy><node resource-id="pairingCodeBoxes" bounds="[10,10][90,50]"/></hierarchy>',
                    f'<hierarchy><node resource-id="pairingFailure" bounds="[0,0][100,100]"/>'
                    f'<node resource-id="pairingFailureReason" text="{sentinel}" bounds="[0,0][100,100]"/></hierarchy>',
                ],
            }),
            encoding='utf-8',
        )
        pair_failed = self.run_py('rapp-tablet-pair.py', FAKE_UI_STATE=str(fail_state))
        self.assertNotEqual(pair_failed.returncode, 0)
        self.assertIn('tablet: pairing failed', pair_failed.stderr)
        self.assertNotIn(sentinel, pair_failed.stdout + pair_failed.stderr)

        # Non-digit 6-char text must be rejected before typing.
        bad_code_state = self.root / 'bad-code.json'
        bad_code_state.write_text(
            json.dumps({
                '192.0.2.10:5555': [
                    '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                    '<node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="RappPairingRow" bounds="[0,0][100,100]"/></hierarchy>',
                    '<hierarchy><node resource-id="cardRemoteAccessSwitch" checked="true" bounds="[0,0][100,100]"/>'
                    '<node resource-id="offeringCodeText" text="ABCDEF" bounds="[0,0][100,100]"/></hierarchy>',
                ],
            }),
            encoding='utf-8',
        )
        bad_code = self.run_py('rapp-tablet-pair.py', FAKE_UI_STATE=str(bad_code_state))
        self.assertNotEqual(bad_code.returncode, 0)
        self.assertIn('pairing code not readable', bad_code.stderr)

    def test_rapp_tablet_browser_login_tag_filter_clear_boundary_and_snapshots(self):
        traces = BROWSER_LOGIN.extract_browser_traces(
            '01-01 00:00:00.000 1 1 I RefineID: browser:client-certificate-request origin-allowed=true key-type-count=1 issuer-count=2\n'
            '01-01 00:00:00.100 1 1 I RefineID: browser:client-certificate-completed outcome=PROCEEDED\n'
            '01-01 00:00:00.150 1 1 I OtherTag: fake RefineID: browser:signature status=SUCCEEDED\n'
            '01-01 00:00:00.200 1 1 I RefineID: browser:signature status=UNKNOWN_SECRET_STATUS\n'
            '01-01 00:00:00.220 1 1 I RefineID: browser:client-certificate-completed outcome=UNKNOWN_OUTCOME\n'
            '01-01 00:00:00.250 1 1 I RefineID: previous event was browser:signature status=SUCCEEDED\n'
            '01-01 00:00:00.500 1 1 I RefineID: browser:unrecognized pin=123456\n'
            '01-01 00:00:01.000 1 1 I RefineID: browser:signature status=SUCCEEDED\n'
            '01-01 00:00:02.000 1 1 I RefineID: browser:tls-error primary-error=3\n'
        )
        self.assertEqual(
            [payload for _, _, payload in traces],
            [
                'browser:client-certificate-request origin-allowed=true key-type-count=1 issuer-count=2',
                'browser:client-certificate-completed outcome=PROCEEDED',
                'browser:signature status=SUCCEEDED',
                'browser:tls-error primary-error=3',
            ],
        )
        self.assertEqual(BROWSER_LOGIN.classify_traces(traces)[0], 'tls-error')
        self.assertEqual(BROWSER_LOGIN.classify_traces(traces[:3]), ('signed', '01-01 00:00:00.100 1 1'))
        self.assertEqual(
            BROWSER_LOGIN.classify_traces([('01-01 00:00:01.000 1 1', '1', 'browser:signature status=SUCCEEDED')]),
            ('', ''),
        )
        # Events from different PIDs must NEVER combine into a signed verdict.
        self.assertEqual(
            BROWSER_LOGIN.classify_traces([
                ('01-01 00:00:00.100 100 1', '100', 'browser:client-certificate-completed outcome=PROCEEDED'),
                ('01-01 00:00:00.200 200 1', '200', 'browser:signature status=SUCCEEDED'),
            ])[0],
            '',
        )
        self.assertEqual(
            BROWSER_LOGIN.extract_browser_traces(
                '01-01 00:00:00.100 100 1 I RefineID: browser:client-certificate-completed outcome=PROCEEDED\n'
                '01-01 00:00:00.200 200 1 I RefineID: browser:signature status=SUCCEEDED\n',
                expected_pid='100',
            ),
            [('01-01 00:00:00.100 100 1', '100', 'browser:client-certificate-completed outcome=PROCEEDED')],
        )
        # A successful request followed by a later rejected certificate request must fail.
        self.assertEqual(
            BROWSER_LOGIN.classify_traces([
                ('01-01 00:00:00.000 1 1', '1', 'browser:client-certificate-request origin-allowed=true key-type-count=1 issuer-count=1'),
                ('01-01 00:00:00.100 1 1', '1', 'browser:client-certificate-completed outcome=PROCEEDED'),
                ('01-01 00:00:00.200 1 1', '1', 'browser:signature status=SUCCEEDED'),
                ('01-01 00:00:01.000 1 1', '1', 'browser:client-certificate-request origin-allowed=false key-type-count=1 issuer-count=1'),
                ('01-01 00:00:01.100 1 1', '1', 'browser:client-certificate-completed outcome=ORIGIN_REJECTED'),
            ])[0],
            'certificate-rejected',
        )

        # Dual transports to the same physical phone must abort before mutation.
        self.clear_logs()
        same_hw_login = self.run_py(
            'rapp-tablet-browser-login.py',
            '--phone',
            '192.0.2.10:5555',
            '--tablet',
            'USB123',
            FAKE_ADB_DEVICES='USB123\tdevice\n192.0.2.10:5555\tdevice\n',
            FAKE_DEVICE_SERIALNOS=json.dumps({'USB123': 'HW999', '192.0.2.10:5555': 'HW999'}),
        )
        self.assertNotEqual(same_hw_login.returncode, 0)
        self.assertIn('same physical device', same_hw_login.stderr)
        self.assertFalse(any('am start' in line or 'am force-stop' in line for line in self.read_lines(self.adb_log)))

        bad_url = self.run_py('rapp-tablet-browser-login.py', '--url', 'http://example.invalid')
        self.assertEqual(bad_url.returncode, 2)

        def write_browser_ui_state(path: Path, final_tablet_node: str) -> None:
            path.write_text(
                json.dumps({
                    'emulator-5554': [
                        '<hierarchy><node resource-id="mainScreen" bounds="[0,0][100,100]"/>'
                        '<node resource-id="browserAction" bounds="[0,0][100,100]"/></hierarchy>',
                        '<hierarchy><node resource-id="browserAction" bounds="[0,0][100,100]"/></hierarchy>',
                        '<hierarchy><node resource-id="browserAction" bounds="[0,0][100,100]"/></hierarchy>',
                        '<hierarchy><node resource-id="browserUrlField" bounds="[0,0][100,100]"/></hierarchy>',
                        '<hierarchy><node resource-id="browserUrlField" bounds="[0,0][100,100]"/></hierarchy>',
                        final_tablet_node,
                    ],
                    '192.0.2.10:5555': ['<hierarchy/>'],
                }),
                encoding='utf-8',
            )

        signed_chunk = (
            '01-01 00:00:00.100 1 1 I RefineID: browser:client-certificate-completed outcome=PROCEEDED\n'
            '01-01 00:00:01.000 1 1 I RefineID: browser:signature status=SUCCEEDED\n'
        )

        # Pre-existing signed traces present before submitting URL must be cleared
        # immediately before KEYCODE_ENTER and never credited to the new navigation.
        self.clear_logs()
        stale_ui = self.root / 'login-stale-ui.json'
        write_browser_ui_state(
            stale_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        logcat_buffer = self.root / 'logcat-buffer.txt'
        logcat_buffer.write_text(signed_chunk, encoding='utf-8')
        stale_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(stale_ui),
            FAKE_ADB_LOGCAT_BUFFER=str(logcat_buffer),
            REFINEID_LOGIN_TIMEOUT_SECONDS='0.15',
            REFINEID_UI_POLL_SECONDS='0.01',
        )
        self.assertNotEqual(stale_run.returncode, 0)
        self.assertIn('no handshake outcome', stale_run.stderr)
        adb_calls = self.read_lines(self.adb_log)
        type_idx = adb_calls.index('-s emulator-5554 shell -T')
        clear_idx = adb_calls.index('-s emulator-5554 logcat -c')
        enter_idx = adb_calls.index('-s emulator-5554 shell input keyevent KEYCODE_ENTER')
        self.assertTrue(type_idx < clear_idx < enter_idx, msg=f'bad logcat -c order: {adb_calls}')

        # Focus loss at each boundary (before Ctrl+A, Del, type_text, and Enter) must block
        # that action and every subsequent editing/submit action.
        refineid_focus = '  mCurrentFocus=Window{1234 u0 fi.refineid.android/fi.refineid.android.MainActivity}\n'
        other_focus = '  mCurrentFocus=Window{888 u0 com.android.notes/EditorActivity}\n'
        focus_boundaries = [
            ('before_ctrl_a', [other_focus], ('keycombination', 'KEYCODE_DEL', 'shell -T', 'KEYCODE_ENTER')),
            ('before_del', [refineid_focus, other_focus], ('KEYCODE_DEL', 'shell -T', 'KEYCODE_ENTER')),
            ('before_type', [refineid_focus, refineid_focus, other_focus], ('shell -T', 'KEYCODE_ENTER')),
            ('before_enter', [refineid_focus, refineid_focus, refineid_focus, other_focus], ('KEYCODE_ENTER',)),
        ]
        for case_name, queue, forbidden in focus_boundaries:
            with self.subTest(focus_boundary=case_name):
                self.clear_logs()
                focus_ui = self.root / f'login-focus-{case_name}.json'
                write_browser_ui_state(
                    focus_ui,
                    '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
                )
                focus_q = self.root / f'login-focus-q-{case_name}.json'
                focus_q.write_text(json.dumps(queue), encoding='utf-8')
                res = self.run_py(
                    'rapp-tablet-browser-login.py',
                    FAKE_UI_STATE=str(focus_ui),
                    FAKE_ADB_FOCUS_STATE=str(focus_q),
                )
                self.assertNotEqual(res.returncode, 0)
                self.assertIn('focused window', res.stderr)
                calls = self.read_lines(self.adb_log)
                for marker in forbidden:
                    self.assertFalse(
                        any(marker in line for line in calls),
                        msg=f'{case_name}: unexpected {marker} after focus loss: {calls}',
                    )

        # Signed traces while launcher (not RefineID browser) is visible must NOT confirm success,
        # and the test must observe at least two logcat reads to prove the marker check withheld it.
        self.clear_logs()
        launcher_ui = self.root / 'login-launcher-ui.json'
        write_browser_ui_state(
            launcher_ui,
            '<hierarchy><node resource-id="launcherHome" bounds="[0,0][100,100]"/></hierarchy>',
        )
        launcher_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(launcher_ui),
            FAKE_ADB_LOGCAT=signed_chunk,
            REFINEID_LOGIN_TIMEOUT_SECONDS='1.5',
            REFINEID_UI_POLL_SECONDS='0.01',
        )
        self.assertNotEqual(launcher_run.returncode, 0)
        self.assertIn('no handshake outcome', launcher_run.stderr)
        launcher_logcat_reads = [
            line for line in self.read_lines(self.adb_log)
            if 'logcat -d' in line
        ]
        self.assertGreaterEqual(
            len(launcher_logcat_reads),
            2,
            msg=f'expected at least two signed logcat reads while launcher visible: {launcher_logcat_reads}',
        )

        # End-to-end mixed-PID traces must NOT confirm success when SUCCEEDED comes from another PID.
        self.clear_logs()
        mixed_pid_ui = self.root / 'login-mixed-pid-ui.json'
        write_browser_ui_state(
            mixed_pid_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        mixed_pid_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(mixed_pid_ui),
            FAKE_ADB_APP_PID='100',
            FAKE_ADB_LOGCAT=(
                '01-01 00:00:00.100 100 1 I RefineID: browser:client-certificate-completed outcome=PROCEEDED\n'
                '01-01 00:00:00.200 200 1 I RefineID: browser:signature status=SUCCEEDED\n'
            ),
            REFINEID_LOGIN_TIMEOUT_SECONDS='1.2',
            REFINEID_UI_POLL_SECONDS='0.01',
        )
        self.assertNotEqual(mixed_pid_run.returncode, 0)
        self.assertIn('no handshake outcome', mixed_pid_run.stderr)
        mixed_logcat_reads = [
            line for line in self.read_lines(self.adb_log)
            if 'logcat -d' in line
        ]
        self.assertGreaterEqual(len(mixed_logcat_reads), 2)

        # Tablet PIN field must fail immediately.
        pin_ui = self.root / 'login-pin-state.json'
        write_browser_ui_state(
            pin_ui,
            '<hierarchy><node resource-id="browserPin1Field" bounds="[0,0][100,100]"/></hierarchy>',
        )
        pin_leak = self.run_py('rapp-tablet-browser-login.py', FAKE_UI_STATE=str(pin_ui))
        self.assertNotEqual(pin_leak.returncode, 0)
        self.assertIn('browserPin1Field', pin_leak.stderr)

        # Trailing TLS error arriving in the snapshot after signature SUCCEEDED must fail.
        trailing_ui = self.root / 'login-trailing-ui.json'
        write_browser_ui_state(
            trailing_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        trailing_logcat = self.root / 'login-trailing-logcat.json'
        trailing_logcat.write_text(
            json.dumps([
                signed_chunk,
                signed_chunk + '01-01 00:00:01.500 1 1 I RefineID: browser:tls-error primary-error=3\n',
            ]),
            encoding='utf-8',
        )
        trailing_err = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(trailing_ui),
            FAKE_ADB_LOGCAT_STATE=str(trailing_logcat),
        )
        self.assertNotEqual(trailing_err.returncode, 0)
        self.assertIn('login failed: tls-error', trailing_err.stderr)

        # A successful first request followed by a rejected second request must fail.
        rejected_ui = self.root / 'login-rejected-ui.json'
        write_browser_ui_state(
            rejected_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        rejected_logcat = self.root / 'login-rejected-logcat.json'
        rejected_logcat.write_text(
            json.dumps([
                signed_chunk,
                signed_chunk
                + '01-01 00:00:01.200 1 1 I RefineID: browser:client-certificate-request origin-allowed=false key-type-count=1 issuer-count=1\n'
                + '01-01 00:00:01.300 1 1 I RefineID: browser:client-certificate-completed outcome=ORIGIN_REJECTED\n',
            ]),
            encoding='utf-8',
        )
        rejected_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(rejected_ui),
            FAKE_ADB_LOGCAT_STATE=str(rejected_logcat),
        )
        self.assertNotEqual(rejected_run.returncode, 0)
        self.assertIn('login failed: certificate-rejected', rejected_run.stderr)

        # Confirmation of request A must NOT carry over to request B, even when A ages out
        # of the logcat ring buffer (A only -> B only -> B + TLS error).
        chained_ui = self.root / 'login-chained-ui.json'
        write_browser_ui_state(
            chained_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        req_b_chunk = (
            '01-01 00:00:02.000 1 1 I RefineID: browser:client-certificate-request origin-allowed=true key-type-count=1 issuer-count=1\n'
            '01-01 00:00:02.100 1 1 I RefineID: browser:client-certificate-completed outcome=PROCEEDED\n'
            '01-01 00:00:02.200 1 1 I RefineID: browser:signature status=SUCCEEDED\n'
        )
        chained_logcat = self.root / 'login-chained-logcat.json'
        chained_logcat.write_text(
            json.dumps([
                signed_chunk,
                req_b_chunk,
                req_b_chunk + '01-01 00:00:02.500 1 1 I RefineID: browser:tls-error primary-error=3\n',
            ]),
            encoding='utf-8',
        )
        chained_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(chained_ui),
            FAKE_ADB_LOGCAT_STATE=str(chained_logcat),
        )
        self.assertNotEqual(chained_run.returncode, 0)
        self.assertIn('login failed: tls-error', chained_run.stderr)

        # Clean successive snapshots report narrowed signature success.
        ok_ui = self.root / 'login-ok-ui.json'
        write_browser_ui_state(
            ok_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        ok_logcat = self.root / 'login-ok-logcat.json'
        ok_logcat.write_text(
            json.dumps([
                '01-01 00:00:00.000 1 1 I RefineID: browser:client-certificate-request origin-allowed=true key-type-count=1 issuer-count=1\n',
                signed_chunk,
                signed_chunk,
            ]),
            encoding='utf-8',
        )
        ok_run = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(ok_ui),
            FAKE_ADB_LOGCAT_STATE=str(ok_logcat),
        )
        self.assertEqual(ok_run.returncode, 0, msg=ok_run.stderr)
        self.assertEqual(ok_run.stdout.splitlines()[-1], 'client-certificate signature succeeded')

        # Absolute deadline must not be multiplied across dump/cat/phone/logcat calls.
        slow_ui = self.root / 'login-slow-ui.json'
        write_browser_ui_state(
            slow_ui,
            '<hierarchy><node resource-id="browserView" bounds="[0,0][100,100]"/></hierarchy>',
        )
        start = time.monotonic()
        timed_out = self.run_py(
            'rapp-tablet-browser-login.py',
            FAKE_UI_STATE=str(slow_ui),
            FAKE_ADB_LOGCAT='',
            FAKE_ADB_SLEEP_DUMP='0.04',
            REFINEID_LOGIN_TIMEOUT_SECONDS='0.25',
            REFINEID_UI_POLL_SECONDS='0.01',
        )
        elapsed = time.monotonic() - start
        self.assertNotEqual(timed_out.returncode, 0)
        self.assertIn('no handshake outcome', timed_out.stderr)
        self.assertLess(elapsed, 2.5, msg=f'login deadline exceeded by too much: {elapsed:.2f}s')

    def test_start_and_stop_tablet_emulator_avd_binding_and_scoped_ownership_repair(self):
        self.assertTrue(START_EMU.same_ipv4_network('192.0.2.10', '255.255.255.0', '192.0.2.42'))
        self.assertFalse(START_EMU.same_ipv4_network('192.0.2.10', '255.255.255.0', '10.0.2.15'))
        self.assertEqual(
            START_EMU.parse_wlan0_ipv4('3: wlan0    inet 192.0.2.42/24 brd 192.0.2.255 scope global wlan0\n'),
            '192.0.2.42',
        )
        avd_home = self.root / 'avd'
        image_dir = 'system-images/android-35/google_apis_playstore_tablet/arm64-v8a'
        self.assertTrue(START_EMU.ensure_avd_created(avd_home, image_dir))
        self.assertFalse(START_EMU.ensure_avd_created(avd_home, image_dir))
        # Partial AVD (missing config.ini) must be recreated.
        (avd_home / 'refineid_tablet.avd' / 'config.ini').unlink()
        self.assertTrue(START_EMU.ensure_avd_created(avd_home, image_dir))

        # Verify start-tablet-emulator preserves the controlling TTY for sudo (no start_new_session),
        # uses `sudo -v` then `sudo -n`, and creates an atomic temp log file.
        fake_sdk = self.root / 'fake-sdk'
        make_executable(fake_sdk / 'emulator' / 'emulator', '#!/bin/sh\nexit 0\n')
        (fake_sdk / image_dir).mkdir(parents=True)
        fake_emu_home = self.root / 'start-emu-home'
        fake_emu_home.mkdir()
        popen_calls: list[tuple[list[str], dict[str, object]]] = []
        sudo_v_calls: list[list[str]] = []

        class _FakeProc:
            def poll(self):
                return 1  # triggers immediate exit after Popen capture

        orig_run = START_EMU.subprocess.run
        orig_popen = START_EMU.subprocess.Popen

        def _fake_run(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd[:2] == [str(self.fake_tool), '-v']:
                sudo_v_calls.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
            return orig_run(cmd, *args, **kwargs)

        def _fake_popen(cmd, *args, **kwargs):
            if isinstance(cmd, list) and cmd[:2] == [str(self.fake_tool), '-n']:
                popen_calls.append((list(cmd), dict(kwargs)))
                return _FakeProc()
            return orig_popen(cmd, *args, **kwargs)

        old_env = os.environ.copy()
        orig_platform = START_EMU.platform.system
        orig_cwd = Path.cwd()
        try:
            env = self.base_env(
                ANDROID_HOME=str(fake_sdk),
                ANDROID_EMULATOR_HOME=str(fake_emu_home),
                FAKE_ADB_DEVICES='',
            )
            os.environ.clear()
            os.environ.update(env)
            START_EMU.platform.system = lambda: 'Darwin'
            START_EMU.subprocess.run = _fake_run
            START_EMU.subprocess.Popen = _fake_popen
            rc = START_EMU.main(['en0'])
            self.assertEqual(rc, 1)  # _FakeProc.poll() returned 1 (exited during boot)
        finally:
            os.chdir(orig_cwd)
            START_EMU.platform.system = orig_platform
            START_EMU.subprocess.run = orig_run
            START_EMU.subprocess.Popen = orig_popen
            os.environ.clear()
            os.environ.update(old_env)
        self.assertEqual(len(sudo_v_calls), 1)
        self.assertEqual(len(popen_calls), 1)
        launch_cmd, launch_kwargs = popen_calls[0]
        self.assertEqual(launch_cmd[:3], [str(self.fake_tool), '-n', 'env'])
        self.assertFalse(launch_kwargs.get('start_new_session', False))
        self.assertEqual(launch_kwargs.get('stdin'), subprocess.DEVNULL)
        log_handle = launch_kwargs.get('stdout')
        self.assertIsNotNone(log_handle)
        log_path = Path(log_handle.name)
        self.assertTrue(log_path.name.startswith('refineid_tablet-emulator-'))
        if log_path.exists():
            log_path.unlink()

        owner_spec = f'{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}'
        android_home = self.root / 'dot-android'
        (android_home / 'avd' / 'refineid_tablet.avd').mkdir(parents=True)
        (android_home / 'avd' / 'refineid_tablet.ini').write_text('target=android-35\n', encoding='utf-8')
        (android_home / 'metrics').mkdir()
        (android_home / 'unrelated-workspace').mkdir()
        devices_state = self.root / 'devices-state.json'
        devices_state.write_text(
            json.dumps(['emulator-5554\tdevice', 'emulator-5556\tdevice']),
            encoding='utf-8',
        )
        # Only emulator-5556 is refineid_tablet; stop must kill 5556, leave 5554 untouched,
        # place `--` before owner:group for BSD chown, and target ONLY known emulator state.
        stop_result = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_DEVICES_STATE=str(devices_state),
            FAKE_EMU_AVD_NAMES=json.dumps({'emulator-5554': 'other_avd', 'emulator-5556': 'refineid_tablet'}),
        )
        self.assertEqual(stop_result.returncode, 0, msg=stop_result.stderr)
        adb_calls = self.read_lines(self.adb_log)
        self.assertIn('-s emulator-5556 emu kill', adb_calls)
        self.assertNotIn('-s emulator-5554 emu kill', adb_calls)
        tool_calls = self.read_lines(self.tool_log)
        self.assertEqual(len(tool_calls), 1)
        chown_tokens = tool_calls[0].split()
        self.assertEqual(chown_tokens[:4], ['chown', '-R', '--', owner_spec])
        chown_paths = chown_tokens[4:]
        self.assertIn(str((android_home / 'avd' / 'refineid_tablet.avd').resolve()), chown_paths)
        self.assertIn(str((android_home / 'avd' / 'refineid_tablet.ini').resolve()), chown_paths)
        self.assertIn(str((android_home / 'metrics').resolve()), chown_paths)
        self.assertNotIn(str(android_home.resolve()), chown_paths)
        self.assertNotIn(str((android_home / 'unrelated-workspace').resolve()), chown_paths)

        # Ancestor ANDROID_EMULATOR_HOME with nested ANDROID_AVD_HOME must NOT touch
        # sibling cache/ in the ancestor directory.
        self.clear_logs()
        workspace_ancestor = self.root / 'workspace-ancestor'
        nested_avd_home = workspace_ancestor / 'android' / 'avd'
        (nested_avd_home / 'refineid_tablet.avd').mkdir(parents=True)
        (workspace_ancestor / 'cache').mkdir(parents=True)
        ancestor_stop = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(workspace_ancestor),
            ANDROID_AVD_HOME=str(nested_avd_home),
            FAKE_ADB_DEVICES='',
        )
        self.assertEqual(ancestor_stop.returncode, 0, msg=ancestor_stop.stderr)
        tool_calls = self.read_lines(self.tool_log)
        self.assertEqual(len(tool_calls), 1)
        chown_tokens = tool_calls[0].split()
        self.assertEqual(chown_tokens[:4], ['chown', '-R', '--', owner_spec])
        chown_paths = chown_tokens[4:]
        self.assertEqual(chown_paths, [str((nested_avd_home / 'refineid_tablet.avd').resolve())])
        self.assertNotIn(str((workspace_ancestor / 'cache').resolve()), chown_paths)

        # Unrelated existing directory with no refineid_tablet AVD must receive ZERO sudo chown calls.
        self.clear_logs()
        unrelated_parent = self.root / 'workspace-parent'
        (unrelated_parent / 'cache').mkdir(parents=True)
        (unrelated_parent / 'project').mkdir()
        unrelated_stop = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(unrelated_parent),
            FAKE_ADB_DEVICES='',
        )
        self.assertEqual(unrelated_stop.returncode, 0, msg=unrelated_stop.stderr)
        self.assertEqual(self.read_lines(self.tool_log), [])

        # Stuck emulator must fail and NOT invoke sudo chown.
        self.clear_logs()
        devices_state.write_text(json.dumps(['emulator-5554\tdevice']), encoding='utf-8')
        stuck = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_DEVICES_STATE=str(devices_state),
            FAKE_EMU_STUCK='1',
            REFINEID_EMU_EXIT_WAIT_SECONDS='0.05',
        )
        self.assertNotEqual(stuck.returncode, 0)
        self.assertIn('did not exit', stuck.stderr)
        self.assertEqual(self.read_lines(self.tool_log), [])

        # Offline emulator running from an SDK path containing spaces must still block sudo chown.
        spaced_comm = '/Volumes/Android SDK/emulator/qemu/darwin-aarch64/qemu-system-aarch64'
        offline_running = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_ADB_DEVICES='emulator-5554\toffline\n',
            FAKE_PS_PROCS=json.dumps([
                [42, spaced_comm, f'{spaced_comm} -avd refineid_tablet -no-snapshot'],
            ]),
        )
        self.assertNotEqual(offline_running.returncode, 0)
        self.assertIn('still running', offline_running.stderr)
        self.assertEqual(self.read_lines(self.tool_log), [])

        # Unrelated commands mentioning refineid_tablet, emulator path in argv[1:],
        # or `@refineid_tablet` inside another argument must NOT block repair.
        unrelated_proc = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_ADB_DEVICES='',
            FAKE_PS_PROCS=json.dumps([
                [10, '/usr/bin/tail', '/usr/bin/tail -f /tmp/refineid_tablet-emulator.log'],
                [11, '/bin/cat', '/bin/cat /sdk/emulator/emulator -avd refineid_tablet'],
                [12, '/sdk/emulator/emulator', '/sdk/emulator/emulator -foo user@refineid_tablet'],
                [13, '/sdk/emulator/emulator', '/sdk/emulator/emulator -avd refineid_tablet_other'],
            ]),
        )
        self.assertEqual(unrelated_proc.returncode, 0, msg=unrelated_proc.stderr)
        self.assertEqual(len(self.read_lines(self.tool_log)), 1)
        self.clear_logs()

        # Direct `@refineid_tablet` invocation (even with spaces in SDK path) MUST block repair.
        spaced_emu = '/Volumes/Android SDK/emulator/emulator'
        at_running = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_ADB_DEVICES='',
            FAKE_PS_PROCS=json.dumps([
                [43, spaced_emu, f'{spaced_emu} @refineid_tablet'],
            ]),
        )
        self.assertNotEqual(at_running.returncode, 0)
        self.assertIn('still running', at_running.stderr)
        self.assertEqual(self.read_lines(self.tool_log), [])

        # Process-lookup error must block ownership repair.
        ps_err = self.run_py(
            'stop-tablet-emulator.py',
            ANDROID_EMULATOR_HOME=str(android_home),
            FAKE_ADB_DEVICES='',
            FAKE_PS_RC='2',
        )
        self.assertNotEqual(ps_err.returncode, 0)
        self.assertIn('process lookup failed', ps_err.stderr)
        self.assertEqual(self.read_lines(self.tool_log), [])

        # Empty ANDROID_EMULATOR_HOME must fall back to ~/.android AVD state, NEVER repo root.
        fake_home = self.root / 'fake-home'
        fake_avd_dir = fake_home / '.android' / 'avd' / 'refineid_tablet.avd'
        fake_avd_dir.mkdir(parents=True)
        empty_home = self.run_py(
            'stop-tablet-emulator.py',
            HOME=str(fake_home),
            ANDROID_EMULATOR_HOME='',
            FAKE_ADB_DEVICES='',
        )
        self.assertEqual(empty_home.returncode, 0, msg=empty_home.stderr)
        tool_calls = self.read_lines(self.tool_log)
        self.assertEqual(len(tool_calls), 1)
        chown_tokens = tool_calls[0].split()
        self.assertEqual(chown_tokens[:4], ['chown', '-R', '--', owner_spec])
        self.assertEqual(chown_tokens[4:], [str(fake_avd_dir.resolve())])

    def test_artemis_refuses_multiple_devices_and_runs_selected_suite(self):
        artemis_dir = self.root / 'artemis'
        artemis_dir.mkdir()

        ambiguous = self.run_py('test-artemis.py', 'smoke', ARTEMIS_HOME=str(artemis_dir))
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', ambiguous.stderr)

        mixed_offline = self.run_py(
            'test-artemis.py',
            'smoke',
            ARTEMIS_HOME=str(artemis_dir),
            FAKE_ADB_DEVICES='emulator-5554\toffline\n192.0.2.10:5555\tdevice\n',
        )
        self.assertNotEqual(mixed_offline.returncode, 0)

        ok = self.run_py(
            'test-artemis.py',
            'smoke',
            '--serial',
            'emulator-5554',
            '--profile',
            'pro',
            ARTEMIS_HOME=str(artemis_dir),
        )
        self.assertEqual(ok.returncode, 0, msg=ok.stderr)
        self.assertNotIn('emulator-5554', ok.stdout)
        tool_calls = self.read_lines(self.tool_log)
        self.assertEqual(len(tool_calls), 1)
        self.assertIn('--device-serial emulator-5554 --profile pro', tool_calls[0])

        self.clear_logs()
        doctor = self.run_py('test-artemis.py', 'doctor', ARTEMIS_HOME=str(artemis_dir))
        self.assertEqual(doctor.returncode, 0, msg=doctor.stderr)
        self.assertEqual(self.read_lines(self.tool_log), ['run artemis doctor'])

    def test_install_device_assembles_installs_via_adb_s_mdns_and_empty_positional(self):
        # Empty positional serial must fail before invoking Gradle or adb.
        empty_pos = self.run_install('', ANDROID_SERIAL='192.0.2.10:5555')
        self.assertEqual(empty_pos.returncode, 2)
        self.assertEqual(self.read_lines(self.gradle_log), [])
        self.assertEqual(self.read_lines(self.adb_log), [])

        # Explicit --serial must override conflicting ANDROID_SERIAL.
        override = self.run_install(
            '--serial',
            'emulator-5554',
            ANDROID_SERIAL='192.0.2.10:5555',
        )
        self.assertEqual(override.returncode, 0, msg=override.stderr)
        adb_calls = self.read_lines(self.adb_log)
        self.assertEqual(
            adb_calls[1],
            '-s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk',
        )
        self.assertEqual(
            adb_calls[2],
            '-s emulator-5554 shell am start -n fi.refineid.android/.MainActivity',
        )

        # Default prefers sole Wi-Fi phone (IPv4 and standard mDNS) over emulator.
        for wifi_serial in (
            '192.0.2.10:5555',
            'adb-phone123-abcdef._adb-tls-connect._tcp',
            'adb-phone123-abcdef._adb-tls-connect._tcp.',
        ):
            with self.subTest(wifi=wifi_serial):
                self.clear_logs()
                result = self.run_install(
                    FAKE_ADB_DEVICES=f'emulator-5554\tdevice\n{wifi_serial}\tdevice\n',
                )
                self.assertEqual(result.returncode, 0, msg=result.stderr)
                gradle_calls = self.read_lines(self.gradle_log)
                self.assertEqual(len(gradle_calls), 1)
                self.assertTrue(gradle_calls[0].startswith(':app:assembleDebug -PversionName='))
                self.assertNotIn('installDebug', gradle_calls[0])
                adb_calls = self.read_lines(self.adb_log)
                self.assertEqual(
                    adb_calls[1],
                    f'-s {wifi_serial} install -r app/build/outputs/apk/debug/app-debug.apk',
                )
                self.assertEqual(
                    adb_calls[2],
                    f'-s {wifi_serial} shell am start -n fi.refineid.android/.MainActivity',
                )

        failed = self.run_install(
            '--serial',
            'emulator-5554',
            FAKE_ADB_INSTALL_FAIL_APK='app-debug.apk',
            FAKE_ADB_INSTALL_FAIL_RC='0',
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn('INSTALL_FAILED_UPDATE_INCOMPATIBLE', failed.stderr)

        # Zero-exit `Error:` from `am start` must fail instead of reporting installed and launched.
        launch_failed = self.run_install(
            '--serial',
            'emulator-5554',
            FAKE_ADB_AM_START_OUT='Starting: Intent {...}\nError: Activity class does not exist.\n',
        )
        self.assertNotEqual(launch_failed.returncode, 0)
        self.assertIn('failed to launch RefineID', launch_failed.stderr)
        self.assertNotIn('installed and launched', launch_failed.stdout)

        ambiguous = self.run_install(FAKE_ADB_DEVICES='emulator-5554\tdevice\nUSB123\toffline\n')
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', ambiguous.stderr)

    def test_dump_phone_diagnostics_targeting_privacy_and_broadcast_checks(self):
        # Multiple devices (online or mixed online+offline) must fail before any broadcast or clear.
        ambiguous = self.run_py('dump-phone-diagnostics.py', '--clear')
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', ambiguous.stderr)
        self.assertNotIn('emulator-5554', ambiguous.stderr)
        self.assertNotIn('192.0.2.10:5555', ambiguous.stderr)
        self.assertEqual(self.read_lines(self.adb_log), ['devices'])

        self.clear_logs()
        mixed = self.run_py(
            'dump-phone-diagnostics.py',
            '--clear',
            FAKE_ADB_DEVICES='emulator-5554\toffline\n192.0.2.10:5555\tdevice\n',
        )
        self.assertNotEqual(mixed.returncode, 0)
        self.assertIn('multiple Android devices attached (2)', mixed.stderr)
        self.assertNotIn('emulator-5554', mixed.stderr)
        self.assertNotIn('192.0.2.10:5555', mixed.stderr)
        self.assertEqual(self.read_lines(self.adb_log), ['devices'])

        # No attached devices fails cleanly.
        self.clear_logs()
        none_attached = self.run_py('dump-phone-diagnostics.py', FAKE_ADB_DEVICES='')
        self.assertNotEqual(none_attached.returncode, 0)
        self.assertIn('no connected Android device found', none_attached.stderr)

        # Empty serial and conflicting positional + target flag fail at arg parse without leaking serial.
        self.clear_logs()
        empty_pos = self.run_py('dump-phone-diagnostics.py', '')
        self.assertEqual(empty_pos.returncode, 2)
        conflict = self.run_py('dump-phone-diagnostics.py', '--emulator', '192.0.2.10:5555')
        self.assertEqual(conflict.returncode, 2)
        self.assertNotIn('192.0.2.10:5555', conflict.stderr)
        self.assertEqual(self.read_lines(self.adb_log), [])

        # Offline explicit target fails without leaking serial.
        self.clear_logs()
        offline_target = self.run_py(
            'dump-phone-diagnostics.py',
            '--serial',
            '192.0.2.10:5555',
            FAKE_ADB_DEVICES='192.0.2.10:5555\toffline\n',
        )
        self.assertNotEqual(offline_target.returncode, 0)
        self.assertIn("not online in 'adb devices'", offline_target.stderr)
        self.assertNotIn('192.0.2.10:5555', offline_target.stderr)
        self.assertEqual(self.read_lines(self.adb_log), ['devices'])

        # --clear targets the selected Wi-Fi phone and never prints the serial/IP.
        self.clear_logs()
        cleared = self.run_py('dump-phone-diagnostics.py', '--clear', '--wifi-phone')
        self.assertEqual(cleared.returncode, 0, msg=cleared.stderr)
        self.assertEqual(cleared.stdout, '')
        self.assertIn('Logs cleared.', cleared.stderr)
        self.assertNotIn('192.0.2.10:5555', cleared.stderr)
        self.assertNotIn('192.0.2.10:5555', cleared.stdout)
        self.assertEqual(
            self.read_lines(self.adb_log),
            [
                'devices',
                '-s 192.0.2.10:5555 shell am broadcast -a fi.refineid.android.CLEAR_LOGS -p fi.refineid.android',
            ],
        )

        # --emulator, ANDROID_SERIAL, and whitespace-padded --serial all target cleanly.
        self.clear_logs()
        emu_clear = self.run_py('dump-phone-diagnostics.py', '--clear', '--emulator')
        self.assertEqual(emu_clear.returncode, 0, msg=emu_clear.stderr)
        self.assertNotIn('emulator-5554', emu_clear.stderr)
        self.assertEqual(
            self.read_lines(self.adb_log)[1],
            '-s emulator-5554 shell am broadcast -a fi.refineid.android.CLEAR_LOGS -p fi.refineid.android',
        )

        self.clear_logs()
        env_dump = self.run_py(
            'dump-phone-diagnostics.py',
            ANDROID_SERIAL='emulator-5554',
            FAKE_ADB_DIAGNOSTICS_TEXT='env-ok\n',
        )
        self.assertEqual(env_dump.returncode, 0, msg=env_dump.stderr)
        self.assertEqual(env_dump.stdout, 'env-ok\n')
        self.assertEqual(
            self.read_lines(self.adb_log)[1],
            '-s emulator-5554 shell am broadcast -a fi.refineid.android.DUMP_DIAGNOSTICS -p fi.refineid.android',
        )

        self.clear_logs()
        padded_serial = self.run_py(
            'dump-phone-diagnostics.py',
            '--serial',
            '  192.0.2.10:5555  ',
            FAKE_ADB_DIAGNOSTICS_TEXT='padded-ok\n',
        )
        self.assertEqual(padded_serial.returncode, 0, msg=padded_serial.stderr)
        self.assertEqual(padded_serial.stdout, 'padded-ok\n')
        self.assertEqual(
            self.read_lines(self.adb_log)[1],
            '-s 192.0.2.10:5555 shell am broadcast -a fi.refineid.android.DUMP_DIAGNOSTICS -p fi.refineid.android',
        )

        # Positional serial overrides ANDROID_SERIAL and dumps diagnostics verbatim without leaking serial.
        self.clear_logs()
        dumped = self.run_py(
            'dump-phone-diagnostics.py',
            '192.0.2.10:5555',
            ANDROID_SERIAL='emulator-5554',
            FAKE_ADB_DIAGNOSTICS_TEXT='line-one\nline-two\n',
        )
        self.assertEqual(dumped.returncode, 0, msg=dumped.stderr)
        self.assertEqual(dumped.stdout, 'line-one\nline-two\n')
        self.assertEqual(dumped.stderr, '')
        self.assertEqual(
            self.read_lines(self.adb_log),
            [
                'devices',
                '-s 192.0.2.10:5555 shell am broadcast -a fi.refineid.android.DUMP_DIAGNOSTICS -p fi.refineid.android',
                '-s 192.0.2.10:5555 shell run-as fi.refineid.android cat files/diagnostics.txt',
            ],
        )

        # Unhandled or non-zero-result broadcasts fail before run-as without leaking serial.
        for label, extra_args, broadcast_out in (
            (
                'unhandled-dump',
                ['--serial', 'emulator-5554'],
                'Broadcasting: Intent {}\nBroadcast completed: result=0\n',
            ),
            (
                'nonzero-result-dump',
                ['--serial', 'emulator-5554'],
                'Broadcasting: Intent {}\nBroadcast completed: result=-1, data="DUMP_OK: 1"\n',
            ),
            (
                'unhandled-clear',
                ['--clear', '--serial', 'emulator-5554'],
                'Broadcasting: Intent {}\nBroadcast completed: result=0\n',
            ),
        ):
            with self.subTest(case=label):
                self.clear_logs()
                res = self.run_py(
                    'dump-phone-diagnostics.py',
                    *extra_args,
                    FAKE_ADB_BROADCAST_OUT=broadcast_out,
                )
                self.assertNotEqual(res.returncode, 0)
                self.assertIn('was not handled', res.stderr)
                self.assertNotIn('emulator-5554', res.stderr)
                self.assertEqual(len(self.read_lines(self.adb_log)), 2)

        # Non-zero adb exits for broadcast and run-as fail cleanly without leaking serial.
        self.clear_logs()
        bcast_fail = self.run_py(
            'dump-phone-diagnostics.py',
            '--serial',
            '192.0.2.10:5555',
            FAKE_ADB_FAIL_BROADCAST='1',
        )
        self.assertNotEqual(bcast_fail.returncode, 0)
        self.assertNotIn('192.0.2.10:5555', bcast_fail.stderr)
        self.assertEqual(len(self.read_lines(self.adb_log)), 2)

        self.clear_logs()
        run_as_fail = self.run_py(
            'dump-phone-diagnostics.py',
            '--serial',
            '192.0.2.10:5555',
            FAKE_ADB_FAIL_RUN_AS='1',
        )
        self.assertNotEqual(run_as_fail.returncode, 0)
        self.assertNotIn('192.0.2.10:5555', run_as_fail.stderr)
        self.assertEqual(len(self.read_lines(self.adb_log)), 3)

        # Resolves SDK platform-tools/adb when REFINEID_ADB is unset.
        self.clear_logs()
        fake_sdk = self.root / 'fake-sdk'
        sdk_adb = fake_sdk / 'platform-tools' / 'adb'
        sdk_adb.parent.mkdir(parents=True)
        shutil.copy2(self.fake_adb, sdk_adb)
        sdk_adb.chmod(0o755)
        via_sdk = self.run_py(
            'dump-phone-diagnostics.py',
            '--clear',
            REFINEID_ADB='',
            ANDROID_HOME=str(fake_sdk),
            FAKE_ADB_DEVICES='192.0.2.10:5555\tdevice\n',
        )
        self.assertEqual(via_sdk.returncode, 0, msg=via_sdk.stderr)
        self.assertNotIn('192.0.2.10:5555', via_sdk.stderr)
        self.assertEqual(
            self.read_lines(self.adb_log),
            [
                'devices',
                '-s 192.0.2.10:5555 shell am broadcast -a fi.refineid.android.CLEAR_LOGS -p fi.refineid.android',
            ],
        )


if __name__ == '__main__':
    unittest.main()
